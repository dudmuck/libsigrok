/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2026 Wayne Roberts
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Repair marginally sampled logic channels.
 *
 * Two independent rules, each enabled by its option:
 *
 * min_period=N enables glitch suppression: a pulse whose leading edge
 * arrives less than N samples after the last accepted edge of the same
 * polarity, and which is itself shorter than N samples, is rewritten to
 * the previous stable level.
 *
 * clock_period=P (in samples, e.g. 2.5 for a 10 MHz clock at 25 MSa/s)
 * enables clock pulse recovery for clocks sampled near the Nyquist rate,
 * where a one-sample pulse phase can collapse to zero width when its
 * edges land on sample instants. Two sub-rules:
 *  - A run at pulse_level longer than one half-period is provably a
 *    merged pair of pulses; it is split by re-inserting the collapsed
 *    opposite phase(s) at the cadence-predicted position(s).
 *  - A vanished pulse at pulse_level leaves a gap indistinguishable from
 *    a legitimate inter-word pause. With frame_pulses=W (e.g. 8 for
 *    byte-oriented SPI), pulses are counted between idle gaps; at a
 *    short gap where the count is not a multiple of W, the missing
 *    pulse is re-inserted and the count realigned.
 *
 * Decisions need bounded look-ahead, so the output stream lags the input
 * and the final few samples of a capture are dropped at end of stream.
 */

#include <config.h>
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "transform/deglitch"

#define MAX_CHANNELS 64

struct chan_state {
	gboolean have_level;
	uint8_t level;		/* Currently accepted output level. */
	int64_t last_edge[2];	/* Last accepted edge, [0]=falling, [1]=rising. */
	int64_t pend_start;	/* First frame of an open pulse candidate, -1 = none. */
	int64_t run_start;	/* First frame of the current level run, -1 = unknown. */
	uint8_t run_level;
	gboolean gap_handled;	/* Open gap already repaired as idle. */
	uint64_t pulse_count;	/* Pulses since the last idle gap. */
	uint64_t suppressed;
	uint64_t splits;
	uint64_t inserted;
	uint64_t unresolved;
};

struct context {
	uint64_t min_period;
	double clock_period;
	uint64_t frame_pulses;
	unsigned int pulse_level;
	uint64_t chan_mask;
	uint64_t lookahead;	/* Carry depth in frames. */
	/* Derived clock-recovery thresholds (frames). */
	int64_t split_min;	/* Shortest pulse_level run that must be split. */
	int64_t gap_max;	/* Longest gap still considered a vanish candidate. */
	uint64_t abs_in;	/* Absolute index of next incoming frame. */
	uint64_t carry_tail;	/* Absolute index of oldest frame in carry. */
	unsigned int unitsize;	/* Latched from the first logic packet. */
	GByteArray *carry;	/* Frames not yet committed to output. */
	GByteArray *out;	/* Frames emitted by the current receive() call. */
	struct chan_state ch[MAX_CHANNELS];
	struct sr_datafeed_packet out_pkt;
	struct sr_datafeed_logic out_logic;
};

static uint8_t *carry_frame(struct context *ctx, uint64_t n)
{
	return ctx->carry->data + (gsize)(n - ctx->carry_tail) * ctx->unitsize;
}

static uint8_t get_bit(const uint8_t *frame, unsigned int c)
{
	return (frame[c >> 3] >> (c & 7)) & 1;
}

static void put_bit(uint8_t *frame, unsigned int c, uint8_t v)
{
	if (v)
		frame[c >> 3] |= 1 << (c & 7);
	else
		frame[c >> 3] &= ~(1 << (c & 7));
}

static int init(struct sr_transform *t, GHashTable *options)
{
	struct context *ctx;
	struct sr_channel *ch;
	const char *chans;
	char **tokens, *tok;
	GSList *l;
	gboolean found, numeric;
	unsigned int i, c;
	uint64_t clock_depth;

	if (!t || !t->sdi || !options)
		return SR_ERR_ARG;

	t->priv = ctx = g_malloc0(sizeof(struct context));

	ctx->min_period = g_variant_get_uint64(
		g_hash_table_lookup(options, "min_period"));
	ctx->clock_period = g_variant_get_double(
		g_hash_table_lookup(options, "clock_period"));
	ctx->frame_pulses = g_variant_get_uint64(
		g_hash_table_lookup(options, "frame_pulses"));
	ctx->pulse_level = g_variant_get_uint64(
		g_hash_table_lookup(options, "pulse_level")) ? 1 : 0;
	chans = g_variant_get_string(
		g_hash_table_lookup(options, "channels"), NULL);

	if (ctx->clock_period < 0.0 ||
			(ctx->clock_period > 0.0 && ctx->clock_period < 2.0)) {
		sr_err("Invalid clock_period %g (need >= 2 samples).",
			ctx->clock_period);
		return SR_ERR_ARG;
	}

	for (c = 0; c < MAX_CHANNELS; c++) {
		/* Far enough back that the first edge is always accepted,
		 * without n - last_edge overflowing. */
		ctx->ch[c].last_edge[0] = INT64_MIN / 2;
		ctx->ch[c].last_edge[1] = INT64_MIN / 2;
		ctx->ch[c].pend_start = -1;
		ctx->ch[c].run_start = -1;
	}

	if (chans && chans[0]) {
		tokens = g_strsplit(chans, ",", -1);
		for (i = 0; tokens[i]; i++) {
			tok = g_strstrip(tokens[i]);
			if (!tok[0])
				continue;
			found = FALSE;
			for (l = t->sdi->channels; l; l = l->next) {
				ch = l->data;
				if (ch->type != SR_CHANNEL_LOGIC)
					continue;
				if (g_strcmp0(ch->name, tok) != 0)
					continue;
				if (ch->index >= MAX_CHANNELS) {
					sr_err("Channel index %d out of range.",
						ch->index);
					g_strfreev(tokens);
					return SR_ERR_ARG;
				}
				ctx->chan_mask |= UINT64_C(1) << ch->index;
				found = TRUE;
				break;
			}
			if (!found) {
				numeric = TRUE;
				for (c = 0; tok[c]; c++)
					numeric = numeric && isdigit((unsigned char)tok[c]);
				if (numeric) {
					c = strtoul(tok, NULL, 10);
					if (c < MAX_CHANNELS) {
						ctx->chan_mask |= UINT64_C(1) << c;
						found = TRUE;
					}
				}
			}
			if (!found) {
				sr_err("Unknown channel '%s'.", tok);
				g_strfreev(tokens);
				return SR_ERR_ARG;
			}
		}
		g_strfreev(tokens);
	} else {
		for (l = t->sdi->channels; l; l = l->next) {
			ch = l->data;
			if (ch->type != SR_CHANNEL_LOGIC)
				continue;
			if (ch->index < MAX_CHANNELS)
				ctx->chan_mask |= UINT64_C(1) << ch->index;
		}
	}

	clock_depth = 0;
	if (ctx->clock_period > 0.0) {
		/* Legitimate pulse phases quantize to at most
		 * ceil(period/2) samples; anything longer is merged. */
		ctx->split_min = (int64_t)ceil(ctx->clock_period / 2.0) + 1;
		/* Gaps of up to ~4 periods can hide vanished pulses;
		 * anything longer is idle. */
		ctx->gap_max = (int64_t)floor(4.0 * ctx->clock_period);
		clock_depth = ctx->gap_max + 4;
	}
	ctx->lookahead = MAX(ctx->min_period, clock_depth);

	ctx->carry = g_byte_array_new();
	ctx->out = g_byte_array_new();

	sr_info("Deglitch: min_period=%" PRIu64 ", clock_period=%g, "
		"frame_pulses=%" PRIu64 ", pulse_level=%u, channel mask 0x%"
		PRIx64 ".", ctx->min_period, ctx->clock_period,
		ctx->frame_pulses, ctx->pulse_level, ctx->chan_mask);

	return SR_OK;
}

/* A run at pulse_level ended: split merged pulses. Returns pulses added. */
static uint64_t split_run(struct context *ctx, struct chan_state *s,
	unsigned int c, uint64_t run_end)
{
	double half;
	int64_t w, pos, k, j;

	w = (int64_t)run_end - s->run_start;
	if (w < ctx->split_min || w > ctx->gap_max)
		return 0;
	half = ctx->clock_period / 2.0;
	k = (int64_t)((w / half - 1.0) / 2.0 + 0.5);
	if (k < 1)
		return 0;
	for (j = 1; j <= k; j++) {
		pos = s->run_start + (int64_t)((2 * j - 1) * half + 0.5);
		pos = CLAMP(pos, s->run_start + 1, (int64_t)run_end - 2);
		put_bit(carry_frame(ctx, pos), c, !ctx->pulse_level);
	}
	s->splits += k;
	return k;
}

/* Insert k pulses at cadence-predicted positions inside a gap starting at
 * gap_start, bounded to [gap_start+1, limit]. Returns pulses added. */
static uint64_t insert_pulses(struct context *ctx, struct chan_state *s,
	unsigned int c, int64_t gap_start, int64_t limit, int64_t k)
{
	double half;
	int64_t j, pos;

	half = ctx->clock_period / 2.0;
	for (j = 1; j <= k; j++) {
		pos = gap_start + (int64_t)((2 * j - 1) * half + 0.5);
		pos = CLAMP(pos, gap_start + 1, limit);
		put_bit(carry_frame(ctx, pos), c, ctx->pulse_level);
	}
	s->inserted += k;
	return k;
}

/* A gap (run at !pulse_level) ended: re-insert vanished pulses when the
 * modulo-frame_pulses count says some are missing. The counter is the
 * authority for how many; the gap width caps how many plausibly fit.
 * Returns pulses added. */
static uint64_t repair_gap(struct context *ctx, struct chan_state *s,
	unsigned int c, uint64_t run_end)
{
	int64_t w, deficit, cap;

	if (s->gap_handled) {
		s->gap_handled = FALSE;
		return 0;
	}
	w = (int64_t)run_end - s->run_start;
	if (w < ctx->split_min || w > ctx->gap_max || !ctx->frame_pulses)
		return 0;
	deficit = (ctx->frame_pulses - s->pulse_count % ctx->frame_pulses) %
		ctx->frame_pulses;
	if (!deficit)
		return 0;
	/* m vanished pulses span (2m+1)*period/2 samples. */
	cap = (int64_t)(w / ctx->clock_period + 0.5);
	cap = MAX(cap, 1);
	return insert_pulses(ctx, s, c, s->run_start,
		(int64_t)run_end - 2, MIN(deficit, cap));
}

/* An open gap has exceeded gap_max: it is an idle gap. Repair any counter
 * deficit at the gap start (a burst-tail vanish swallowed by the idle) and
 * realign the frame counter. */
static void idle_realign(struct context *ctx, struct chan_state *s,
	unsigned int c, uint64_t n)
{
	int64_t deficit;

	s->gap_handled = TRUE;
	if (!ctx->frame_pulses) {
		s->pulse_count = 0;
		return;
	}
	deficit = (ctx->frame_pulses - s->pulse_count % ctx->frame_pulses) %
		ctx->frame_pulses;
	if (deficit) {
		if (deficit <= 2)
			insert_pulses(ctx, s, c, s->run_start,
				(int64_t)n - 1, deficit);
		else
			s->unresolved++;
	}
	s->pulse_count = 0;
}

static void track_clock(struct context *ctx, struct chan_state *s,
	unsigned int c, uint64_t n)
{
	uint8_t x;

	x = get_bit(carry_frame(ctx, n), c);
	if (s->run_start < 0) {
		s->run_start = n;
		s->run_level = x;
		s->gap_handled = FALSE;
		return;
	}
	if (x == s->run_level) {
		/* An open gap past gap_max is an idle gap: repair the
		 * counter deficit before the gap start leaves the carry. */
		if (s->run_level != ctx->pulse_level && !s->gap_handled &&
				(int64_t)n - s->run_start > ctx->gap_max)
			idle_realign(ctx, s, c, n);
		return;
	}
	/* Run [run_start, n) at run_level just ended. */
	if (s->run_level == ctx->pulse_level)
		s->pulse_count += 1 + split_run(ctx, s, c, n);
	else
		s->pulse_count += repair_gap(ctx, s, c, n);
	s->run_start = n;
	s->run_level = x;
}

static void process_frame(struct context *ctx, uint64_t n)
{
	struct chan_state *s;
	uint8_t *frame, x;
	uint64_t mask;
	unsigned int c;
	int64_t m;

	frame = carry_frame(ctx, n);
	mask = ctx->chan_mask;
	for (c = 0; mask; c++, mask >>= 1) {
		if (!(mask & 1))
			continue;
		if ((c >> 3) >= ctx->unitsize)
			break;
		s = &ctx->ch[c];
		if (ctx->min_period >= 2) {
			x = get_bit(frame, c);
			if (!s->have_level) {
				s->level = x;
				s->have_level = TRUE;
			} else if (s->pend_start >= 0) {
				if (x == s->level) {
					/* Pulse ended short: confirmed glitch. */
					s->pend_start = -1;
					s->suppressed++;
				} else if ((int64_t)n - s->pend_start + 1 >=
						(int64_t)ctx->min_period) {
					/* Pulse persisted: retroactively accept. */
					for (m = s->pend_start; m <= (int64_t)n; m++)
						put_bit(carry_frame(ctx, m), c, x);
					s->last_edge[x] = s->pend_start;
					s->level = x;
					s->pend_start = -1;
					/* History changed: resync run tracking. */
					s->run_start = -1;
				} else {
					put_bit(frame, c, s->level);
				}
			} else if (x != s->level) {
				if ((int64_t)n - s->last_edge[x] >=
						(int64_t)ctx->min_period) {
					s->level = x;
					s->last_edge[x] = n;
				} else {
					/* Same-polarity edge too soon. */
					s->pend_start = n;
					put_bit(frame, c, s->level);
				}
			}
		}
		if (ctx->clock_period > 0.0)
			track_clock(ctx, s, c, n);
	}
}

static int receive(const struct sr_transform *t,
		struct sr_datafeed_packet *packet_in,
		struct sr_datafeed_packet **packet_out)
{
	struct context *ctx;
	const struct sr_datafeed_logic *logic;
	uint64_t n, nframes, emit;
	unsigned int c;

	if (!t || !t->sdi || !packet_in || !packet_out)
		return SR_ERR_ARG;
	ctx = t->priv;

	switch (packet_in->type) {
	case SR_DF_LOGIC:
		if (!ctx->lookahead || !ctx->chan_mask)
			break;
		logic = packet_in->payload;
		if (!logic->length || !logic->unitsize)
			break;
		if (!ctx->unitsize) {
			ctx->unitsize = logic->unitsize;
		} else if (ctx->unitsize != logic->unitsize) {
			sr_err("Unit size changed mid-stream (%u -> %u).",
				ctx->unitsize, logic->unitsize);
			return SR_ERR;
		}
		nframes = logic->length / logic->unitsize;
		g_byte_array_append(ctx->carry, logic->data,
			nframes * ctx->unitsize);
		for (n = ctx->abs_in; n < ctx->abs_in + nframes; n++)
			process_frame(ctx, n);
		ctx->abs_in += nframes;

		/* Commit everything older than the look-ahead window. */
		g_byte_array_set_size(ctx->out, 0);
		nframes = ctx->carry->len / ctx->unitsize;
		if (nframes > ctx->lookahead) {
			emit = nframes - ctx->lookahead;
			g_byte_array_append(ctx->out, ctx->carry->data,
				emit * ctx->unitsize);
			g_byte_array_remove_range(ctx->carry, 0,
				emit * ctx->unitsize);
			ctx->carry_tail += emit;
		}
		if (!ctx->out->len) {
			/* Stream start: nothing decided yet. */
			*packet_out = NULL;
			return SR_OK;
		}
		ctx->out_logic.length = ctx->out->len;
		ctx->out_logic.unitsize = ctx->unitsize;
		ctx->out_logic.data = ctx->out->data;
		ctx->out_pkt.type = SR_DF_LOGIC;
		ctx->out_pkt.payload = &ctx->out_logic;
		*packet_out = &ctx->out_pkt;
		return SR_OK;
	case SR_DF_END:
		/*
		 * The look-ahead window cannot be flushed as an extra
		 * packet, so the final lookahead samples are dropped.
		 */
		for (c = 0; c < MAX_CHANNELS; c++) {
			struct chan_state *s = &ctx->ch[c];
			if (s->suppressed || s->splits || s->inserted ||
					s->unresolved)
				sr_info("Channel %u: suppressed %" PRIu64
					", split %" PRIu64 ", inserted %"
					PRIu64 ", unresolved %" PRIu64 ".",
					c, s->suppressed, s->splits,
					s->inserted, s->unresolved);
		}
		g_byte_array_set_size(ctx->carry, 0);
		break;
	default:
		break;
	}

	*packet_out = packet_in;

	return SR_OK;
}

static int cleanup(struct sr_transform *t)
{
	struct context *ctx;

	if (!t || !t->sdi)
		return SR_ERR_ARG;
	ctx = t->priv;

	g_byte_array_free(ctx->carry, TRUE);
	g_byte_array_free(ctx->out, TRUE);
	g_free(ctx);
	t->priv = NULL;

	return SR_OK;
}

static struct sr_option options[] = {
	{ "channels", "Channels", "Comma-separated channel names or indices to repair (default: all logic channels)", NULL, NULL },
	{ "min_period", "Minimum period", "Minimum same-polarity edge spacing in samples; shorter pulses are suppressed (0 = disabled)", NULL, NULL },
	{ "clock_period", "Clock period", "Nominal clock period in samples for pulse recovery, e.g. 2.5 (0 = disabled)", NULL, NULL },
	{ "frame_pulses", "Frame pulses", "Clock pulses per word for vanished-pulse recovery, e.g. 8 (0 = disabled)", NULL, NULL },
	{ "pulse_level", "Pulse level", "Level of the clock's active pulses (idle level is the opposite)", NULL, NULL },
	ALL_ZERO
};

static const struct sr_option *get_options(void)
{
	if (!options[0].def) {
		options[0].def = g_variant_ref_sink(g_variant_new_string(""));
		options[1].def = g_variant_ref_sink(g_variant_new_uint64(0));
		options[2].def = g_variant_ref_sink(g_variant_new_double(0.0));
		options[3].def = g_variant_ref_sink(g_variant_new_uint64(0));
		options[4].def = g_variant_ref_sink(g_variant_new_uint64(1));
	}

	return options;
}

SR_PRIV struct sr_transform_module transform_deglitch = {
	.id = "deglitch",
	.name = "Deglitch",
	.desc = "Repair glitches and degraded clock pulse trains on logic channels",
	.options = get_options,
	.init = init,
	.receive = receive,
	.cleanup = cleanup,
};
