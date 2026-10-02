/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2017 Jan Luebbe <jluebbe@lasnet.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBSIGROK_HARDWARE_SALEAE_LOGIC_PRO_PROTOCOL_H
#define LIBSIGROK_HARDWARE_SALEAE_LOGIC_PRO_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "saleae-logic-pro"

/* 16 channels * 32 samples */
#define CONV_BATCH_SIZE (2 * 32)

/*
 * One packet + one partial conversion: Worst case is only one active
 * channel converted to 2 bytes per sample, with 8 * 16384 samples per packet.
 */
#define CONV_BUFFER_SIZE (2 * 8 * 16384 + CONV_BATCH_SIZE)

struct dev_context {
	/* A failed capture stays failed through cancellation, drain and END. */
	struct sr_saleae_capture_status capture_status;
	gboolean stop_requested;
	gboolean capture_failed;
	unsigned int dig_channel_cnt;
	uint16_t dig_channel_mask;
	uint16_t dig_channel_masks[16];
	uint64_t dig_samplerate;

	const char *fpga_bitstream;
	unsigned int unit_size; /* 1 for <=8ch, 2 for <=16ch */
	gboolean is_fx2;

	uint32_t lfsr;

	unsigned int num_transfers;
	unsigned int submitted_transfers;
	struct libusb_transfer **transfers;

	uint8_t *conv_buffer;
	unsigned int conv_size;
	unsigned int batch_index;

	/* FX2: partial frame carried across USB transfers. */
	uint8_t fx2_partial[16]; /* max frame = 8 channels × 2 bytes */
	unsigned int fx2_partial_len;
};

static inline void saleae_logic_pro_record_failure(struct dev_context *devc,
		const char *stage, int code)
{
	if (!devc->capture_failed) {
		devc->capture_status.first_stage = stage;
		devc->capture_status.first_code = code;
	}
	devc->capture_failed = TRUE;
}

/* Pure transfer accounting: exercised by offline fault-injection tests. A
 * timeout carrying bytes is valid data; a cancellation is clean only after
 * stop intent. Short USB packets are counted, not assumed to be data loss. */
static inline gboolean saleae_logic_pro_account_transfer(struct dev_context *devc,
		int status, int actual, int requested)
{
	if (actual < 0 || actual > requested) {
		devc->capture_status.usb_errors++;
		saleae_logic_pro_record_failure(devc, "usb_length", actual);
		return FALSE;
	}
	switch (status) {
	case LIBUSB_TRANSFER_COMPLETED:
		devc->capture_status.transfers_completed++;
		break;
	case LIBUSB_TRANSFER_TIMED_OUT:
		devc->capture_status.transfers_timed_out++;
		break;
	case LIBUSB_TRANSFER_CANCELLED:
		devc->capture_status.transfers_cancelled++;
		if (!devc->stop_requested) {
			devc->capture_status.usb_errors++;
			devc->capture_status.usb_unexpected_cancel++;
			saleae_logic_pro_record_failure(devc, "usb_unexpected_cancel", status);
		}
		return FALSE;
	case LIBUSB_TRANSFER_NO_DEVICE:
		devc->capture_status.usb_errors++;
		devc->capture_status.usb_no_device++;
		saleae_logic_pro_record_failure(devc, "usb_no_device", status);
		return FALSE;
	default:
		devc->capture_status.usb_errors++;
		if (status == LIBUSB_TRANSFER_STALL)
			devc->capture_status.usb_stall++;
		if (status == LIBUSB_TRANSFER_OVERFLOW)
			devc->capture_status.usb_overflow++;
		saleae_logic_pro_record_failure(devc, "usb_transfer", status);
		return FALSE;
	}
	if (actual > 0 && actual < requested)
		devc->capture_status.transfers_short++;
	devc->capture_status.bytes_received += actual;
	if (!devc->is_fx2 && actual % 4 != 0) {
		devc->capture_status.usb_errors++;
		devc->capture_status.usb_partial_word++;
		saleae_logic_pro_record_failure(devc, "usb_partial_word", actual);
		return FALSE;
	}
	return TRUE;
}

/* The abort path owns only transfers still present in this array. Remove a
 * completed callback's transfer before its storage is released. */
static inline void saleae_logic_pro_retire_slot(struct dev_context *devc,
		struct libusb_transfer *transfer)
{
	unsigned int i;
	for (i = 0; i < devc->num_transfers; i++) {
		if (devc->transfers[i] == transfer) {
			devc->transfers[i] = NULL;
			devc->submitted_transfers--;
			return;
		}
	}
	/* A callback for an unowned transfer is a capture-integrity failure. */
	saleae_logic_pro_record_failure(devc, "usb_transfer_owner", SR_ERR);
}

SR_PRIV int saleae_logic_pro_init(const struct sr_dev_inst *sdi);
SR_PRIV int saleae_logic_pro_prepare(const struct sr_dev_inst *sdi);
SR_PRIV int saleae_logic_pro_start(const struct sr_dev_inst *sdi);
SR_PRIV int saleae_logic_pro_stop(const struct sr_dev_inst *sdi);
SR_PRIV void LIBUSB_CALL saleae_logic_pro_receive_data(struct libusb_transfer *transfer);

#endif
