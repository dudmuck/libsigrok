/* Offline callback -> abort ownership regression. Run with ASan; no USB open. */
#include <config.h>
#include <assert.h>
#include <string.h>
#include "../src/hardware/saleae-logic-pro/protocol.h"

int sr_session_send(const struct sr_dev_inst *sdi, const struct sr_datafeed_packet *packet)
{
	(void)sdi;
	(void)packet;
	return SR_OK;
}

int sr_log(int loglevel, const char *format, ...)
{
	(void)loglevel;
	(void)format;
	return 0;
}

int __wrap_libusb_submit_transfer(struct libusb_transfer *transfer)
{
	(void)transfer;
	return LIBUSB_ERROR_IO;
}

static void failed_callback_then_abort_scan(int status)
{
	struct dev_context devc = {0};
	struct sr_dev_inst sdi = {0};
	struct libusb_transfer *transfer;
	unsigned int i;

	devc.is_fx2 = TRUE;
	devc.num_transfers = 1;
	devc.submitted_transfers = 1;
	devc.transfers = g_new0(struct libusb_transfer *, 1);
	sdi.priv = &devc;
	transfer = libusb_alloc_transfer(0);
	assert(transfer);
	transfer->buffer = g_malloc(16);
	transfer->length = 16;
	transfer->actual_length = 0;
	transfer->status = status;
	transfer->user_data = &sdi;
	devc.transfers[0] = transfer;

	saleae_logic_pro_receive_data(transfer);
	assert(devc.capture_failed);
	assert(devc.submitted_transfers == 0);
	/* The real abort cancels every non-NULL slot. Deliberately read each
	 * candidate so ASan catches a stale pointer before it reaches libusb. */
	for (i = 0; i < devc.num_transfers; i++)
		if (devc.transfers[i])
			assert(devc.transfers[i]->status == LIBUSB_TRANSFER_CANCELLED);
	assert(devc.transfers[0] == NULL);
	g_free(devc.transfers);
}

int main(void)
{
	failed_callback_then_abort_scan(LIBUSB_TRANSFER_ERROR);
	failed_callback_then_abort_scan(LIBUSB_TRANSFER_COMPLETED); /* resubmit fault */
	return 0;
}
