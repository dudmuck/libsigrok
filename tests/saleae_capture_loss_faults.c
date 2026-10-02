/* Standalone, no-device deterministic fault matrix for the Saleae transfer
 * accountant. Build command is retained with the desk handoff. */
#include <config.h>
#include <assert.h>
#include <string.h>
#include "../src/hardware/saleae-logic-pro/protocol.h"

int main(void)
{
	struct dev_context d = {0};
	struct sr_dev_inst *other;
	struct sr_dev_inst fake = {0};
	struct sr_dev_driver saleae = {.name = "saleae-logic-pro"};
	struct sr_saleae_capture_status result;
	struct libusb_transfer *retired;
	int failures[] = {LIBUSB_TRANSFER_ERROR, LIBUSB_TRANSFER_STALL,
		LIBUSB_TRANSFER_OVERFLOW, LIBUSB_TRANSFER_NO_DEVICE};
	size_t i;

	d.is_fx2 = TRUE;
	assert(saleae_logic_pro_account_transfer(&d, LIBUSB_TRANSFER_COMPLETED, 128, 128));
	assert(saleae_logic_pro_account_transfer(&d, LIBUSB_TRANSFER_TIMED_OUT, 64, 128));
	assert(d.capture_status.bytes_received == 192);
	assert(d.capture_status.transfers_short == 1);
	d.stop_requested = TRUE;
	assert(!saleae_logic_pro_account_transfer(&d, LIBUSB_TRANSFER_CANCELLED, 0, 128));
	assert(!d.capture_failed);
	d.stop_requested = FALSE;
	assert(!saleae_logic_pro_account_transfer(&d, LIBUSB_TRANSFER_CANCELLED, 0, 128));
	assert(d.capture_failed && !strcmp(d.capture_status.first_stage, "usb_unexpected_cancel"));
	for (i = 0; i < G_N_ELEMENTS(failures); i++)
		assert(!saleae_logic_pro_account_transfer(&d, failures[i], 0, 128));
	d.stop_requested = TRUE;
	assert(!saleae_logic_pro_account_transfer(&d, LIBUSB_TRANSFER_CANCELLED, 0, 128));
	assert(!strcmp(d.capture_status.first_stage, "usb_unexpected_cancel"));
	assert(d.capture_status.usb_errors == 1 + G_N_ELEMENTS(failures));

	memset(&d, 0, sizeof(d));
	d.is_fx2 = FALSE;
	assert(!saleae_logic_pro_account_transfer(&d, LIBUSB_TRANSFER_COMPLETED, 3, 128));
	assert(!strcmp(d.capture_status.first_stage, "usb_partial_word"));
	assert(d.capture_status.usb_errors == 1);
	fake.driver = &saleae;
	fake.priv = &d;
	assert(sr_saleae_logic_pro_capture_status_get(&fake, &result) == SR_OK);
	assert(result.usb_partial_word == 1);

	other = sr_dev_inst_user_new("fixture", "not-saleae", "1");
	assert(other);
	assert(sr_saleae_logic_pro_capture_status_get(other, &result) == SR_ERR_NA);
	assert(sr_saleae_logic_pro_capture_status_get(NULL, &result) == SR_ERR_ARG);

	/* Model the callback's failed-status retirement followed by stop/abort.
	 * Under ASan, an uncleared slot makes the abort scan touch freed storage. */
	memset(&d, 0, sizeof(d));
	d.num_transfers = 2;
	d.transfers = g_new0(struct libusb_transfer *, 2);
	d.transfers[0] = libusb_alloc_transfer(0);
	d.transfers[1] = libusb_alloc_transfer(0);
	assert(d.transfers[0] && d.transfers[1]);
	d.submitted_transfers = 2;
	assert(!saleae_logic_pro_account_transfer(&d, LIBUSB_TRANSFER_ERROR, 0, 128));
	retired = d.transfers[0];
	saleae_logic_pro_retire_slot(&d, retired);
	libusb_free_transfer(retired);
	assert(d.transfers[0] == NULL && d.submitted_transfers == 1);
	for (i = 0; i < d.num_transfers; i++)
		if (d.transfers[i])
			assert(d.transfers[i] == d.transfers[1]);
	retired = d.transfers[1];
	saleae_logic_pro_retire_slot(&d, retired);
	libusb_free_transfer(retired);
	g_free(d.transfers);
	/* The public API has no standalone user-device destroy; process exits now. */
	return 0;
}
