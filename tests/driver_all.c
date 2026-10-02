/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2013 Uwe Hermann <uwe@hermann-uwe.de>
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

#include <config.h>
#include <stdlib.h>
#include <check.h>
#include <libsigrok/libsigrok.h>
#include "lib.h"
#if HAVE_HW_SALEAE_LOGIC_PRO
#include "../src/hardware/saleae-logic-pro/protocol.h"
#endif

#if HAVE_HW_SALEAE_LOGIC_PRO
START_TEST(test_saleae_capture_transfer_faults_are_sticky)
{
	struct dev_context devc = {0};
	struct sr_dev_inst *other;
	struct sr_saleae_capture_status status;
	int failures[] = {LIBUSB_TRANSFER_ERROR, LIBUSB_TRANSFER_STALL,
		LIBUSB_TRANSFER_OVERFLOW, LIBUSB_TRANSFER_NO_DEVICE};
	size_t i;

	devc.is_fx2 = TRUE;
	ck_assert(saleae_logic_pro_account_transfer(&devc,
		LIBUSB_TRANSFER_COMPLETED, 128, 128));
	ck_assert(saleae_logic_pro_account_transfer(&devc,
		LIBUSB_TRANSFER_TIMED_OUT, 64, 128));
	ck_assert_uint_eq(devc.capture_status.bytes_received, 192);
	ck_assert_uint_eq(devc.capture_status.transfers_short, 1);
	devc.stop_requested = TRUE;
	ck_assert(!saleae_logic_pro_account_transfer(&devc,
		LIBUSB_TRANSFER_CANCELLED, 0, 128));
	ck_assert(!devc.capture_failed);
	devc.stop_requested = FALSE;
	ck_assert(!saleae_logic_pro_account_transfer(&devc,
		LIBUSB_TRANSFER_CANCELLED, 0, 128));
	ck_assert(devc.capture_failed);
	ck_assert_str_eq(devc.capture_status.first_stage, "usb_unexpected_cancel");
	for (i = 0; i < G_N_ELEMENTS(failures); i++)
		ck_assert(!saleae_logic_pro_account_transfer(&devc, failures[i], 0, 128));
	devc.stop_requested = TRUE;
	ck_assert(!saleae_logic_pro_account_transfer(&devc,
		LIBUSB_TRANSFER_CANCELLED, 0, 128));
	ck_assert_str_eq(devc.capture_status.first_stage, "usb_unexpected_cancel");
	ck_assert_uint_eq(devc.capture_status.usb_errors, 1 + G_N_ELEMENTS(failures));

	other = sr_dev_inst_user_new("fixture", "other", "1");
	ck_assert(other != NULL);
	ck_assert_int_eq(sr_saleae_logic_pro_capture_status_get(other, &status), SR_ERR_NA);
	ck_assert_int_eq(sr_saleae_logic_pro_capture_status_get(NULL, &status), SR_ERR_ARG);
	/* No public standalone user-device destroy; the test process exits. */
}
END_TEST

START_TEST(test_saleae_partial_word_fails)
{
	struct dev_context devc = {0};
	devc.is_fx2 = FALSE;
	ck_assert(!saleae_logic_pro_account_transfer(&devc,
		LIBUSB_TRANSFER_COMPLETED, 3, 128));
	ck_assert_str_eq(devc.capture_status.first_stage, "usb_partial_word");
	ck_assert_uint_eq(devc.capture_status.usb_errors, 1);
}
END_TEST
#endif

/* Check whether at least one driver is available. */
START_TEST(test_driver_available)
{
	struct sr_dev_driver **drivers;

	drivers = sr_driver_list(srtest_ctx);
	ck_assert_msg(drivers != NULL, "No drivers found.");
}
END_TEST

/* Check whether initializing all drivers works. */
START_TEST(test_driver_init_all)
{
	srtest_driver_init_all(srtest_ctx);
}
END_TEST

/*
 * Check whether setting a samplerate works.
 *
 * Additionally, this also checks whether SR_CONF_SAMPLERATE can be both
 * set and read back properly.
 */
#if 0
START_TEST(test_config_get_set_samplerate)
{
	/*
	 * Note: This currently only works for the demo driver.
	 *       For other drivers, a scan is needed and the respective
	 *       hardware must be attached to the host running the testsuite.
	 */
	srtest_check_samplerate(sr_ctx, "demo", SR_KHZ(19));
}
END_TEST
#endif

Suite *suite_driver_all(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("driver-all");

	tc = tcase_create("config");
	tcase_add_checked_fixture(tc, srtest_setup, srtest_teardown);
	tcase_add_test(tc, test_driver_available);
	tcase_add_test(tc, test_driver_init_all);
#if HAVE_HW_SALEAE_LOGIC_PRO
	tcase_add_test(tc, test_saleae_capture_transfer_faults_are_sticky);
	tcase_add_test(tc, test_saleae_partial_word_fails);
#endif
	// TODO: Currently broken.
	// tcase_add_test(tc, test_config_get_set_samplerate);
	suite_add_tcase(s, tc);

	return s;
}
