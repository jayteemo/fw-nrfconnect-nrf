/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <bsd.h>
#include <string.h>
#include <zephyr.h>
#include <power/reboot.h>
#include <modem/bsdlib.h>
#include <modem/lte_lc.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <modem/modem_fota.h>

#include <net/socket.h>
#include <tinycrypt/hmac_prng.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/constants.h>
#include <sys/base64.h>
#include <net/http_client.h>
#include "fota_client_mgmt.h"

static int provision_device(void);
static bool get_pending_job(void);
static int update_job_status(void);

void bsd_recoverable_error_handler(uint32_t err)
{
	printk("bsdlib recoverable error: %u\n", err);
}

void modem_fota_callback(enum modem_fota_evt_id event_id)
{
	switch (event_id) {
	case MODEM_FOTA_EVT_CHECKING_FOR_UPDATE:
		/* TODO: check for update */
		get_pending_job();
		break;

	case MODEM_FOTA_EVT_NO_UPDATE_AVAILABLE:
		break;

	case MODEM_FOTA_EVT_DOWNLOADING_UPDATE:
		/* TODO: report progress? */
		update_job_status();
		break;

	case MODEM_FOTA_EVT_RESTART_PENDING:
		 /* TODO: update job status before reboot */
		update_job_status();
		printk("Rebooting...\n");
		lte_lc_offline();
		sys_reboot(SYS_REBOOT_WARM);
		break;

	case MODEM_FOTA_EVT_ERROR:
		/* TODO: report error */
		update_job_status();
	default:
		break;
	}
}

void main(void)
{
	int err;
	char * jwt;

	printk("Modem FOTA sample started\n");

	printk("Initializing bsdlib...\n");
	err = bsdlib_init();
	switch (err) {
	case MODEM_DFU_RESULT_OK:
		printk("Modem firmware update successful!\n");
		printk("Modem will run the new firmware after reboot\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case MODEM_DFU_RESULT_UUID_ERROR:
	case MODEM_DFU_RESULT_AUTH_ERROR:
		printk("Modem firmware update failed!\n");
		printk("Modem will run non-updated firmware on reboot.\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case MODEM_DFU_RESULT_HARDWARE_ERROR:
	case MODEM_DFU_RESULT_INTERNAL_ERROR:
		printk("Modem firmware update failed!\n");
		printk("Fatal error.\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case -1:
		printk("Could not initialize bsdlib.\n");
		printk("Fatal error.\n");
		return;
	default:
		break;
	}
	printk("Initialized bsdlib\n");

	/* Initialize AT command and notification libraries because
	 * CONFIG_BSD_LIBRARY_SYS_INIT is disabled and these libraries aren't
	 * initialized automatically.
	 */
	at_cmd_init();
	at_notif_init();

	err = fota_client_generate_jwt(&jwt);
	if (err < 0){
		printk("Failed to generate JWT: %d\n", err);
		return;
	}
	printk("JWT: %s\n", jwt);

	printk("LTE link connecting...\n");
	err = lte_lc_init_and_connect();
	__ASSERT(err == 0, "LTE link could not be established.");
	printk("LTE link connected!\n");

	provision_device();
	get_pending_job();

	modem_fota_init(&modem_fota_callback);

	k_free(jwt);

	k_sleep(K_FOREVER);
}

static int provision_device(void)
{
	int ret = fota_client_provision_device();
	if (ret == 0) {
		printk("Device provisioned, wait 30s before using API.\n");
	} else if (ret == 1) {
		printk("Device already provisioned.\n");
	} else {
		printk("Error provisioning device: %d.\n", ret);
	}

	return ret;
}

static bool get_pending_job(void)
{
	return false;
}

static int update_job_status(void)
{
	return 0;
}