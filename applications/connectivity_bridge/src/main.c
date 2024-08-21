/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>

#include <pm_config.h>
#include <zephyr/stats/stats.h>
#include <zephyr/usb/usb_device.h>
#include <zephyr/dfu/mcuboot.h>

#include <app_event_manager.h>
#include <hw_id.h>

#define MODULE main
#include "module_state_event.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(MODULE);

static uint8_t usb_serial_str[] = "THINGY91_12PLACEHLDRS";

/* Overriding weak function to set iSerialNumber at runtime. */
uint8_t *usb_update_sn_string_descriptor(void)
{
#if defined(CONFIG_SOC_SERIES_NRF52X)
	snprintk(usb_serial_str, sizeof(usb_serial_str), "THINGY91_%04X%08X",
				(uint32_t)(NRF_FICR->DEVICEADDR[1] & 0x0000FFFF)|0x0000C000,
				(uint32_t)NRF_FICR->DEVICEADDR[0]);
#else
	char buf[HW_ID_LEN] = {0};

	if (!hw_id_get(buf, ARRAY_SIZE(buf))) {
		snprintk(usb_serial_str, sizeof(usb_serial_str), "THINGY91X_%s", buf);
	}
#endif
	return usb_serial_str;
}

static void image_validation(void)
{
	int rc;
	char buf[255];
	struct mcuboot_img_header header;

	boot_read_bank_header(PM_MCUBOOT_PRIMARY_ID, &header, sizeof(header));
	snprintk(buf, sizeof(buf), "%d.%d.%d-%d", header.h.v1.sem_ver.major,
		 header.h.v1.sem_ver.minor, header.h.v1.sem_ver.revision,
		 header.h.v1.sem_ver.build_num);

	LOG_INF("Booting image: build time: " __DATE__ " " __TIME__);
	LOG_INF("Image Version %s", buf);
	rc = boot_is_img_confirmed();
	LOG_INF("Image is%s confirmed OK", rc ? "" : " not");
	if (!rc) {
		if (boot_write_img_confirmed()) {
			LOG_ERR("Failed to confirm image");
		} else {
			LOG_INF("Marked image as OK");
		}
	}
}

int main(void)
{
	image_validation();

	if (app_event_manager_init()) {
		LOG_ERR("Application Event Manager not initialized");
	} else {
		module_set_state(MODULE_STATE_READY);
	}
	return 0;
}
