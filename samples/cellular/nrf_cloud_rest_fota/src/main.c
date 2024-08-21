/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <dk_buttons_and_leds.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>
#include <ctype.h>
#include <zephyr/drivers/gpio.h>
#include <stdio.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <mcumgr_smp_client.h>
#if defined(CONFIG_BOARD_THINGY91X)
#include "conn_bridge_fw.h"
#else
#include "smp_svr_fw.h"
#endif


LOG_MODULE_REGISTER(nrf_cloud_rest_fota, CONFIG_NRF_CLOUD_REST_FOTA_SAMPLE_LOG_LEVEL);

#define BTN_NUM			CONFIG_REST_FOTA_BUTTON_EVT_NUM

/* Semaphore to indicate a button has been pressed */
static K_SEM_DEFINE(button_press_sem, 0, 1);

#if defined(CONFIG_BOARD_THINGY91X)
#define HAS_RECOVERY_MODE	1
#define ZEPHYR_USER_NODE	DT_PATH(zephyr_user)
#define RESET_PIN_SPEC		GPIO_DT_SPEC_GET(ZEPHYR_USER_NODE, nrf5340_reset_gpios);
#else
#define RESET_NODE		DT_NODELABEL(nrf52840_reset)
#define HAS_RECOVERY_MODE	(DT_NODE_HAS_STATUS(RESET_NODE, okay))
#define RESET_PIN_SPEC		GPIO_DT_SPEC_GET(RESET_NODE, gpios)
#endif

#if HAS_RECOVERY_MODE
static int nrf52840_reset_api(void)
{
	int err;
	const struct gpio_dt_spec reset_pin_spec = RESET_PIN_SPEC;

	if (!device_is_ready(reset_pin_spec.port)) {
		LOG_ERR("Reset device not ready");
		return -EIO;
	}

	/* Configure pin as output and initialize it to inactive state. */
	err = gpio_pin_configure_dt(&reset_pin_spec, GPIO_OUTPUT_INACTIVE);
	if (err) {
		LOG_ERR("Pin configure err:%d", err);
		return err;
	}

	/* Reset the nRF52840 and let it wait until the pin is inactive again
	 * before running to main to ensure that it won't send any data until
	 * the H4 device is setup and ready to receive.
	 */
	err = gpio_pin_set_dt(&reset_pin_spec, 1);
	if (err) {
		LOG_ERR("GPIO Pin set to 1 err:%d", err);
		return err;
	}

	/* Wait for the nRF52840 peripheral to stop sending data.
	 *
	 * It is critical (!) to wait here, so that all bytes
	 * on the lines are received and drained correctly.
	 */
	k_sleep(K_MSEC(100));

	/* We are ready, let the nRF52840 run to main */
	err = gpio_pin_set_dt(&reset_pin_spec, 0);
	if (err) {
		LOG_ERR("GPIO Pin set to 0 err:%d", err);
		return err;
	}

	LOG_DBG("Reset Pin %d", reset_pin_spec.pin);

	return 0;
}
#endif /* HAS_RECOVERY_MODE */

static void button_handler(uint32_t button_states, uint32_t has_changed)
{
	if (has_changed & button_states & BIT(BTN_NUM - 1)) {
		LOG_DBG("Button %d pressed", BTN_NUM);
		k_sem_give(&button_press_sem);
	}
}

int init(void)
{
	int err;

	err = dk_buttons_init(button_handler);
	if (err) {
		LOG_ERR("Failed to initialize button: error: %d", err);
		return err;
	}

#if HAS_RECOVERY_MODE
	LOG_INF("Init external FOTA for use with MCUBoot recovery mode");
	err = mcumgr_smp_client_init(nrf52840_reset_api);
#else
	LOG_INF("Init external FOTA, no recovery mode");
	err = mcumgr_smp_client_init(NULL);
#endif

	if (err) {
		LOG_ERR("mcumgr_smp_client_init() failed, error: %d", err);
	}

	return 0;
}

static int hash_to_string(char *hash_string, size_t string_size, uint8_t *hash)
{
	char *ptr = hash_string;
	int buf_size = string_size;
	int len = 0;

	for (int i = 0; i < IMG_MGMT_DATA_SHA_LEN; i++) {
		len += snprintk(ptr + len, buf_size - len, "%x", hash[i]);
		if (len >= string_size) {
			return -1;
		}
	}
	hash_string[len] = 0;

	return 0;
}

static bool process_image_list(struct mcumgr_image_state *image_list)
{
	struct mcumgr_image_data *list;
	char hash_string[(IMG_MGMT_DATA_SHA_LEN * 2) + 1];
	bool update_pending = false;

	list = image_list->image_list;
	for (int i = 0; i < image_list->image_list_length; ++i) {
		if (list->flags.active) {
			LOG_INF("Primary Image(%d) slot(%d)", list->img_num,
				    list->slot_num);
		} else {
			LOG_INF("Secondary Image(%d) slot(%d)", list->img_num, list->slot_num);
		}

		LOG_INF("       Version: %s", list->version);
		LOG_INF("       Bootable(%d) Pending(%d) Confirmed(%d)",
			list->flags.bootable, list->flags.pending, list->flags.confirmed);
		if (!list->flags.active && list->flags.pending) {
			update_pending = true;
		}
		if (hash_to_string(hash_string, sizeof(hash_string), list->hash) == 0) {
			LOG_INF("       Hash: %s", hash_string);
		}

		++list;
	}

	return update_pending;
}

static bool is_update_pending(void)
{
	static struct mcumgr_image_state image_list;

	memset(&image_list, 0, sizeof(image_list));

	if (mcumgr_smp_client_local_download_read_list(&image_list) == 0) {
		return process_image_list(&image_list);
	} else {
		LOG_WRN("Failed to read image list");
	}

	return false;
}

int main(void)
{
	int err;
	bool update_pending = false;

	err = init();
	if (err) {
		LOG_ERR("Initialization failed");
		return 0;
	}

	k_sleep(K_SECONDS(10));
	LOG_INF("Press button 1 to read image list");
	(void)k_sem_take(&button_press_sem, K_FOREVER);
	update_pending = is_update_pending();

	if (!update_pending) {
		LOG_INF("Press button 1 to transfer update");
		(void)k_sem_take(&button_press_sem, K_FOREVER);

		err = mcumgr_smp_client_local_download_start(sizeof(fw_update));
		LOG_INF("mcumgr_smp_client_local_download_start: %d", err);

		err = mcumgr_smp_client_local_download_write(fw_update, sizeof(fw_update));
		LOG_INF("mcumgr_smp_client_local_download_write: %d", err);
		if (err != 1) {
			LOG_ERR("Failed to transfer update");
			goto sleep;
		}

		LOG_INF("Update transfer complete");
		/* Print the list again to show the new image */
		(void)is_update_pending();
	}

	LOG_INF("Press button 1 to apply update");
	(void)k_sem_take(&button_press_sem, K_FOREVER);

	err = mcumgr_smp_client_local_download_apply();
	LOG_INF("mcumgr_smp_client_local_download_apply: %d", err);

	k_sleep(K_SECONDS(5));

	err = mcumgr_smp_client_local_download_reboot();
	LOG_INF("mcumgr_smp_client_local_download_reboot: %d", err);

#if !HAS_RECOVERY_MODE
	k_sleep(K_SECONDS(1));
	err = mcumgr_smp_client_confirm_image();
	LOG_INF("mcumgr_smp_client_confirm_image: %d", err);
#endif


sleep:
	while (1) {
		LOG_INF("Press button 1 to read image list");
		(void)k_sem_take(&button_press_sem, K_FOREVER);
		update_pending = is_update_pending();
	}
}
