/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <modem/nrf_modem_lib.h>
#include <nrf_modem_at.h>
#include <zephyr/settings/settings.h>
#include <net/nrf_cloud.h>
#include <zephyr/logging/log.h>
#include <net/fota_download.h>
#include <net/nrf_cloud_coap.h>
#include <net/nrf_cloud_fota_poll.h>
#include "cloud_connection.h"
#include "fota_support.h"
#include "fota_support_coap.h"
#include "sample_reboot.h"

#include <zephyr/drivers/gpio.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>

LOG_MODULE_REGISTER(fota_support_coap, CONFIG_MULTI_SERVICE_LOG_LEVEL);

#define FOTA_THREAD_DELAY_S 10

static void fota_reboot(enum nrf_cloud_fota_reboot_status status);

#define RESET_NODE DT_NODELABEL(nrf52840_reset)
#define HAS_RECOVERY_MODE (DT_NODE_HAS_STATUS(RESET_NODE, okay))

#if HAS_RECOVERY_MODE
static int nrf52840_reset_api(void)
{
	int err;
	const struct gpio_dt_spec reset_pin_spec = GPIO_DT_SPEC_GET(RESET_NODE, gpios);

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
	k_sleep(K_MSEC(10));

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

/* FOTA support context */
static struct nrf_cloud_fota_poll_ctx ctx = {
	.reboot_fn = fota_reboot,
#if HAS_RECOVERY_MODE
	.smp_reset_cb = nrf52840_reset_api
#endif
};

void fota_reboot(enum nrf_cloud_fota_reboot_status status)
{
	switch (status) {
	case FOTA_REBOOT_REQUIRED:
		sample_reboot_normal();
		break;
	case FOTA_REBOOT_SUCCESS:
		LOG_INF("Rebooting to complete FOTA update...");
		sample_reboot_normal();
		break;
	case FOTA_REBOOT_FAIL:
	case FOTA_REBOOT_SYS_ERROR:
	default:
		sample_reboot_error();
		break;
	}
}

int coap_fota_init(void)
{
	int err = nrf_cloud_fota_poll_init(&ctx);

	if (err) {
		return err;
	}

	/* Process pending FOTA job, the FOTA type is returned */
	err = nrf_cloud_fota_poll_process_pending(&ctx);
	if (err < 0) {
		return err;
	} else if (err != NRF_CLOUD_FOTA_TYPE__INVALID) {
		LOG_INF("Processed pending FOTA job type: %d", err);
	}

	return 0;
}

int coap_fota_thread_fn(void)
{
	int err;

	while (1) {
		/* Wait until we are able to communicate. */
		LOG_DBG("Waiting for valid connection before processing FOTA");
		(void)await_cloud_ready(K_FOREVER);

		/* Query for any queued FOTA jobs. If one is found, download and install
		 * it. This is a blocking operation which can take a long time.
		 * This function is likely to reboot in order to complete the FOTA update.
		 */
		err = nrf_cloud_fota_poll_process(&ctx);
		if (err == -EAGAIN) {
			LOG_INF("Checking for FOTA job in %d seconds",
				CONFIG_COAP_FOTA_JOB_CHECK_RATE_MINUTES * SEC_PER_MIN);
			k_sleep(K_MINUTES(CONFIG_COAP_FOTA_JOB_CHECK_RATE_MINUTES));
			continue;
		}
		if (err == -ENOENT) {
			cloud_transport_error_detected();
		}
		k_sleep(K_SECONDS(FOTA_THREAD_DELAY_S));
	}
	return 0;
}
