/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <ctype.h>
#include <zephyr/drivers/gpio.h>
#include <stdio.h>
#include <dfu/dfu_target_smp.h>
#include <net/fota_download.h>
#include <fota_download_util.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(nrf_mcumgr_smp_client, CONFIG_NRF_MCUMGR_SMP_CLIENT_LOG_LEVEL);

static dfu_target_reset_cb_t reset_cb;

static size_t local_dl_size;
static size_t local_dl_bytes_written;

static void dfu_target_cb(enum dfu_target_evt_id evt)
{
	switch (evt) {
	case DFU_TARGET_EVT_ERASE_PENDING:
		LOG_DBG("DFU_TARGET_EVT_ERASE_PENDING");
		break;
	case DFU_TARGET_EVT_TIMEOUT:
		LOG_DBG("DFU_TARGET_EVT_TIMEOUT");
		break;
	case DFU_TARGET_EVT_ERASE_DONE:
		LOG_DBG("DFU_TARGET_EVT_ERASE_DONE");
		break;
	default:
		break;
	}
}

int mcumgr_smp_client_local_download_start(const size_t size)
{
	int err;

	err = dfu_target_init(DFU_TARGET_IMAGE_TYPE_SMP, 0, size, dfu_target_cb);
	if (!err) {
		local_dl_size = size;
		local_dl_bytes_written = 0;
	}

	return err;
}

int mcumgr_smp_client_local_download_write(const uint8_t *buf, const size_t len)
{
	if (local_dl_bytes_written == 0) {
		/* Validate SMP target type */
		enum dfu_target_image_type img_type = dfu_target_smp_img_type_check(buf, len);

		if (img_type != DFU_TARGET_IMAGE_TYPE_SMP) {
			return -EFTYPE;
		}
	}

	LOG_INF("SMP client: writing %u bytes", len);
	int err = dfu_target_write((const void *)buf, len);

	if (err) {
		(void)dfu_target_done(false);
		return err;
	}

	local_dl_bytes_written += len;

	if (local_dl_bytes_written < local_dl_size) {
		return 0;
	}

	LOG_INF("SMP client: all bytes written");
	err = dfu_target_done(true);
	if (!err) {
		/* Return 1 to indicate complete */
		err = 1;
	}

	return err;
}

int mcumgr_smp_client_local_download_apply(void)
{
	return fota_download_util_image_schedule(DFU_TARGET_IMAGE_TYPE_SMP);
}

int mcumgr_smp_client_local_download_reboot(void)
{
	return dfu_target_smp_reboot();
}

int mcumgr_smp_client_local_download_read_list(struct mcumgr_image_state *image_list)
{
	return dfu_target_smp_image_list_get(image_list);
}


int mcumgr_smp_client_init(dfu_target_reset_cb_t cb)
{
	int ret;

	ret = dfu_target_smp_client_init();
	if (ret) {
		LOG_ERR("Failed to init DFU target SMP, %d", ret);
		return ret;
	}

	dfu_target_smp_recovery_mode_enable(cb);
	reset_cb = cb;

	return ret;
}

int mcumgr_smp_client_download_start(const char *download_uri, int sec_tag,
				     fota_download_callback_t client_callback)
{
	return fota_download_util_download_start(download_uri, DFU_TARGET_IMAGE_TYPE_SMP, sec_tag,
						 client_callback);
}

int mcumgr_smp_client_download_cancel(void)
{
	return fota_download_util_download_cancel();
}

int mcumgr_smp_client_update(void)
{
	return fota_download_util_image_schedule(DFU_TARGET_IMAGE_TYPE_SMP);
}

int mcumgr_smp_client_read_list(struct mcumgr_image_state *image_list)
{
	return dfu_target_smp_image_list_get(image_list);
}

int mcumgr_smp_client_reset(void)
{
	int ret;

	ret = fota_download_util_apply_update(DFU_TARGET_IMAGE_TYPE_SMP);

	if (ret != 0 && reset_cb) {
		ret = reset_cb();
	}

	return ret;
}

int mcumgr_smp_client_erase(void)
{
	int ret;

	if (reset_cb) {
		LOG_ERR("Erase not supported with Recovery mode");
		return -ENOTSUP;
	}

	ret = dfu_target_smp_done(false);
	if (ret != 0) {
		LOG_ERR("dfu_target_done() returned %d", ret);
		return -EBUSY;
	}

	return ret;
}

int mcumgr_smp_client_confirm_image(void)
{
	return dfu_target_smp_confirm_image();
}
