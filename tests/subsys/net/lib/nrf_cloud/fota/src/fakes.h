/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/fff.h>
#include <zephyr/ztest.h>
#include <zephyr/net/mqtt.h>
#include <net/nrf_cloud.h>
#include <net/fota_download.h>
#include "nrf_cloud_fota.h"

DEFINE_FFF_GLOBALS;

FAKE_VALUE_FUNC(int, nrf_cloud_fota_pending_job_validate, enum nrf_cloud_fota_type * const);
FAKE_VALUE_FUNC(int, fota_download_init, fota_download_callback_t client_callback);
FAKE_VALUE_FUNC(int, mqtt_publish, struct mqtt_client *, const struct mqtt_publish_param *);

int fake_nrf_cloud_fota_pending_job_validate__fails(enum nrf_cloud_fota_type * const type)
{
	ARG_UNUSED(type);
	return -EIO;
}

int fake_nrf_cloud_fota_pending_job_validate__no_job(enum nrf_cloud_fota_type * const type)
{
	ARG_UNUSED(type);
	return -ENODEV;
}

int fake_nrf_cloud_fota_pending_job_validate__succeeds_zero(enum nrf_cloud_fota_type * const type)
{
	ARG_UNUSED(type);
	return 0;
}

int fake_nrf_cloud_fota_pending_job_validate__succeeds_one(enum nrf_cloud_fota_type * const type)
{
	ARG_UNUSED(type);
	return 1;
}

int fota_download_init__fails(fota_download_callback_t client_callback)
{
	ARG_UNUSED(client_callback);
	return -EIO;
}

int fota_download_init__succeeds(fota_download_callback_t client_callback)
{
	ARG_UNUSED(client_callback);
	return 0;
}

int mqtt_publish__succeeds(struct mqtt_client *client, const struct mqtt_publish_param *param)
{
	ARG_UNUSED(client);
	ARG_UNUSED(param);
	return 0;
}

int mqtt_publish__fails(struct mqtt_client *client, const struct mqtt_publish_param *param)
{
	ARG_UNUSED(client);
	ARG_UNUSED(param);
	return -EIO;
}
