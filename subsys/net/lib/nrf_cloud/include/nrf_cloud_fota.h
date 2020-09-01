/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef NRF_CLOUD_FOTA_H__
#define NRF_CLOUD_FOTA_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <net/mqtt.h>

enum nrf_cloud_fota_type {
	NRF_FOTA_APPLICATION = 0,
	NRF_FOTA_MODEM = 1,
	NRF_FOTA_BOOTLOADER = 2,
};

enum nrf_cloud_fota_status {
	NRF_FOTA_QUEUED = 0,
	NRF_FOTA_IN_PROGRESS = 1,
	NRF_FOTA_FAILED = 2,
	NRF_FOTA_SUCCEEDED = 3,
	NRF_FOTA_TIMED_OUT = 4,
	NRF_FOTA_CANCELED = 5,
	NRF_FOTA_REJECTED = 6,
	NRF_FOTA_DOWNLOADING = 7,
};

enum nrf_cloud_fota_evt_id {
	NRF_FOTA_EVT_START,
	NRF_FOTA_EVT_DONE,
	NRF_FOTA_EVT_ERROR,
	NRF_FOTA_EVT_ERASE_PENDING,
	NRF_FOTA_EVT_ERASE_DONE,
	NRF_FOTA_EVT_DL_PROGRESS,
};

enum nrf_cloud_fota_error {
	NRF_FOTA_ERROR_NONE = 0,
	NRF_FOTA_ERROR_DOWNLOAD_START,
	NRF_FOTA_ERROR_DOWNLOAD,
};

struct nrf_cloud_fota_evt {
	enum nrf_cloud_fota_evt_id id;

	enum nrf_cloud_fota_status status;
	enum nrf_cloud_fota_type type;
	union {
		enum nrf_cloud_fota_error error;
		int dl_progress;
	} evt_data;
};

typedef void (*nrf_cloud_fota_callback_t)(const struct nrf_cloud_fota_evt * const evt);

int nrf_cloud_fota_init(struct mqtt_client *const client, nrf_cloud_fota_callback_t cb);

int nrf_cloud_fota_mqtt_evt_handler(const struct mqtt_evt *_mqtt_evt);

int nrf_cloud_fota_endpoint_set(const char * const client_id,
				const struct mqtt_utf8 * const endpoint);
void nrf_cloud_fota_endpoint_clear(void);

int nrf_cloud_fota_subscribe(void);
int nrf_cloud_fota_unsubscribe(void);

#endif /* NRF_CLOUD_FOTA_H__ */