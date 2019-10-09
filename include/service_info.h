/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef ZEPHYR_INCLUDE_SERVICE_INFO_H_
#define ZEPHYR_INCLUDE_SERVICE_INFO_H_

#ifdef CONFIG_CJSON_LIB
#include <cJSON.h>
#endif

#include <sensor.h>

/**
 * @file service_info.h
 *
 * @brief API for registering device capabilities with the cloud.
 * @defgroup service_info API for registering device capabilities with the cloud.
 * @{
 */

/**@brief Supported sensor capabilities */
typedef enum service_info_sensor_cap_e {
	SERVICE_INFO_SENSOR__FIRST,

	SERVICE_INFO_SENSOR_ACCEL = SERVICE_INFO_SENSOR__FIRST,
	SERVICE_INFO_SENSOR_HUMID,
	SERVICE_INFO_SENSOR_TEMP,
	SERVICE_INFO_SENSOR_COLOR,
	SERVICE_INFO_SENSOR_AIR_PRESS,
	SERVICE_INFO_SENSOR_AIR_QUAL,
	SERVICE_INFO_SENSOR_GPS,
	SERVICE_INFO_SENSOR_BUTTON,

	SERVICE_INFO_SENSOR__SIZE
} service_info_sensor_cap;


/**@brief Supported fota capabilities */
typedef enum service_info_fota_cap_e {
	SERVICE_INFO_FOTA__FIRST,

	SERVICE_INFO_FOTA_BOOTLOADER = SERVICE_INFO_FOTA__FIRST,
	SERVICE_INFO_FOTA_MODEM,
	SERVICE_INFO_FOTA_APP,

	SERVICE_INFO_FOTA__SIZE,
} service_info_fota_cap;

int service_info_sensor_cap_add_by_ch		(const enum sensor_channel channel);
int service_info_sensor_cap_remove_by_ch	(const enum sensor_channel channel);

int service_info_sensor_cap_add		(const service_info_sensor_cap sensor_cap);
int service_info_sensor_cap_remove	(const service_info_sensor_cap sensor_cap);

int service_info_fota_cap_add		(const uint32_t version, const service_info_fota_cap fota_cap);
int service_info_fota_cap_remove	(const uint32_t version, const service_info_fota_cap fota_cap);

#ifdef CONFIG_CJSON_LIB
int service_info_json_object_get(cJSON *obj_out);
#endif /* CONFIG_CJSON_LIB */

#endif /* ZEPHYR_INCLUDE_SERVICE_INFO_H_ */
