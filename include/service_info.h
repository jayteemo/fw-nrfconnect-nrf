/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef ZEPHYR_INCLUDE_SERVICE_INFO_H_
#define ZEPHYR_INCLUDE_SERVICE_INFO_H_

#include <sensor.h>
#include <cJSON.h>

/**
 * @file service_info.h
 *
 * @brief API for registering device capabilities with the cloud.
 * @defgroup service_info API for registering device capabilities with the cloud.
 * @{
 */

/**@brief Supported sensor capabilities */
typedef enum service_info_sensor_e {
	SERVICE_INFO_SENSOR__FIRST = 0,

	SERVICE_INFO_SENSOR_ACCEL = SERVICE_INFO_SENSOR__FIRST,
	SERVICE_INFO_SENSOR_HUMID,
	SERVICE_INFO_SENSOR_TEMP,
	SERVICE_INFO_SENSOR_COLOR,
	SERVICE_INFO_SENSOR_AIR_PRESS,
	SERVICE_INFO_SENSOR_AIR_QUAL,
	SERVICE_INFO_SENSOR_GPS,
	SERVICE_INFO_SENSOR_BUTTON,

	SERVICE_INFO_SENSOR__SIZE
} service_info_sensor;

/**@brief Supported fota versions */
typedef enum service_info_fota_ver_e {
	SERVICE_INFO_FOTA_VER__FIRST = 0,

	SERVICE_INFO_FOTA_VER_1 = SERVICE_INFO_FOTA_VER__FIRST,

	SERVICE_INFO_FOTA_VER__SIZE,
} service_info_fota_ver;

/**@brief Supported fota capabilities */
typedef enum service_info_fota_e {
	SERVICE_INFO_FOTA__FIRST = 0,

	SERVICE_INFO_FOTA_BOOTLOADER = SERVICE_INFO_FOTA__FIRST,
	SERVICE_INFO_FOTA_MODEM,
	SERVICE_INFO_FOTA_APP,

	SERVICE_INFO_FOTA__SIZE,
} service_info_fota;

int service_info_sensor_add_by_ch		(const enum sensor_channel channel);

int service_info_sensor_remove_by_ch	(const enum sensor_channel channel);

int service_info_sensor_add		(const service_info_sensor sensor);

int service_info_sensor_remove	(const service_info_sensor sensor);

int service_info_fota_add		(const service_info_fota_ver version, 
								 const service_info_fota fota);

int service_info_fota_remove	(const service_info_fota_ver version, 
								 const service_info_fota fota);

int service_info_json_object_get(cJSON *obj_out);

#endif /* ZEPHYR_INCLUDE_SERVICE_INFO_H_ */
