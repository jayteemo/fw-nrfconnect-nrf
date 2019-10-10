/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <service_info.h>
#include <logging/log.h>

LOG_MODULE_REGISTER(service_info);

#define SERVICE_INFO_JSON_NAME		"serviceInfo"
#define FOTA_CAPS_JSON_NAME			"fota_v%u"
#define FOTA_CAPS_JSON_NAME_SIZE	(sizeof(FOTA_CAPS_JSON_NAME))
#define SENSOR_CAPS_JSON_NAME		"sensors"

static const char * _sensor_caps[SERVICE_INFO_SENSOR__SIZE];
static const char * _fota_caps[SERVICE_INFO_FOTA_VER__SIZE][SERVICE_INFO_FOTA__SIZE];

static const char * const _sensor_string[] = {
	[SERVICE_INFO_SENSOR_ACCEL]		= "FLIP",
	[SERVICE_INFO_SENSOR_HUMID]		= "HUMID",
	[SERVICE_INFO_SENSOR_TEMP]		= "TEMP",
	[SERVICE_INFO_SENSOR_COLOR]		= "COLOR",
	[SERVICE_INFO_SENSOR_AIR_PRESS]	= "AIR_PRESS",
	[SERVICE_INFO_SENSOR_AIR_QUAL]	= "AIR_QUAL",
	[SERVICE_INFO_SENSOR_GPS]		= "GPS",
	[SERVICE_INFO_SENSOR_BUTTON]	= "BUTTON"
};
BUILD_ASSERT(ARRAY_SIZE(_sensor_string) == SERVICE_INFO_SENSOR__SIZE);


static const char * const _fota_string[] = {
	[SERVICE_INFO_FOTA_BOOTLOADER]	= "BOOT",
	[SERVICE_INFO_FOTA_MODEM]		= "MODEM",
	[SERVICE_INFO_FOTA_APP]			= "APP"
};
BUILD_ASSERT(ARRAY_SIZE(_fota_string) == SERVICE_INFO_FOTA__SIZE);

static service_info_sensor get_from_ch( const enum sensor_channel channel )
{
	service_info_sensor ret = SERVICE_INFO_SENSOR__SIZE;

	switch (channel)
	{
		case SENSOR_CHAN_ACCEL_X:
		case SENSOR_CHAN_ACCEL_Y:
		case SENSOR_CHAN_ACCEL_Z:
		case SENSOR_CHAN_ACCEL_XYZ:
		case SENSOR_CHAN_GYRO_X:
		case SENSOR_CHAN_GYRO_Y:
		case SENSOR_CHAN_GYRO_Z:
		case SENSOR_CHAN_GYRO_XYZ:
		case SENSOR_CHAN_MAGN_X:
		case SENSOR_CHAN_MAGN_Y:
		case SENSOR_CHAN_MAGN_Z:
		case SENSOR_CHAN_MAGN_XYZ:
		case SENSOR_CHAN_ROTATION:
		case SENSOR_CHAN_POS_DX:
		case SENSOR_CHAN_POS_DY:
		case SENSOR_CHAN_POS_DZ:
			ret = SERVICE_INFO_SENSOR_ACCEL;
			break;
		case SENSOR_CHAN_DIE_TEMP:
		case SENSOR_CHAN_AMBIENT_TEMP:
			ret = SERVICE_INFO_SENSOR_TEMP;
			break;
		case SENSOR_CHAN_PRESS:
			ret = SERVICE_INFO_SENSOR_AIR_PRESS;
			break;
		case SENSOR_CHAN_HUMIDITY:
			ret = SERVICE_INFO_SENSOR_HUMID;
			break;
		case SENSOR_CHAN_LIGHT:
		case SENSOR_CHAN_RED:
		case SENSOR_CHAN_GREEN:
		case SENSOR_CHAN_BLUE:
			ret = SERVICE_INFO_SENSOR_COLOR;
			break;
		case SENSOR_CHAN_PM_1_0:
		case SENSOR_CHAN_PM_2_5:
		case SENSOR_CHAN_PM_10:
		case SENSOR_CHAN_CO2:
		case SENSOR_CHAN_VOC:
			ret = SERVICE_INFO_SENSOR_AIR_QUAL;
			break;
		case SENSOR_CHAN_ALTITUDE:
		case SENSOR_CHAN_IR:
		case SENSOR_CHAN_DISTANCE:
		case SENSOR_CHAN_PROX:
		case SENSOR_CHAN_GAS_RES:
		case SENSOR_CHAN_VOLTAGE:
		case SENSOR_CHAN_CURRENT:
		case SENSOR_CHAN_RESISTANCE:
		default:
			break;
	}

	return ret;
}

int service_info_sensor_add_by_ch(const enum sensor_channel channel)
{
	return service_info_sensor_add( get_from_ch(channel) );
}

int service_info_sensor_remove_by_ch(const enum sensor_channel channel)
{
	return service_info_sensor_remove( get_from_ch(channel) );
}

int service_info_sensor_add( const service_info_sensor sensor )
{
	if ( sensor < SERVICE_INFO_SENSOR__FIRST ||
		 sensor >= SERVICE_INFO_SENSOR__SIZE )
	{
		return -EINVAL;
	}

	_sensor_caps[sensor] = _sensor_string[sensor];

	LOG_DBG("Added cap %s", _sensor_string[sensor] );
	return 0;
}

int service_info_sensor_remove( const service_info_sensor sensor )
{
	if ( sensor < SERVICE_INFO_SENSOR__FIRST ||
		 sensor >= SERVICE_INFO_SENSOR__SIZE )
	{
		return -EINVAL;
	}

	_sensor_caps[sensor] = NULL;
	return 0;
}

int service_info_fota_add( const service_info_fota_ver version, const service_info_fota fota )
{
	if ( version < SERVICE_INFO_FOTA_VER__FIRST ||
		 version >= SERVICE_INFO_FOTA_VER__SIZE ||
		 fota < SERVICE_INFO_FOTA__FIRST ||
		 fota >= SERVICE_INFO_FOTA__SIZE )
	{
		return -EINVAL;
	}

	_fota_caps[version][fota] = _fota_string[fota];

	LOG_DBG("Added cap %s", _fota_string[fota] );
	return 0;
}

int service_info_fota_remove( const service_info_fota_ver version, const service_info_fota fota )
{
	if ( version < SERVICE_INFO_FOTA_VER__FIRST ||
		 version >= SERVICE_INFO_FOTA_VER__SIZE ||
		 fota < SERVICE_INFO_FOTA__FIRST ||
		 fota >= SERVICE_INFO_FOTA__SIZE )
	{
		return -EINVAL;
	}

	_fota_caps[version][fota] = NULL;
	return 0;
}

static int add_sensor_caps_json( cJSON *root_obj_out )
{
	if (root_obj_out == NULL) {
		return -EINVAL;
	}

	cJSON * sensors = cJSON_CreateArray();

	if (!sensors)
	{
		return -ENOMEM;
	}

	for ( service_info_sensor cap = SERVICE_INFO_SENSOR__FIRST;
		  cap < SERVICE_INFO_SENSOR__SIZE;
		  ++cap )
	{
		if ( _sensor_caps[cap] )
		{
			cJSON_AddItemToArray( sensors, cJSON_CreateString(_sensor_caps[cap]) );
		}
	}

	cJSON_AddItemToObject(root_obj_out, SENSOR_CAPS_JSON_NAME, sensors );

	return 0;
}

static int add_fota_caps_json( cJSON *root_obj_out )
{
	if (root_obj_out == NULL) {
		return -EINVAL;
	}

	for ( uint32_t ver = 0; ver < SERVICE_INFO_FOTA_VER__SIZE; ++ver )
	{
		char fota_name[FOTA_CAPS_JSON_NAME_SIZE];
		cJSON * fotas = cJSON_CreateArray();

		if (!fotas)
		{
			return -ENOMEM;
		}

		for ( service_info_fota cap = SERVICE_INFO_FOTA__FIRST;
			  cap < SERVICE_INFO_FOTA__SIZE;
			  ++cap )
		{
			if ( _fota_caps[ver][cap] )
			{
				cJSON_AddItemToArray( fotas, cJSON_CreateString(_fota_caps[ver][cap]) );
			}
		}

		int ret = snprintf( fota_name, FOTA_CAPS_JSON_NAME_SIZE, FOTA_CAPS_JSON_NAME, ver+1);

		if ( ret > 0 && ret < FOTA_CAPS_JSON_NAME_SIZE )
		{
			cJSON_AddItemToObject(root_obj_out, fota_name, fotas );
		}
		else
		{
			LOG_ERR("FOTA capabilities not added for version %u", ver);
			cJSON_Delete(fotas);
		}

	}

	return 0;
}


int service_info_json_object_get(cJSON *root_obj_out)
{
	int ret = 0;

	if (root_obj_out == NULL ) {
		return -EINVAL;
	}

	cJSON * service_info_obj = cJSON_CreateObject();

	if (service_info_obj == NULL) {
		ret = -ENOMEM;
	}

	if ( !ret )
	{
		ret = add_sensor_caps_json(service_info_obj);
	}

	if ( !ret )
	{
		ret = add_fota_caps_json(service_info_obj);
	}

	if ( !ret )
	{
		cJSON_AddItemToObject(root_obj_out, SERVICE_INFO_JSON_NAME, service_info_obj);
	}
	else
	{
		cJSON_Delete(service_info_obj);
	}

	return ret;
}
