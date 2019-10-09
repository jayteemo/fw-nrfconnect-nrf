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

#define SUPPORTED_FOTA_VERSIONS		(1)
#define SERVICE_INFO_JSON_NAME		"serviceInfo"
#define FOTA_CAPS_JSON_NAME			"fota_v%u"
#define FOTA_CAPS_JSON_NAME_SIZE	(sizeof(FOTA_CAPS_JSON_NAME))
#define SENSOR_CAPS_JSON_NAME		"sensors"

#define CAP_SET		0x01
#define CAP_NOT_SET	0x00

static uint8_t _sensor_caps[SERVICE_INFO_SENSOR__SIZE];
static uint8_t _fota_caps[SUPPORTED_FOTA_VERSIONS][SERVICE_INFO_FOTA__SIZE];

static const char * const _sensor_cap_string[] = {
	[SERVICE_INFO_SENSOR_ACCEL]		= "accel",
	[SERVICE_INFO_SENSOR_HUMID]		= "humid",
	[SERVICE_INFO_SENSOR_TEMP]		= "temp",
	[SERVICE_INFO_SENSOR_COLOR]		= "color",
	[SERVICE_INFO_SENSOR_AIR_PRESS]	= "airPress",
	[SERVICE_INFO_SENSOR_AIR_QUAL]	= "airQual",
	[SERVICE_INFO_SENSOR_GPS]		= "GPS",
	[SERVICE_INFO_SENSOR_BUTTON]	= "button"
};
BUILD_ASSERT(ARRAY_SIZE(_sensor_cap_string) == SERVICE_INFO_SENSOR__SIZE);


static const char * const _fota_cap_string[] = {
	[SERVICE_INFO_FOTA_BOOTLOADER]	= "boot",
	[SERVICE_INFO_FOTA_MODEM]		= "modem",
	[SERVICE_INFO_FOTA_APP]			= "app"
};
BUILD_ASSERT(ARRAY_SIZE(_fota_cap_string) == SERVICE_INFO_FOTA__SIZE);

static service_info_sensor_cap get_cap_from_ch( const enum sensor_channel channel )
{
	service_info_sensor_cap ret = SERVICE_INFO_SENSOR__SIZE;

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
		case SENSOR_CHAN_ALTITUDE:
		case SENSOR_CHAN_PM_1_0:
		case SENSOR_CHAN_PM_2_5:
		case SENSOR_CHAN_PM_10:
		case SENSOR_CHAN_CO2:
		case SENSOR_CHAN_VOC:
			ret = SERVICE_INFO_SENSOR_AIR_QUAL;
			break;
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

int service_info_sensor_cap_add_by_ch(const enum sensor_channel channel)
{
	return service_info_sensor_cap_add( get_cap_from_ch(channel) );
}

int service_info_sensor_cap_remove_by_ch(const enum sensor_channel channel)
{
	return service_info_sensor_cap_remove( get_cap_from_ch(channel) );
}

int service_info_sensor_cap_add( const service_info_sensor_cap sensor_cap )
{
	if ( sensor_cap >= SERVICE_INFO_SENSOR__SIZE )
	{
		return -EINVAL;
	}

	_sensor_caps[sensor_cap] = CAP_SET;

	LOG_DBG("Added cap %s", _sensor_cap_string[sensor_cap] );
	return 0;
}

int service_info_sensor_cap_remove( const service_info_sensor_cap sensor_cap )
{
	if ( sensor_cap >= SERVICE_INFO_SENSOR__SIZE )
	{
		return -EINVAL;
	}

	_sensor_caps[sensor_cap] = CAP_NOT_SET;
	return 0;
}

int service_info_fota_cap_add( const uint32_t version, const service_info_fota_cap fota_cap )
{
	if ( version > SUPPORTED_FOTA_VERSIONS || fota_cap >= SERVICE_INFO_FOTA__SIZE )
	{
		return -EINVAL;
	}

	_fota_caps[version-1][fota_cap] = CAP_SET;

	LOG_DBG("Added cap %s", _fota_cap_string[fota_cap] );
	return 0;
}

int service_info_fota_cap_remove( const uint32_t version, const service_info_fota_cap fota_cap )
{
	if ( version > SUPPORTED_FOTA_VERSIONS || fota_cap >= SERVICE_INFO_FOTA__SIZE )
	{
		return -EINVAL;
	}

	_fota_caps[version-1][fota_cap] = CAP_NOT_SET;
	return 0;
}


#ifdef CONFIG_CJSON_LIB

static int add_sensor_caps_json( cJSON *root_obj_out )
{
	if (root_obj_out == NULL) {
		return -EINVAL;
	}

	cJSON * sens_caps = cJSON_CreateArray();

	if (!sens_caps)
	{
		return -ENOMEM;
	}

	for ( service_info_sensor_cap cap = SERVICE_INFO_SENSOR__FIRST;
		  cap < SERVICE_INFO_SENSOR__SIZE;
		  ++cap )
	{
		if ( _sensor_caps[cap] == CAP_SET )
		{
			cJSON_AddItemToArray( sens_caps, cJSON_CreateString(_sensor_cap_string[cap]) );
		}
	}

	cJSON_AddItemToObject(root_obj_out, SENSOR_CAPS_JSON_NAME, sens_caps );

	return 0;
}

static int add_fota_caps_json( cJSON *root_obj_out )
{
	if (root_obj_out == NULL) {
		return -EINVAL;
	}

	for ( uint32_t ver = 0; ver < SUPPORTED_FOTA_VERSIONS; ++ver )
	{
		char fota_name[FOTA_CAPS_JSON_NAME_SIZE];
		cJSON * fota_caps = cJSON_CreateArray();

		if (!fota_caps)
		{
			return -ENOMEM;
		}

		for ( service_info_fota_cap cap = SERVICE_INFO_FOTA__FIRST;
			  cap < SERVICE_INFO_FOTA__SIZE;
			  ++cap )
		{
			if ( _fota_caps[ver][cap] == CAP_SET )
			{
				cJSON_AddItemToArray( fota_caps, cJSON_CreateString(_fota_cap_string[cap]) );
			}
		}

		int ret = snprintf( fota_name, FOTA_CAPS_JSON_NAME_SIZE, FOTA_CAPS_JSON_NAME, ver+1);

		if ( ret > 0 && ret < FOTA_CAPS_JSON_NAME_SIZE )
		{
			cJSON_AddItemToObject(root_obj_out, fota_name, fota_caps );
		}
		else
		{
			LOG_ERR("FOTA capabilites not added for version %u", ver);
			cJSON_Delete(fota_caps);
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

#endif /* CONFIG_CJSON_LIB */
