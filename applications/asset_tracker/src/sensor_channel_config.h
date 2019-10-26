/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef SENSOR_CHANNEL_CONFIG_H__
#define SENSOR_CHANNEL_CONFIG_H__

#include <zephyr.h>

/**
 * @file sensor_channel_config.h
 *
 * @brief API to configure sensor channels for sending data to the cloud.
 * @defgroup sensor_channel_config API to configure sensor to cloud data.
 * @{
 */

enum sensor_ch_cfg_item_type {
	SENSOR_CH_CFG_ITEM_TYPE__BEGIN,

	SENSOR_CH_CFG_ITEM_TYPE_SEND_ENABLE = SENSOR_CH_CFG_ITEM_TYPE__BEGIN,
	SENSOR_CH_CFG_ITEM_TYPE_THRESH_LOW_VALUE,
	SENSOR_CH_CFG_ITEM_TYPE_THRESH_LOW_ENABLE,
	SENSOR_CH_CFG_ITEM_TYPE_THRESH_HIGH_VALUE,
	SENSOR_CH_CFG_ITEM_TYPE_THRESH_HIGH_ENABLE,

	SENSOR_CH_CFG_ITEM_TYPE__END
};

struct sensor_ch_cfg {
	s32_t value[SENSOR_CH_CFG_ITEM_TYPE__END];
};

int sensor_ch_config_set_item( struct sensor_ch_cfg * const cfg,
		const enum sensor_ch_cfg_item_type type, const s32_t value);

/** @} */

#endif /* SENSOR_CHANNEL_CONFIG_H__ */
