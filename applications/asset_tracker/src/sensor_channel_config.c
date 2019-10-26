/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include "sensor_channel_config.h"

int sensor_ch_config_set_item( struct sensor_ch_cfg * const cfg,
		const enum sensor_ch_cfg_item_type type, const s32_t value)
{
	if ((type < SENSOR_CH_CFG_ITEM_TYPE__BEGIN) ||
		(type >= SENSOR_CH_CFG_ITEM_TYPE__END) ||
		(cfg == NULL)) {
		return -EINVAL;
	}

	cfg->value[type] = value;

	return 0;
}
