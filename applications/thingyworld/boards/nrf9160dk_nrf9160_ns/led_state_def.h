/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <caf/led_effect.h>
#include "events/led_state_event.h"

/* This configuration file is included only once from led_state module and holds
 * information about LED effects associated with Asset Tracker v2 states.
 */

/* This structure enforces the header file to be included only once in the build.
 * Violating this requirement triggers a multiple definition error at link time.
 */
const struct {} led_state_def_include_once;

enum led_id {
	LED_ID_1,
	LED_ID_2,
	LED_ID_3,
	LED_ID_4,

	LED_ID_COUNT,

	LED_ID_CONNECTING = LED_ID_1,
	LED_ID_SEARCHING = LED_ID_2,
	LED_ID_PUBLISHING = LED_ID_3,
	LED_ID_MODE = LED_ID_4,
};

#define LED_PERIOD_NORMAL	500
#define LED_PERIOD_LONG		3500

static const struct led_effect asset_tracker_led_effect[] = {
	[LED_STATE_LTE_CONNECTING]	= LED_EFFECT_LED_BLINK(LED_PERIOD_NORMAL,
								LED_COLOR(100, 100, 100)),
	[LED_STATE_GPS_SEARCHING]	= LED_EFFECT_LED_BLINK(LED_PERIOD_NORMAL,
								LED_COLOR(100, 100, 100)),
	[LED_STATE_CLOUD_PUBLISHING]	= LED_EFFECT_LED_BLINK(LED_PERIOD_NORMAL,
								LED_COLOR(100, 100, 100)),
	[LED_STATE_ACTIVE_MODE]		= LED_EFFECT_LED_BLINK(LED_PERIOD_NORMAL,
								LED_COLOR(100, 100, 100)),
	[LED_STATE_PASSIVE_MODE]	= LED_EFFECT_LED_BLINK(LED_PERIOD_LONG,
								LED_COLOR(100, 100, 100)),
	[LED_STATE_ERROR_SYSTEM_FAULT]	= LED_EFFECT_LED_BLINK(LED_PERIOD_NORMAL,
								LED_COLOR(100, 100, 100)),
	[LED_STATE_FOTA_UPDATE_REBOOT]	= LED_EFFECT_LED_ON(LED_COLOR(100, 100, 100)),
	[LED_STATE_LOC_MODE_SCELL]	 LED_EFFECT_LED_BREATH(LED_PERIOD_NORMAL,
								LED_COLOR(0, 0, 100)),
	[LED_STATE_LOC_MODE_MCELL]	 LED_EFFECT_LED_BREATH(LED_PERIOD_NORMAL,
								LED_COLOR(0, 100, 0)),
	[LED_STATE_LOC_MODE_ALL]	 LED_EFFECT_LED_BLINK_2(LED_PERIOD_NORMAL,
								LED_COLOR(100, 0, 100),
								LED_COLOR(0, 100, 0 )),
	[LED_STATE_TURN_OFF]		= LED_EFFECT_LED_OFF(),
};
