/* Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef _FOTA_SUPPORT_H_
#define _FOTA_SUPPORT_H_

#include <zephyr/kernel.h>

/**
 * @brief Check whether we are capable of Firmware Over The Air (FOTA) application or modem update.
 *
 * @return bool - Whether we are capable of application or modem FOTA.
 */
static inline bool app_fota_capable(void)
{
	return IS_ENABLED(CONFIG_NRF_CLOUD_FOTA) &&
	       IS_ENABLED(CONFIG_BOOTLOADER_MCUBOOT);
}
static inline bool boot_fota_capable(void)
{
	return IS_ENABLED(CONFIG_NRF_CLOUD_FOTA) &&
	       IS_ENABLED(CONFIG_BOOTLOADER_MCUBOOT) &&
	       IS_ENABLED(CONFIG_BUILD_S1_VARIANT) &&
	       IS_ENABLED(CONFIG_SECURE_BOOT);
}
static inline bool modem_delta_fota_capable(void)
{
	return IS_ENABLED(CONFIG_NRF_CLOUD_FOTA) &&
	       IS_ENABLED(CONFIG_NRF_MODEM);
}
static inline bool modem_full_fota_capable(void)
{
	return IS_ENABLED(CONFIG_NRF_CLOUD_FOTA) &&
	       IS_ENABLED(CONFIG_NRF_CLOUD_FOTA_FULL_MODEM_UPDATE) &&
	       IS_ENABLED(CONFIG_NRF_MODEM);
}

/**
 * @brief Notify fota_support that a FOTA download has finished.
 *
 * Besides updating the device shadow (handled in connection.c), this is the only additional
 * code needed to get FOTA working properly, and its sole function is to reboot the microcontroller
 * after FOTA download completes.
 *
 */
void on_fota_downloaded(void);

#endif /* _FOTA_SUPPORT_H_ */
