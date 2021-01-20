/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#ifndef NRF_CLOUD_AGPS_H_
#define NRF_CLOUD_AGPS_H_

/** @file nrf_cloud_agps.h
 * @brief Module to provide nRF Cloud A-GPS support to nRF9160 SiP.
 */

#include <zephyr.h>
#include <drivers/gps.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup nrf_cloud_agps nRF Cloud AGPS
 * @{
 */

/**@brief Requests specified A-GPS data from nRF Cloud.
 *
 * @param request Structure containing specified A-GPS data to be requested.
 *
 * @return 0 if successful, otherwise a (negative) error code.
 */
int nrf_cloud_agps_request(const struct gps_agps_request request);

/**@brief Requests all available A-GPS data from nRF Cloud.
 *
 * @return 0 if successful, otherwise a (negative) error code.
 */
int nrf_cloud_agps_request_all(void);

/**@brief Requests single-cell based location from nRF Cloud.
 *
 * @return 0 if successful, otherwise a (negative) error code.
 * @note Requires CONFIG_NRF_CLOUD_AGPS_SINGLE_CELL_ONLY to be enabled.
 */
int nrf_cloud_agps_request_single_cell(void);

/**@brief Gets most recent location from single-cell request.
 *
 * @param lat Pointer where last single cell latitude is to be copied.
 * @param lon Pointer where last single cell longitude is to be copied.
 * @return 0 if successful, otherwise a (negative) error code.
 * @note Requires CONFIG_NRF_CLOUD_AGPS_SINGLE_CELL_ONLY to be enabled.
 */
int nrf_cloud_agps_get_last_single_cell_location(double * const lat,
						 double * const lon);

/**@brief Processes binary A-GPS data received from nRF Cloud.
 *
 * @param buf Pointer to data received from nRF Cloud.
 * @param buf_len Buffer size of data to be processed.
 * @param socket Pointer to GNSS socket to which A-GPS data will be injected.
 *		 If NULL, the nRF9160 GPS driver is used to inject the data.
 *
 * @return 0 if successful, otherwise a (negative) error code.
 */
int nrf_cloud_agps_process(const char *buf, size_t buf_len, const int *socket);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* NRF_CLOUD_AGPS_H_ */
