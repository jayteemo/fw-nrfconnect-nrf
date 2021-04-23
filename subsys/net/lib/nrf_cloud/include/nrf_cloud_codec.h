/*
 * Copyright (c) 2017 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef NRF_CLOUD_CODEC_H__
#define NRF_CLOUD_CODEC_H__

#include <stdbool.h>
#include <net/nrf_cloud.h>
#include "cJSON.h"
#include "nrf_cloud_fsm.h"

#ifdef __cplusplus
extern "C" {
#endif

/**@brief Initialize the codec used encoding the data to the cloud. */
int nrf_cloud_codec_init(void);

/**@brief Encode the sensor data based on the indicated type. */
int nrf_cloud_encode_sensor_data(const struct nrf_cloud_sensor_data *input,
				 struct nrf_cloud_data *output);

/**@brief Encode the sensor data to be sent to the device shadow. */
int nrf_cloud_encode_shadow_data(const struct nrf_cloud_sensor_data *sensor,
				 struct nrf_cloud_data *output);

/**@brief Encode the user association data based on the indicated type. */
int nrf_cloud_decode_requested_state(const struct nrf_cloud_data *payload,
				     enum nfsm_state *requested_state);

/**@brief Decodes data endpoint information. */
int nrf_cloud_decode_data_endpoint(const struct nrf_cloud_data *input,
				   struct nrf_cloud_data *tx_endpoint,
				   struct nrf_cloud_data *rx_endpoint,
				   struct nrf_cloud_data *m_endpoint);

/** @brief Encodes state information. */
int nrf_cloud_encode_state(uint32_t reported_state, struct nrf_cloud_data *output);

/** @brief Search input for config and encode response if necessary. */
int nrf_cloud_encode_config_response(struct nrf_cloud_data const *const input,
				     struct nrf_cloud_data *const output,
				     bool *const has_config);

int nrf_cloud_parse_cell_location_json(const cJSON * const cell_loc_obj,
	const enum cell_based_location_type type,
	struct nrf_cloud_cell_pos_result *const location_out);

int nrf_cloud_parse_cell_location(const char *const response,
	const enum cell_based_location_type type,
	struct nrf_cloud_cell_pos_result *const location_out);

void nrf_cloud_fota_job_free(struct nrf_cloud_fota_job_info *const job);

int nrf_cloud_rest_fota_execution_parse(const char *const response,
	struct nrf_cloud_fota_job_info *const job);

int nrf_cloud_parse_pgps_response(const char *const response,
	struct nrf_cloud_pgps_result *const result);

int get_string_from_array(const cJSON * const array, const int index,
			  char **string_out);

int get_string_from_obj(const cJSON * const obj, const char *const key,
			char **string_out);

#ifdef __cplusplus
}
#endif

#endif /* NRF_CLOUD_CODEC_H__ */
