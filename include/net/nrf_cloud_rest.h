/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file nrf_cloud_rest.h
 *
 * @brief nRF Cloud REST API.
 *
 */
#ifndef NRF_CLOUD_REST_H__
#define NRF_CLOUD_REST_H__

#include <zephyr/types.h>
#include <net/nrf_cloud.h>
#include <drivers/gps.h>

#ifdef __cplusplus
extern "C" {
#endif

enum http_status {
	HTTP_STATUS_UNHANDLED = -1,
	HTTP_STATUS_NONE = 0,
	HTTP_STATUS_OK = 200,
	HTTP_STATUS_ACCEPTED = 202,
	HTTP_STATUS_PARTIAL = 206,
	HTTP_STATUS_BAD_REQ = 400,
	HTTP_STATUS_UNAUTH = 401,
	HTTP_STATUS_FORBIDDEN = 403,
	HTTP_STATUS_NOT_FOUND = 404,
	HTTP_STATUS_BAD_RANGE = 416,
	HTTP_STATUS_UNPROC_ENTITY = 422,
};

/** @brief nRF Cloud AGPS REST request types */
enum nrf_cloud_rest_agps_req_type {
	NRF_CLOUD_REST_AGPS_REQ_ASSISTANCE,
	NRF_CLOUD_REST_AGPS_REQ_LOCATION,
	NRF_CLOUD_REST_AGPS_REQ_CUSTOM,
	NRF_CLOUD_REST_AGPS_REQ_UNSPECIFIED,
};

/** @brief Parameters and data for using the nRF Cloud REST API */
struct nrf_cloud_rest_context {

	/** Connection socket */
	int connect_socket;
	/** If the connection should remain after API call */
	bool keep_alive;
	/** Timeout value for receiving response data */
	int32_t timeout_ms;
	/** Authentication string: JWT or API token */
	char * auth;
	/** User allocated buffer for receiving API response */
	char * rx_buf;
	/** Size of rx_buf */
	size_t rx_buf_len;

	/** Results from API call */
	/** HTTP status of API call */
	enum http_status status;
	/** Start of response data in rx_buf */
	char * response;
	/** Length of response data */
	size_t response_len;
};

struct nrf_cloud_rest_network_info {
	uint16_t mcc;
	uint16_t mnc;
	uint16_t area_code;
	uint32_t cell_id;
};

struct nrf_cloud_rest_single_cell_request {
	/* Optional; provide valid string or set to NULL */
	char * device_id;
	struct nrf_cloud_rest_network_info net_info;
};

struct nrf_cloud_rest_agps_request {
	/* Optional; provide valid string or set to NULL */
	char * device_id;
	enum nrf_cloud_rest_agps_req_type type;
	/* Required for custom request type */
	struct gps_agps_request * agps_req;
	/* Optional; provide network info or set to NULL */
	struct nrf_cloud_rest_network_info * net_info;
};

int nrf_cloud_rest_get_single_cell_loc(struct nrf_cloud_rest_context * const rest_ctx,
	struct nrf_cloud_rest_single_cell_request const * const request,
	struct cell_based_loc_data * const result);

int nrf_cloud_rest_get_multi_cell_loc(struct nrf_cloud_rest_context * const rest_ctx);

int nrf_cloud_rest_agps_data_get(struct nrf_cloud_rest_context * const rest_ctx,
				 struct nrf_cloud_rest_agps_request const *const request,
				 struct nrf_cloud_data *const result);

int nrf_cloud_rest_get_fota_job(struct nrf_cloud_rest_context * const rest_ctx,
	const char * const device_id, struct nrf_cloud_fota_job_info *const job);

int nrf_cloud_rest_update_fota_job(struct nrf_cloud_rest_context * const rest_ctx,
	const char * const device_id, const char * const job_id,
	const enum nrf_cloud_fota_status status);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* NRF_CLOUD_REST_H__ */
