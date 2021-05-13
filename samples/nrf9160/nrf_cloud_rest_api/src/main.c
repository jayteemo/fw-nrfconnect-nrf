/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <stdlib.h>
#include <stdio.h>
#include <net/socket.h>
#include <net/net_ip.h>
#include <modem/nrf_modem_lib.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <net/tls_credentials.h>
#include <modem/lte_lc.h>
#include <modem/modem_key_mgmt.h>
#include <net/http_client.h>
#include <sys/base64.h>
#include <net/nrf_cloud_rest.h>
#include <modem/modem_jwt.h>
#include <logging/log.h>
#include "modem_ncellmeas.h"

BUILD_ASSERT(sizeof(CONFIG_REST_DEVICE_ID) > 1, "Device ID must be specified");

LOG_MODULE_REGISTER(rest_sample, CONFIG_NRF_CLOUD_REST_SAMPLE_LOG_LEVEL);

int init_modem_and_connect(void)
{
	int err;

	err = nrf_modem_lib_init(NORMAL_MODE);
	if (err) {
		LOG_ERR("Failed to initialize modem library: %d", err);
		return err;
	}

	err = at_cmd_init();
	if (err) {
		LOG_ERR("Failed to initialize AT commands, err %d", err);
		return err;
	}

	err = at_notif_init();
	if (err) {
		LOG_ERR("Failed to initialize AT notifications, err %d", err);
		return err;
	}

	LOG_INF("Waiting for network...");
	err = lte_lc_init_and_connect();
	if (err) {
		LOG_ERR("Failed to connect to the LTE network, err %d", err);
		return err;
	}
	LOG_INF("Connected");
	return 0;
}

void main(void)
{
	char rx_buf[2100];
	int agps_sz;
	static struct nrf_cloud_fota_job_info job;
	struct cell_based_loc_data location;
	struct n_cell_measure_result n_cell;
	struct jwt_data jwt = {
		.subject = CONFIG_REST_DEVICE_ID,
		.audience = "nRF Cloud",
		.exp_delta_s = 0,
		.sec_tag = CONFIG_REST_JWT_SEC_TAG,
		.key = JWT_KEY_TYPE_CLIENT_PRIV,
		.alg = JWT_ALG_TYPE_ES256
	};
	struct nrf_cloud_rest_context rest_ctx = {
		.connect_socket = -1,
		.keep_alive = true,
		/* TODO: JWTs are not yet supported; use API token for location APIs */
		.auth = CONFIG_REST_API_TOKEN,
		.timeout_ms = 30000,
		.rx_buf = rx_buf,
		.rx_buf_len = sizeof(rx_buf)
	};
	struct nrf_cloud_rest_single_cell_request req = {
		.device_id = CONFIG_REST_DEVICE_ID,
		.net_info = {
			.mcc = 310,
			.mnc = 410,
			.area_code = 36879,
			.cell_id = 84486415
		}
	};
	struct nrf_cloud_rest_agps_request agps_request = {
		.device_id = CONFIG_REST_DEVICE_ID,
		.type = NRF_CLOUD_REST_AGPS_REQ_CUSTOM
	};
	struct gps_agps_request agps = {
		.utc = 1,
		.sv_mask_ephe = 1,
		.sv_mask_alm = 1,
		.klobuchar = 1
	};
	struct nrf_cloud_rest_agps_result agps_result = {
		.buf_sz = 0,
		.buf = NULL
	};

	int err = init_modem_and_connect();

	if (err){
		return;
	}

	/* Exercise AGPS API */
	agps_request.net_info = &req.net_info;
	agps_request.agps_req = &agps;
	/* When requesting a potentially large result, set fragment size to a
	 * small value (1) and do not provide a result buffer.
	 * This will allow you to obtain the necessary size while limiting
	 * data transfer.
	 */
	rest_ctx.fragment_size = 1;
	agps_sz = nrf_cloud_rest_agps_data_get(&rest_ctx, &agps_request, NULL);
	if (agps_sz < 0) {
		LOG_ERR("Failed to get AGPS data: %d", agps_sz);
		return;
	} else if (agps_sz == 0) {
		LOG_ERR("AGPS request successful");
		return;
	}

	LOG_INF("Additional buffer required to download AGPS data of %d bytes",
		agps_sz);

	agps_result.buf_sz = (uint32_t)agps_sz;
	agps_result.buf = k_calloc(agps_result.buf_sz, 1);
	if (!agps_result.buf) {
		LOG_ERR("Failed to allocate %u bytes for AGPS buffer", agps_result.buf_sz);
		return;
	}
	/* Use the default configured fragment size */
	rest_ctx.fragment_size = 0;
	err = nrf_cloud_rest_agps_data_get(&rest_ctx, &agps_request, &agps_result);
	if (err) {
		LOG_ERR("Failed to get AGPS data: %d", err);
	} else {
		// TODO: send to modem?
	}

	k_free(agps_result.buf);
	agps_result.buf = NULL;

	/* TODO: replace with existing ncellmeas handling */
	err = modem_get_neighboring_cell_data(&n_cell);
	if (err) {
		LOG_ERR("Failed to get neighboring cell data");
		n_cell.status = N_CELL_MEAS_N_STATUS_FAIL;
	}

	if (n_cell.status == N_CELL_MEAS_N_STATUS_FAIL) {
		LOG_WRN("Using dummy data for SCELL/MCELL location request");
	} else {
		LOG_INF("CID: %d, TAC: %d, MNC: %d, MCC: %d, neighbors: %d",
			n_cell.cell_id,
			n_cell.area_code,
			n_cell.mnc,
			n_cell.mcc,
			n_cell.n_cnt);

		/* Single-cell request */
		/* TODO: when MCELL is available, use neighbor data */
		req.net_info.cell_id = n_cell.cell_id;
		req.net_info.area_code = n_cell.area_code;
		req.net_info.mnc = n_cell.mnc;
		req.net_info.mcc = n_cell.mcc;
	}

	/* Exercise single-cell API */
	err = nrf_cloud_rest_get_single_cell_loc(&rest_ctx, &req, &location);
	if (err) {
		LOG_ERR("Single Cell API call failed, error: %d", err);
	} else {
		LOG_INF("Single Cell Response: %s", log_strdup(rest_ctx.response));
	}

	/* Use JWT for FOTA endpoints */
	err = modem_jwt_generate(&jwt);
	if (err) {
		LOG_ERR("Failed to generate JWT, err %d", err);
		return;
	}
	LOG_INF("JWT:\n%s", log_strdup(jwt.jwt_out));

	/* JWT auth */
	rest_ctx.auth = jwt.jwt_out;

	/* Exercise the FOTA API by checking for a job
	 * and if a job exists, mark it as cancelled.
	 */
	err = nrf_cloud_rest_get_fota_job(&rest_ctx, CONFIG_REST_DEVICE_ID, &job);
	if (err) {
		goto cleanup;
	}

	if (job.type == NRF_CLOUD_FOTA_TYPE__INVALID) {
		LOG_INF("No pending FOTA jobs");
		goto cleanup;
	}

	LOG_INF("FOTA Job: %s, type: %d", log_strdup(job.id), job.type);

	/* Disconnect after next API call */
	rest_ctx.keep_alive = false;

	/* Cancel the job */
	err = nrf_cloud_rest_update_fota_job(&rest_ctx,
						CONFIG_REST_DEVICE_ID,
						job.id,
						NRF_CLOUD_FOTA_CANCELED);
	if (err) {
		LOG_ERR("Failed to update FOTA job, error: %d", err);
	} else {
		LOG_INF("FOTA job updated");
	}

cleanup:
	if (jwt.jwt_out) {
		k_free(jwt.jwt_out);
	}
	if (job.id) {
		k_free(job.id);
	}
	if (job.host) {
		k_free(job.host);
	}
	if (job.path) {
		k_free(job.path);
	}
}
