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

#define REST_RX_BUF_SZ	2100

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
	char rx_buf[REST_RX_BUF_SZ];
	char pgps_host[65];
	char pgps_path[129];
	int agps_sz;
	static struct nrf_cloud_fota_job_info job;
	struct nrf_cloud_cell_pos_result location;
	struct n_cell_measure_result n_cell;
	struct jwt_data jwt = {
		.subject = CONFIG_REST_DEVICE_ID,
		.audience = NULL,
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
		.rx_buf_len = sizeof(rx_buf),
		.fragment_size = 0
	};
	struct nrf_cloud_rest_scell_request scell_req = {
		.device_id = CONFIG_REST_DEVICE_ID,
		.net_info = {
			.mcc = 310,
			.mnc = 410,
			.area_code = 36879,
			.cell_id = 84486415
		}
	};
	struct nrf_cloud_rest_mcell_request mcell_req = {
		.device_id = CONFIG_REST_DEVICE_ID
	};
	struct nrf_cloud_rest_agps_request agps_req = {
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

	struct nrf_cloud_pgps_result pgps_result = {
		.host = pgps_host,
		.host_sz = sizeof(pgps_host),
		.path = pgps_path,
		.path_sz = sizeof(pgps_path)
	};

	struct gps_pgps_request pgps = {
		.gps_day = 15103,
		.prediction_count = 42,
		.prediction_period_min = 420,
		.gps_time_of_day = 0
	};

	struct nrf_cloud_rest_pgps_request pgps_request = {
		.device_id = CONFIG_REST_DEVICE_ID,
	};

	int err = init_modem_and_connect();

	if (err){
		return;
	}

	if (IS_ENABLED(CONFIG_REST_FOTA_ONLY)) {
		goto fota_start;
	}

	/* Exercise PGPS API */
	LOG_INF("\n********************* P-GPS API *********************");
	pgps_request.pgps_req = &pgps;
	err = nrf_cloud_rest_pgps_data_get(&rest_ctx, &pgps_request, &pgps_result);
	if (err) {
		LOG_ERR("PGPS request failed, error: %d", err);
	} else {
		LOG_INF("PGPS data host/path: %s/%s",
			log_strdup(pgps_result.host), log_strdup(pgps_result.path));
	}

	LOG_INF("\n********************* A-GPS API *********************");
	/* Exercise AGPS API */
	agps_req.net_info = &scell_req.net_info;
	agps_req.agps_req = &agps;
	/* When requesting a potentially large result, set fragment size to a
	 * small value (1) and do not provide a result buffer.
	 * This will allow you to obtain the necessary size while limiting
	 * data transfer.
	 */
	rest_ctx.fragment_size = 1;
	agps_sz = nrf_cloud_rest_agps_data_get(&rest_ctx, &agps_req, NULL);
	if (agps_sz < 0) {
		LOG_ERR("Failed to get AGPS data: %d", agps_sz);
		goto agps_done;
	} else if (agps_sz == 0) {
		LOG_WRN("AGPS data size is zero, skipping");
		goto agps_done;
	}

	LOG_INF("Additional buffer required to download AGPS data of %d bytes",
		agps_sz);

	agps_result.buf_sz = (uint32_t)agps_sz;
	agps_result.buf = k_calloc(agps_result.buf_sz, 1);
	if (!agps_result.buf) {
		LOG_ERR("Failed to allocate %u bytes for AGPS buffer", agps_result.buf_sz);
		goto agps_done;
	}
	/* Use the default configured fragment size */
	rest_ctx.fragment_size = 0;
	err = nrf_cloud_rest_agps_data_get(&rest_ctx, &agps_req, &agps_result);
	if (err) {
		LOG_ERR("Failed to get AGPS data: %d", err);
	} else {
		// TODO: send to modem?
	}

	k_free(agps_result.buf);
	agps_result.buf = NULL;

agps_done:
	LOG_INF("\n******************* Single-Cell API *******************");

	/* TODO: replace with existing ncellmeas handling */
	err = modem_get_neighboring_cell_data(&n_cell);
	if (err) {
		LOG_ERR("Failed to get neighboring cell data");
		n_cell.status = N_CELL_MEAS_N_STATUS_FAIL;
	}

	if (n_cell.status == N_CELL_MEAS_N_STATUS_FAIL) {
		LOG_WRN("Using dummy data for SCELL/MCELL location request");
		mcell_req.net_info = scell_req.net_info;
	} else {
		LOG_INF("CID: %d, TAC: %d, MNC: %d, MCC: %d, neighbors: %d",
			n_cell.cell_id,
			n_cell.area_code,
			n_cell.mnc,
			n_cell.mcc,
			n_cell.n_cnt);

		/* Single-cell request */
		scell_req.net_info.cell_id = n_cell.cell_id;
		scell_req.net_info.area_code = n_cell.area_code;
		scell_req.net_info.mnc = n_cell.mnc;
		scell_req.net_info.mcc = n_cell.mcc;

		/* TODO: when MCELL is available, use neighbor data */
		mcell_req.net_info = scell_req.net_info;
	}

	/* Exercise single-cell API */
	err = nrf_cloud_rest_scell_get(&rest_ctx, &scell_req, &location);
	if (err) {
		LOG_ERR("Single-Cell API call failed, error: %d", err);
	} else {
		LOG_INF("Single-Cell Response: %s", log_strdup(rest_ctx.response));
	}

	/* Exercise multi-cell API */
	LOG_INF("\n******************* Multi-Cell API *******************");
	err = nrf_cloud_rest_mcell_get(&rest_ctx, &mcell_req, &location);
	if (err) {
		LOG_ERR("Multi-Cell API call failed, error: %d", err);
	} else {
		LOG_INF("Multi-Cell Response: %s", log_strdup(rest_ctx.response));
	}

fota_start:
	LOG_INF("\n******************* FOTA API *******************");
	/* Use JWT for FOTA endpoints */
	err = modem_jwt_generate(&jwt);
	if (err) {
		LOG_ERR("Failed to generate JWT, err %d", err);
		goto cleanup;
	}
	LOG_DBG("JWT:\n%s", log_strdup(jwt.jwt_buf));

	/* JWT auth */
	rest_ctx.auth = jwt.jwt_buf;

	/* Exercise the FOTA API by checking for a job
	 * and if a job exists, mark it as cancelled.
	 */
	err = nrf_cloud_rest_fota_job_get(&rest_ctx, CONFIG_REST_DEVICE_ID, &job);
	if (err) {
		LOG_INF("Failed to fetch FOTA job, error: %d", err);
		goto cleanup;
	}

	if (job.type == NRF_CLOUD_FOTA_TYPE__INVALID) {
		LOG_INF("No pending FOTA job");
		goto cleanup;
	}

	LOG_INF("FOTA Job: %s, type: %d\n", log_strdup(job.id), job.type);

	/* Disconnect after next API call */
	rest_ctx.keep_alive = false;

	/* Cancel the job */
	err = nrf_cloud_rest_fota_job_update(&rest_ctx,
						CONFIG_REST_DEVICE_ID,
						job.id,
						NRF_CLOUD_FOTA_CANCELED);
	if (err) {
		LOG_ERR("Failed to update FOTA job, error: %d", err);
	} else {
		LOG_INF("FOTA job updated");
	}

cleanup:
	(void)nrf_cloud_rest_disconnect(&rest_ctx);
	modem_jwt_free(jwt.jwt_buf);
	nrf_cloud_rest_fota_job_free(&job);
}
