/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr.h>
#include <device.h>
#include <net/socket.h>
#include <nrf_socket.h>

#include <cJSON.h>
#include <cJSON_os.h>
#include <net/nrf_cloud_cell_pos.h>

#include <logging/log.h>

LOG_MODULE_REGISTER(nrf_cloud_cell_pos, CONFIG_NRF_CLOUD_LOG_LEVEL);

#include "nrf_cloud_codec.h"

#if defined(CONFIG_NRF_CLOUD_MQTT)
#include "nrf_cloud_transport.h"

#define CELL_POS_JSON_CELL_LOC_KEY_DOREPLY	"doReply"

int nrf_cloud_cell_pos_request(enum nrf_cloud_cell_pos_type type, const bool request_loc)
{
	int err;
	cJSON *data_obj;
	cJSON *cell_pos_req_obj;

	/* TODO: currently single cell only */
	ARG_UNUSED(type);
	cell_pos_req_obj = json_create_req_obj(NRF_CLOUD_JSON_APPID_VAL_SINGLE_CELL,
					       NRF_CLOUD_JSON_MSG_TYPE_VAL_DATA);
	data_obj = cJSON_AddObjectToObject(cell_pos_req_obj, NRF_CLOUD_JSON_DATA_KEY);

	if (!cell_pos_req_obj || !data_obj) {
		err = -ENOMEM;
		goto cleanup;
	}

	/* Add modem info to the data object */
	err = nrf_cloud_json_add_modem_info(data_obj);
	if (err) {
		LOG_ERR("Failed to add modem info to cell loc req: %d", err);
		goto cleanup;
	}

	/* By default, nRF Cloud will send the location to the device */
	if (!request_loc) {
		/* Specify that location should not be sent to the device */
		cJSON_AddNumberToObject(data_obj, CELL_POS_JSON_CELL_LOC_KEY_DOREPLY, 0);
	}

	err = json_send_to_cloud(cell_pos_req_obj);

cleanup:
	cJSON_Delete(cell_pos_req_obj);

	return err;
}
#endif /* #if defined(CONFIG_NRF_CLOUD_MQTT) */

int nrf_cloud_cell_pos_process(const char *buf, struct nrf_cloud_cell_pos_result *result)
{
	int err;

	if (!result) {
		return -EINVAL;
	}

	err = nrf_cloud_parse_cell_pos_response(buf, result);
	if (err < 0) {
		LOG_ERR("Error processing cell-based location: %d", err);
	}

	return err;
}
