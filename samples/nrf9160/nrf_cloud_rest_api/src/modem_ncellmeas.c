/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <string.h>
#include <zephyr.h>
#include <stdlib.h>
#include <stdio.h>
#include <modem/nrf_modem_lib.h>
#include <modem/at_cmd.h>
#include <cJSON.h>
#include <cJSON_os.h>
#include "modem_ncellmeas.h"

#define AT_CMD_N_CELL_MEAS	"AT%NCELLMEAS\r\n"
#define N_CELL_MEAS_DATA_NAME	"nCellMeasure"

#define ITEMS_PER_NEIGHBOR	5
#define N_CELL_MEAS_MIN_ITEMS	9
#define N_CELL_MEAS_MAX_ITEMS	(N_CELL_MEAS_MIN_ITEMS + \
				(ITEMS_PER_NEIGHBOR * MAX_N_CELLS))
#define N_CELL_MEAS_STATUS_IDX	0
#define N_CELL_MEAS_CID_IDX	1 // hex string
#define N_CELL_MEAS_MCCMNC_IDX	2 // hex string
#define N_CELL_MEAS_TAC_IDX	3 // hex string
#define N_CELL_MEAS_TIM_ADV_IDX	4
#define N_CELL_MEAS_EARFCN_IDX	5
#define N_CELL_MEAS_PHYCID_IDX  6
#define N_CELL_MEAS_RSRP_IDX  7
#define N_CELL_MEAS_RSRQ_IDX  8
#define N_CELL_MEAS_N_EARFCN_IDX 9
#define N_CELL_MEAS_N_PHYCID_IDX 10
#define N_CELL_MEAS_N_RSRP_IDX 11
#define N_CELL_MEAS_N_RSRQ_IDX 12
#define N_CELL_MEAS_N_TDIFF_IDX 13

#define CELL_ID_HEX_STR_LEN	8
#define TAC_HEX_STR_LEN		4
#define MCCMNC_STR_LEN		6
#define MCC_STR_LEN		3

#define N_CELL_MEAS_CMD_RSP_MAX_SZ	1024

static int parse_n_cell_meas_json(cJSON * const obj, struct n_cell_measure_result * const result)
{
	__ASSERT_NO_MSG(obj);
	__ASSERT_NO_MSG(result);

	int item_cnt;
	char buff[MCC_STR_LEN + 1];
	cJSON * item;

	if (!cJSON_IsArray(obj)) {
		return -ENOSTR;
	}

	/* Verify item count */
	item_cnt = cJSON_GetArraySize(obj);
	if (item_cnt == (N_CELL_MEAS_MIN_ITEMS + 1)) {
		/* ??? There is a trailing zero if no neigbors ??? */
		result->n_cnt = 0;
	} else if (item_cnt < N_CELL_MEAS_MIN_ITEMS || item_cnt > N_CELL_MEAS_MAX_ITEMS ||
		   (((item_cnt - N_CELL_MEAS_MIN_ITEMS) % ITEMS_PER_NEIGHBOR) != 0)) {
		return -ECHILD;
	} else {
		result->n_cnt = ((item_cnt - N_CELL_MEAS_MIN_ITEMS) /
				ITEMS_PER_NEIGHBOR);
	}

	/* Get status of n cell measure cmd */
	item = cJSON_GetArrayItem(obj, N_CELL_MEAS_STATUS_IDX);
	if (!item || !cJSON_IsNumber(item)) {
		return -ENOEXEC;
	}
	result->status = item->valueint;
	if (result->status == N_CELL_MEAS_N_STATUS_FAIL) {
		/* Nothing more to process */
		return 0;
	}

	/* Get Cell ID hex string and convert to int */
	item = cJSON_GetArrayItem(obj, N_CELL_MEAS_CID_IDX);
	if (!item || !cJSON_IsString(item) ||
	    strlen(item->valuestring) > CELL_ID_HEX_STR_LEN) {
		return -ENOEXEC;
	}
	result->cell_id = (uint32_t)strtol(item->valuestring, NULL, 16);

	/* Get 3 digit MCC and 2-3 digit MNC string and convert to int  */
	item = cJSON_GetArrayItem(obj, N_CELL_MEAS_MCCMNC_IDX);
	if (!item || !cJSON_IsString(item) ||
	    strlen(item->valuestring) > MCCMNC_STR_LEN) {
		return -ENOEXEC;
	}
	memcpy(buff, item->valuestring, MCC_STR_LEN);
	buff[MCC_STR_LEN] = '\0';
	result->mcc = strtol(buff, NULL, 10);
	result->mnc = strtol(&item->valuestring[MCC_STR_LEN], NULL, 10);

	/* Get TAC hex string and convert to int */
	item = cJSON_GetArrayItem(obj, N_CELL_MEAS_TAC_IDX);
	if (!item || !cJSON_IsString(item) ||
	    strlen(item->valuestring) > TAC_HEX_STR_LEN) {
		return -ENOEXEC;
	}
	result->area_code = (uint16_t)strtol(item->valuestring, NULL, 16);

	/* Get timing advance */
	item = cJSON_GetArrayItem(obj, N_CELL_MEAS_TIM_ADV_IDX);
	if (!item || !cJSON_IsNumber(item)) {
		return -ENOEXEC;
	}
	result->timing_adv = (uint16_t)item->valueint;

	/* Get EARFN */
	item = cJSON_GetArrayItem(obj, N_CELL_MEAS_EARFCN_IDX);
	if (!item || !cJSON_IsNumber(item)) {
		return -ENOEXEC;
	}
	result->cur_data.earfcn = (uint32_t)item->valueint;

	/* Get physical cell ID */
	item = cJSON_GetArrayItem(obj, N_CELL_MEAS_PHYCID_IDX);
	if (!item || !cJSON_IsNumber(item)) {
		return -ENOEXEC;
	}
	result->cur_data.phy_cell_id = (uint32_t)item->valueint;

	/* Get RSRP */
	item = cJSON_GetArrayItem(obj, N_CELL_MEAS_RSRP_IDX);
	if (!item || !cJSON_IsNumber(item)) {
		return -ENOEXEC;
	}
	result->cur_data.rsrp = (int8_t)item->valueint;

	/* Get RSRQ */
	item = cJSON_GetArrayItem(obj, N_CELL_MEAS_RSRQ_IDX);
	if (!item || !cJSON_IsNumber(item)) {
		return -ENOEXEC;
	}
	result->cur_data.rsrq = (int8_t)item->valueint;

	/* Get all neighbor data */
	for (uint8_t cnt = 0; cnt < result->n_cnt; ++cnt) {
		int idx = N_CELL_MEAS_MIN_ITEMS + (cnt * ITEMS_PER_NEIGHBOR);

		/* Neighbor data is in the following order:
		 * EARFN, Physical cell id, RSRP, RSRQ, Time diff
		 */
		item = cJSON_GetArrayItem(obj, idx++);
		if (!item || !cJSON_IsNumber(item)) {
			return -ENOEXEC;
		}
		result->nghbr[cnt].data.earfcn = (uint32_t)item->valueint;

		item = cJSON_GetArrayItem(obj, idx++);
		if (!item || !cJSON_IsNumber(item)) {
			return -ENOEXEC;
		}
		result->nghbr[cnt].data.phy_cell_id = (uint32_t)item->valueint;

		item = cJSON_GetArrayItem(obj, idx++);
		if (!item || !cJSON_IsNumber(item)) {
			return -ENOEXEC;
		}
		result->nghbr[cnt].data.rsrp = (int8_t)item->valueint;

		item = cJSON_GetArrayItem(obj, idx++);
		if (!item || !cJSON_IsNumber(item)) {
			return -ENOEXEC;
		}
		result->nghbr[cnt].data.rsrq = (int8_t)item->valueint;

		item = cJSON_GetArrayItem(obj, idx);
		if (!item || !cJSON_IsNumber(item)) {
			return -ENOEXEC;
		}
		result->nghbr[cnt].time_diff_ms = (uint32_t)item->valueint;
	}

	return 0;
}

int modem_get_neighboring_cell_data(struct n_cell_measure_result * const result)
{
	if (!result) {
		return -EINVAL;
	}

	int ret = 0;
	enum at_cmd_state state;
	cJSON * result_obj = NULL;
	char * cmd_resp = NULL;
	char * json_start;
	char * json_end;

	ret = at_cmd_init();
	if (ret) {
		return -EPIPE;
	}

	/* Allocate response buffer and send cmd */
	cmd_resp = k_calloc(N_CELL_MEAS_CMD_RSP_MAX_SZ, 1);
	if (!cmd_resp) {
		ret = -ENOMEM;
		goto cleanup;
	}

	ret = at_cmd_write(AT_CMD_N_CELL_MEAS, cmd_resp,
			   N_CELL_MEAS_CMD_RSP_MAX_SZ, &state);
	if (ret) {
		ret = -EBADMSG;
		goto cleanup;
	}

	json_start = strchr(cmd_resp,' ');
	if (!json_start) {
		ret = -ENOMSG;
		goto cleanup;
	}

	json_end = strchr(json_start,'\r');
	if (!json_end) {
		ret = -ENOMSG;
		goto cleanup;
	}

	/* Reformat into JSON array */
	*json_start = '[';
	*json_end = ']';
	*(json_end + 1) = '\0';

	cJSON_Init();
	result_obj = cJSON_Parse(json_start);
	if (!result_obj) {
		ret = -ENOMSG;
		goto cleanup;
	}

	ret = parse_n_cell_meas_json(result_obj, result);

cleanup:

	if (cmd_resp) {
		k_free(cmd_resp);
	}

	if (result_obj) {
		cJSON_Delete(result_obj);
	}

	return ret;
}