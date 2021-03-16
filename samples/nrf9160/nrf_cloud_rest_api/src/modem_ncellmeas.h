/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file modem_ncellmeas.h
 *
 * @brief Execute and process the command AT%NCELLMEAS
 *
 */
#ifndef MODEM_NCELLMEAS_H__
#define MODEM_NCELLMEAS_H__

#include <zephyr/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_N_CELLS 17
#define N_CELL_MEAS_N_STATUS_PASS 0
#define N_CELL_MEAS_N_STATUS_FAIL 1

struct cell_data {
	uint32_t earfcn;
	uint32_t phy_cell_id;
	int8_t rsrp;
	int8_t rsrq;
};

struct neighbor_data {
	struct cell_data data;
	uint32_t time_diff_ms;
};

/** @brief Neighboring cell mesurement results */
struct n_cell_measure_result {
	/** Status result of command */
	uint8_t status;
	/** Connected cell information */
	uint32_t cell_id;
	uint16_t mcc;
	uint16_t mnc;
	uint16_t area_code;
	uint16_t timing_adv;
	struct cell_data cur_data;
	/** Number of neighbors in n_cell_data */
	uint8_t n_cnt;
	/** Neighbor cell information */
	struct neighbor_data nghbr[MAX_N_CELLS];
};

/**
 * @brief Executes the NCELLMEAS AT command and parses the result into the
 *        provided structure.
 *
 * @param[out] result Results from NCELLMEAS AT command.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int modem_get_neighboring_cell_data(struct n_cell_measure_result * const result);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* MODEM_NCELLMEAS_H__ */
