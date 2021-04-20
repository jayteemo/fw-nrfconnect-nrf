/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file modem_attest_token.h
 *
 * @brief Modem attestation token and parsing.
 *
 */
#ifndef MODEM_ATTEST_TOKEN_H__
#define MODEM_ATTEST_TOKEN_H__

#include <zephyr/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Base64url attestation and COSE strings */
struct nrf_attestation_token {
	char *attest;
	char *cose;
};

enum nrf_id_srvc_msg_type {
	NRF_ID_SRVC_MSG_TYPE_INVALID = -1,
	NRF_ID_SRVC_MSG_TYPE_ID_V1 = 1,
	NRF_ID_SRVC_MSG_TYPE_PROV_RESP_V1 = 5,
	NRF_ID_SRVC_MSG_TYPE_PUB_KEY_V2 = 8,
	NRF_ID_SRVC_MSG_TYPE_CSR_V2 = 9,
};

enum nrf_device_type {
	NRF_DEVICE_TYPE_INVALID = -1,
	NRF_DEVICE_TYPE_9160_SIAA = 1,
	NRF_DEVICE_TYPE_9160_SIBA = 2,
	NRF_DEVICE_TYPE_9160_SICA = 3,
};

#define NRF_DEVICE_UUID_SZ 16
#define NRF_FW_UUID_SZ 16
#define NRF_ATTEST_NONCE_SZ 16

#define NRF_DEVICE_UUID_STR_LEN (NRF_DEVICE_UUID_SZ * 2)

/** @brief Parsed attestation token data */
struct nrf_attestation_data {
	enum nrf_id_srvc_msg_type msg_type;
	enum nrf_device_type dev_type;

	char device_uuid[NRF_DEVICE_UUID_SZ];
	char fw_uuid[NRF_FW_UUID_SZ];
	char nonce[NRF_ATTEST_NONCE_SZ];
};

/** @brief Device UUID String (no hypens) */
struct nrf_device_uuid {
	char str[NRF_DEVICE_UUID_STR_LEN + 1];
};

/**
 * @brief Gets the device attestation token from the modem. If successful,
 * a pointer to the base64url attestation string and base64url COSE string
 * will be stored in the supplied struct.
 * The user is responsible for freeing the strings.
 *
 * @param[out] token Pointer to struct containing attestation token strings.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int modem_attest_token_get(struct nrf_attestation_token *const token);

/**
 * @brief Parses attestation token.
 *
 * @param[in] token_in Pointer to struct containing attestation token strings.
 * @param[out] data_out Pointer to struct containing parsed attestation data.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int modem_attest_token_parse(struct nrf_attestation_token const *const token_in,
			     struct nrf_attestation_data *const data_out);

/**
 * @brief Gets the device UUID from the modem and returns it as a
 * NULL-terminated string in the supplied struct.
 *
 * @param[out] uuid Pointer to struct containing UUID string.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int modem_attest_token_get_device_uuid(struct nrf_device_uuid *uuid);
/** @} */

#ifdef __cplusplus
}
#endif

#endif /* MODEM_ATTEST_TOKEN_H__ */
