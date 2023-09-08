/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#ifndef NRF_JWT_H__
#define NRF_JWT_H__

#include <zephyr/types.h>
#include <psa/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/**@brief Source of the signing key */
enum nrf_jwt_key_src {
	NRF_JWT_KEY_SRC_MODEM,
	NRF_JWT_KEY_SRC_PSA,
	NRF_JWT_KEY_SRC_DER
};

#define NRF_JWT_KEY_DER_SZ 32

/**@brief The type of key to be used for signing the JWT. */
enum jwt_key_type {
	JWT_KEY_TYPE_CLIENT_PRIV = 2,
	JWT_KEY_TYPE_ENDORSEMENT = 8,
};

/**@brief JWT signing algorithm */
enum jwt_alg_type {
	JWT_ALG_TYPE_ES256 = 0,
};

/** @brief JWT parameters required for JWT generation and pointer to generated JWT */
struct jwt_data {
	enum nrf_jwt_key_src key_src;

	/** For NRF_JWT_KEY_SRC_PSA types: PSA key handle of JWT signing key */
	psa_key_handle_t signing_key_h;

	/** For NRF_JWT_KEY_SRC_DER types: Raw private key.
	 * Provide a buffer of size NRF_JWT_KEY_DER_SZ
	 */
	char *der;

	/** For NRF_JWT_KEY_SRC_MODEM types: Modem sec tag to use for JWT signing */
	unsigned int sec_tag;
	/** For NRF_JWT_KEY_SRC_MODEM types: Key type in the specified sec tag */
	enum jwt_key_type key;

	/** JWT signing algorithm */
	enum jwt_alg_type alg;

	/** JWT expiration time/date; epoch seconds. If 0, 'exp' claim is
	 * controlled by the exp_delta_s value.
	 * Not used for NRF_JWT_KEY_SRC_MODEM types.
	 */
	int64_t exp_time_s;

	/** Defines how long the JWT will be valid; in seconds (from generation).
	 * For NRF_JWT_KEY_SRC_MODEM types, The 'iat' and 'exp' claims will be
	 * populated only if the modem has a valid date and time.
	 * For other types, this value is used only if exp_time_s is 0,
	 * and requires DATE_TIME to be enabled and have a valid time.
	 */
	uint32_t exp_delta_s;

	/**  NULL terminated 'sub' claim; the principal that is the subject of the JWT */
	const char *subject;
	/**  NULL terminated 'aud' claim; intended recipient of the JWT */
	const char *audience;

	/** Buffer to which the NULL terminated JWT will be copied.
	 * If a buffer is provided by the user, the size must also be set.
	 * If buffer is NULL, memory will be allocated and user must free memory
	 * when finished by calling @ref nrf_jwt_free.
	 */
	char *jwt_buf;
	/** Size of the user provided buffer or size of the allocated buffer */
	size_t jwt_sz;
};

int nrf_jwt_generate(struct jwt_data *const jwt);

/**
 * @brief Frees the JWT buffer.
 *
 * @param[in] jwt_buf Pointer to JWT struct containing allocated JWT buffer.
 */
void nrf_jwt_free(struct jwt_data *const jwt);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* MODEM_JWT_H__ */
