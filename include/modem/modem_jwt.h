/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

/**
 * @file modem_jwt.h
 *
 * @brief Request a JWT from the modem.
 *
 */
#ifndef MODEM_JWT_H__
#define MODEM_JWT_H__

#include <zephyr/types.h>

#ifdef __cplusplus
extern "C" {
#endif

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
	/** Modem sec tag to use for JWT generation */
	int sec_tag;
	/** Key type in the specified sec tag */
	enum jwt_key_type key;
	/** JWT signing algorithm */
	enum jwt_alg_type alg;

	/** Defines how long the JWT will be valid; in seconds (from generation) */
	size_t exp_delta_s;

	/**  NULL terminated 'sub' claim; the principal that is the subject of the JWT */
	char *subject;
	/**  NULL terminated 'aud' claim; intended recipient of the JWT */
	char *audience;

	/** NULL terminated JWT; user must free memory when finished */
	char *jwt_out;
};

/**
 * @brief Generates a JWT using the supplied parameters. If successful,
 * a pointer to the JWT string will be stored in the supplied struct.
 * The user is responsible for freeing the JWT string.
 *
 * @param[in,out] jwt Pointer to struct containing JWT parameters and result.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int modem_jwt_generate(struct jwt_data *const jwt);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* MODEM_JWT_H__ */
