/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef MODEM_JWT_H__
#define MODEM_JWT_H__

#include <zephyr/types.h>
#include <modem/modem_attest_token.h>
#include <net/nrf_jwt.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file modem_jwt.h
 *
 * @brief Request a JWT from the modem.
 * @defgroup modem_jwt JWT generation
 * @{
 *
 */

/**
 * @brief Generates a JWT using the supplied parameters. If successful,
 * the JWT string will be stored in the supplied struct.
 * This function will allocate memory for the JWT if the user does not
 * provide a buffer.  In that case, the user is responsible for freeing
 * the memory by calling @ref modem_jwt_free.
 *
 * Subject and audience fields may be NULL in which case those fields are left out
 * from generated JWT token.
 *
 * If sec_tag value is given as zero, JWT is signed with Nordic's own keys that
 * already exist in the modem.
 *
 * @param[in,out] jwt Pointer to struct containing JWT parameters and result.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int modem_jwt_generate(struct jwt_data *const jwt);

/**
 * @brief Gets the device and/or modem firmware UUID from the modem
 * and returns it as a NULL terminated string in the supplied struct(s).
 *
 * Uses internally @ref modem_jwt_generate and parses JWT token for "iss"
 * "jti" fields which contains given UUID values.
 *
 * @param[out] dev Pointer to struct containing device UUID string.
 *                 Can be NULL if UUID is not wanted.
 * @param[out] mfw Pointer to struct containing modem fw UUID string.
 *                 Can be NULL if UUID is not wanted.
 *
 * @retval 0 If the operation was successful.
 *           Otherwise, a (negative) error code is returned.
 */
int modem_jwt_get_uuids(struct nrf_device_uuid *dev,
			struct nrf_modem_fw_uuid *mfw);

/**
 * @brief Frees the JWT buffer allocated by @ref modem_jwt_generate.
 *
 * @param[in] jwt_buf Pointer to JWT buffer; see #jwt_data.
 */
void modem_jwt_free(char *const jwt_buf);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* MODEM_JWT_H__ */
