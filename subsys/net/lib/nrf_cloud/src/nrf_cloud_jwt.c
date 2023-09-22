/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <net/nrf_cloud.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <modem/modem_jwt.h>
#if defined(CONFIG_NRF_MODEM_LIB)
#include <nrf_modem_at.h>
#endif
#include <string.h>
#include <net/nrf_jwt.h>
#include <zephyr/sys/base64.h>
#include <psa/crypto.h>

/* For testing */
#define READ_FROM_INC_FILE 0
#if READ_FROM_INC_FILE
#include CONFIG_NRF_CLOUD_CERTIFICATES_FILE
#endif

#define GET_TIME_CMD "AT%%CCLK?"

LOG_MODULE_REGISTER(nrf_cloud_jwt, CONFIG_NRF_CLOUD_LOG_LEVEL);

#define PRV_KEY_SZ (NRF_JWT_KEY_DER_SZ)
#define PRV_KEY_DER_SZ (138)
#define PRV_KEY_PEM_SZ (256)
#define PRV_KEY_DER_START_IDX (36)

#if defined(CONFIG_NRF_CLOUD_JWT_GEN_METHOD_PSA)
#define JWT_KEY_ID CONFIG_NRF_CLOUD_JWT_PSA_KEY_ID
#else
#define JWT_KEY_ID PSA_KEY_ID_NULL
#endif

static void remove_newlines(char *const str)
{
	size_t new;
	size_t len = strlen(str);

	for (size_t old = new = 0; old < len; ++old) {
		if (str[old] != '\n') {
			str[new++] = str[old];
		}
	}

	str[new] = '\0';
}

#define BEGIN_PRV_KEY "-----BEGIN PRIVATE KEY-----"
#define END_PRV_KEY "-----END PRIVATE KEY-----"
static int strip_non_key_data(char *const str)
{
	char *start;
	char *end;
	size_t new_len;

	/* Find and remove end string */
	end = strstr(str, END_PRV_KEY);
	if (end == NULL) {
		return -EINVAL;
	}
	*end = '\0';

	/* Find and remove begin string */
	start = strstr(str, BEGIN_PRV_KEY);
	if (start == NULL) {
		return -EINVAL;
	}

	start += strlen(BEGIN_PRV_KEY);
	new_len = strlen(start);

	/* Move key data to the front */
	memmove(str, start, new_len);
	str[new_len] = '\0';

	remove_newlines(str);

	return 0;
}

static int open_key(psa_key_id_t key_id, psa_key_handle_t *const key_h_out)
{
#if defined(CONFIG_NRF_CLOUD_JWT_GEN_METHOD_PSA)
	int ret = psa_crypto_init();

	if (ret != PSA_SUCCESS) {
		LOG_ERR("psa_crypto_init() failed, error: %d", ret);
		return -EIO;
	}

	ret = psa_open_key(key_id, key_h_out);

	if (ret != PSA_SUCCESS) {
		LOG_ERR("psa_open_key() failed, error: %d", ret);
		return -EACCES;
	}

	return 0;
#else
	return -ENOTSUP;
#endif
}

static int get_key_from_cred(struct jwt_data *const jwt)
{
	static char pem[PRV_KEY_PEM_SZ];
	static char der[PRV_KEY_DER_SZ];
	size_t pem_sz = sizeof(pem);
	size_t der_sz;
	int err;

#if READ_FROM_INC_FILE
	/* If the file is included here, just read it */
	pem_sz = strlen(private_key) + 1;

	if (pem_sz > PRV_KEY_PEM_SZ) {
		return -EMSGSIZE;
	}
	memcpy(pem, private_key, pem_sz);
#else
	/* Get the private key from protected storage */
	err = tls_credential_get(jwt->sec_tag, TLS_CREDENTIAL_PRIVATE_KEY,
				 pem, &pem_sz);
	if (err) {
		LOG_ERR("tls_credential_get() failed, error: %d", err);
		return err;
	}
#endif

	err = strip_non_key_data(pem);
	if (err) {
		LOG_ERR("Failed to parse PEM file, error: %d", err);
		return err;
	}

	LOG_DBG("PEM:\n%s", pem);
	pem_sz = strlen(pem);

	/* Convert the PEM to DER (binary) */
	err = base64_decode(der, sizeof(der), &der_sz, pem, pem_sz);
	if (err) {
		LOG_ERR("base64_decode() failed, error: %d", err);
		return -EBADF;
	}

	LOG_DBG("DER size = %u", der_sz);

	/* TODO: hack, not actually parsing the ASN.1... expecting the key data to look like this */
	if (((der[0] == 0x30) && (der[1] == 0x81) && (der[2] == 0x87)) == false) {
		LOG_ERR("Unexpected DER format: 0x%X 0x%X 0x%X", der[0], der[1], der[2]);
		return -EBADF;
	}

	/* Grab the private key bytes */
	memcpy((void*)jwt->der, (void*)&der[PRV_KEY_DER_START_IDX], NRF_JWT_KEY_DER_SZ);

	return 0;
}

int nrf_cloud_jwt_generate(uint32_t time_valid_s, char *const jwt_buf, size_t jwt_buf_sz)
{
	if (!jwt_buf || !jwt_buf_sz) {
		return -EINVAL;
	}

	int err;
	char buf[NRF_CLOUD_CLIENT_ID_MAX_LEN + 1];
	char der_buf[PRV_KEY_SZ];
	struct jwt_data jwt = {
		.audience = NULL,
#if defined(CONFIG_NRF_CLOUD_COAP)
		.sec_tag = CONFIG_NRF_CLOUD_COAP_SEC_TAG,
#else
		.sec_tag = CONFIG_NRF_CLOUD_SEC_TAG,
#endif
		.key = JWT_KEY_TYPE_CLIENT_PRIV,

		.alg = JWT_ALG_TYPE_ES256,
		.jwt_buf = jwt_buf,
		.jwt_sz = jwt_buf_sz,
		.der = NULL,
		.signing_key_h = PSA_KEY_ID_NULL
	};

	if (IS_ENABLED(CONFIG_NRF_CLOUD_JWT_GEN_METHOD_MODEM)) {
		jwt.key_src = NRF_JWT_KEY_SRC_MODEM;
		jwt.key = JWT_KEY_TYPE_CLIENT_PRIV;
#if defined(CONFIG_NRF_MODEM_LIB)
		/* Check if modem time is valid */
		err = nrf_modem_at_cmd(buf, sizeof(buf), GET_TIME_CMD);
		if (err != 0) {
			LOG_ERR("Modem does not have valid date/time, JWT not generated");
			return -ETIME;
		}
#endif
	} else if (IS_ENABLED(CONFIG_NRF_CLOUD_JWT_GEN_METHOD_PSA)) {
		jwt.key_src = NRF_JWT_KEY_SRC_PSA;
		err = open_key(JWT_KEY_ID, &jwt.signing_key_h);
		if (err) {
			return -ESPIPE;
		}
	} else if (IS_ENABLED(CONFIG_NRF_CLOUD_JWT_GEN_METHOD_DER)) {
		jwt.key_src = NRF_JWT_KEY_SRC_DER;
		jwt.der = der_buf;
		err = get_key_from_cred(&jwt);
		if (err) {
			return -ESPIPE;
		}
	} else {
		LOG_ERR("Unknown NRF_CLOUD_JWT_GEN_METHOD Kconfig choice");
		return -ENXIO;
	}

	if (time_valid_s > NRF_CLOUD_JWT_VALID_TIME_S_MAX) {
		jwt.exp_delta_s = NRF_CLOUD_JWT_VALID_TIME_S_MAX;
	} else if (time_valid_s == 0) {
		jwt.exp_delta_s = NRF_CLOUD_JWT_VALID_TIME_S_DEF;
	} else {
		jwt.exp_delta_s = time_valid_s;
	}

	if (IS_ENABLED(CONFIG_NRF_CLOUD_CLIENT_ID_SRC_INTERNAL_UUID)) {
		/* The UUID is present in the iss claim, so there is no need
		 * to also include it in the sub claim.
		 */
		jwt.subject = NULL;
	} else {
		err = nrf_cloud_client_id_get(buf, sizeof(buf));
		if (err) {
			LOG_ERR("Failed to obtain client id, error: %d", err);
			return err;
		}
		jwt.subject = buf;
	}

	err = nrf_jwt_generate(&jwt);
	if (err) {
		LOG_ERR("Failed to generate JWT, error: %d", err);
	}

	if (jwt.key_src == NRF_JWT_KEY_SRC_PSA) {
		psa_status_t status = psa_destroy_key(jwt.signing_key_h);
		if (status != PSA_SUCCESS) {
			LOG_ERR("psa_destroy_key() failed, error: %d", status);
		}
	}
	return err;
}
