/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <cJSON.h>
#include <date_time.h>
#include <net/nrf_jwt.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/base64.h>
#include <zephyr/logging/log.h>

#include <tinycrypt/ctr_prng.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/ecc_dsa.h>
#include <tinycrypt/constants.h>
#include <zephyr/random/rand32.h>

#include <psa/crypto_extra.h>

LOG_MODULE_REGISTER(nrf_jwt, CONFIG_NRF_JWT_LOG_LEVEL);

#define ECDSA_SHA_256_SIG_SZ 	(64)
#define ECDSA_SHA_256_HASH_SZ	(32)
#define BASE64_ENCODE_SZ(n) 	(((4 * n / 3) + 3) & ~3)
#define B64_SIG_SZ 		(BASE64_ENCODE_SZ(ECDSA_SHA_256_SIG_SZ) + 1)

static void base64_url_format(char *const base64_string)
{
	if (base64_string == NULL) {
		return;
	}

	char *found = NULL;

	/* replace '+' with "-" */
	for (found = base64_string; (found = strchr(found, '+'));) {
		*found = '-';
	}

	/* replace '/' with "_" */
	for (found = base64_string; (found = strchr(found, '/'));) {
		*found = '_';
	}

	/* remove padding '=' */
	found = strchr(base64_string, '=');
	if (found) {
		*found = '\0';
	}
}

#if defined(CONFIG_NRF_JWT_DER)
static TCCtrPrng_t prng_state;

static int setup_prng(void)
{
	static bool prng_init;
	uint8_t entropy[TC_AES_KEY_SIZE + TC_AES_BLOCK_SIZE];

	if (prng_init) {
		return 0;
	}

	for (int i = 0; i < sizeof(entropy); i += sizeof(uint32_t)) {
		uint32_t rv = sys_rand32_get();

		memcpy(entropy + i, &rv, sizeof(uint32_t));
	}

	int res = tc_ctr_prng_init(&prng_state,
				   (const uint8_t *)&entropy, sizeof(entropy),
				   __FILE__, sizeof(__FILE__));

	if (res != TC_CRYPTO_SUCCESS) {
		LOG_ERR("tc_ctr_prng_init() failed, error: %d", res);
		return -EINVAL;
	}

	prng_init = true;

	return 0;
}

int default_CSPRNG(uint8_t *dest, unsigned int size)
{
	return tc_ctr_prng_generate(&prng_state, NULL, 0, dest, size);
}
#endif

static int sign_message_der(const char *der_key, char * msg_in, char *const sig_out)
{
#if defined(CONFIG_NRF_JWT_DER)
	struct tc_sha256_state_struct ctx;
	uint8_t hash[ECDSA_SHA_256_HASH_SZ];
	int res;

	tc_sha256_init(&ctx);
	tc_sha256_update(&ctx, msg_in, strlen(msg_in));
	tc_sha256_final(hash, &ctx);

	res = setup_prng();
	if (res != 0) {
		LOG_ERR("uECC_sign() failed, error: %d", res);
		return res;
	}

	LOG_HEXDUMP_DBG(hash, sizeof(hash), "SHA256 hash: ");

	uECC_set_rng(&default_CSPRNG);

	/* Note that tinycrypt only supports P-256. */
	res = uECC_sign(der_key, hash, sizeof(hash), sig_out, &curve_secp256r1);
	if (res != TC_CRYPTO_SUCCESS) {
		LOG_ERR("uECC_sign() failed, error: %d", res);
		return -EINVAL;
	}

	return 0;
#else
	return -ENOTSUP;
#endif
}

static int sign_message_psa(psa_key_handle_t key, char * msg, char *const sig, size_t sig_sz)
{
#if defined(CONFIG_NRF_JWT_PSA)
	if (!key || !msg) {
		return -EINVAL;
	}

	static uint8_t hash[ECDSA_SHA_256_HASH_SZ];

	size_t output_len;
	psa_status_t status;

	memset(hash, 0, sizeof(hash));

	/* Compute the SHA256 hash*/
	status = psa_hash_compute(PSA_ALG_SHA_256,
				  msg,
				  strlen(msg),
				  hash,
				  sizeof(hash),
				  &output_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_hash_compute failed! (Error: %d)", status);
		return -EBADF;
	}

	LOG_HEXDUMP_DBG(hash, sizeof(hash), "SHA256 hash: ");

	/* Sign the hash */
	status = psa_sign_hash(key,
			       PSA_ALG_ECDSA(PSA_ALG_SHA_256),
			       hash,
			       sizeof(hash),
			       sig,
			       sig_sz,
			       &output_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_sign_hash failed! (Error: %d)", status);
		return -EIO;
	}

	return 0;
#else
	return -ENOTSUP;
#endif
}

static int jwt_generate(struct jwt_data *const jwt)
{
	int err = 0;
	int ret = 0;
	size_t len = 0;

	char *hdr_str = NULL;
	char *pay_str = NULL;
	char *b64_hdr = NULL;
	char *b64_pay = NULL;

	size_t hdr_len;
	size_t pay_len;
	size_t b64_hdr_sz;
	size_t b64_pay_sz;
	size_t jwt_sz;

	cJSON *jwt_hdr = cJSON_CreateObject();
	cJSON *jwt_pay = cJSON_CreateObject();

	if (!jwt_hdr || !jwt_pay) {
		return -ENOMEM;
	}

	/* Build the JWT header */
	cJSON_AddStringToObjectCS(jwt_hdr, "typ", "JWT");
	if (jwt->alg == JWT_ALG_TYPE_ES256) {
		if (cJSON_AddStringToObjectCS(jwt_hdr, "alg", "ES256") == NULL) {
			err = -ENOMEM;
		}
	} else {
		LOG_ERR("Invalid JWT alg type: %d", jwt->alg);
		err = -EPROTO;
	}

	/* Build the JWT payload */
	if (jwt->subject && (cJSON_AddStringToObjectCS(jwt_pay, "sub", jwt->subject) == NULL)) {
		err = -ENOMEM;
	}

	if (jwt->audience && (cJSON_AddStringToObjectCS(jwt_pay, "aud", jwt->audience) == NULL)) {
		err = -ENOMEM;
	}

	if (jwt->exp_time_s > 0) {
		if (cJSON_AddNumberToObjectCS(jwt_pay, "exp", jwt->exp_time_s) == NULL) {
			err = -ENOMEM;
		}
	} else if (jwt->exp_delta_s > 0) {
#if defined(CONFIG_DATE_TIME)
		int64_t ts;

		err = date_time_now(&ts);
		if (!err) {
			if (cJSON_AddNumberToObjectCS(jwt_pay, "exp",
						      ts + jwt->exp_delta_s) == NULL) {
				err = -ENOMEM;
			}
		} else {
			LOG_ERR("date_time_now() failed, error: %d", err);
			err = -ETIME;
		}
#else
	LOG_ERR("CONFIG_DATE_TIME is not enabled, cannot calculate JWT expiration");
	err = -ENOTSUP;
#endif
	}

	if (!err) {
		hdr_str = cJSON_PrintUnformatted(jwt_hdr);
		pay_str = cJSON_PrintUnformatted(jwt_pay);
		if (!hdr_str || !pay_str) {
			err = -ENOMEM;
		}
	}

	cJSON_Delete(jwt_pay);
	jwt_pay = NULL;
	cJSON_Delete(jwt_hdr);
	jwt_hdr = NULL;

	if (err) {
		cJSON_free(hdr_str);
		cJSON_free(pay_str);
		return err;
	}

	hdr_len = strlen(hdr_str);
	pay_len = strlen(pay_str);

	b64_hdr_sz = BASE64_ENCODE_SZ(hdr_len) + 1;
	b64_pay_sz = BASE64_ENCODE_SZ(pay_len) + 1;

	b64_hdr = k_calloc(1, b64_hdr_sz);
	b64_pay = k_calloc(1, b64_pay_sz);

	if (b64_hdr && b64_pay) {
		/* Convert to base64 */
		err = base64_encode(b64_pay, b64_pay_sz, &b64_pay_sz, pay_str, pay_len);
		if (!err) {
			err = base64_encode(b64_hdr, b64_hdr_sz, &b64_hdr_sz, hdr_str, hdr_len);
		}

		if (err) {
			LOG_ERR("base64_encode failed, error: %d", err);
			err = -EIO;
		}
	} else {
		err = -ENOMEM;
	}

	cJSON_free(hdr_str);
	hdr_str = NULL;
	cJSON_free(pay_str);
	pay_str = NULL;

	if (err) {
		k_free(b64_hdr);
		k_free(b64_pay);
		return err;
	}

	/* Convert to base64 URL */
	base64_url_format(b64_hdr);
	base64_url_format(b64_pay);

	/* Allocate buffer for the JWT header and payload to be signed */
	size_t msg_to_sign_sz = strlen(b64_hdr) + 1 + strlen(b64_pay) + 1;
	char *msg_to_sign = k_calloc(1, msg_to_sign_sz);

	/* Build the base64 URL JWT to sign:
	 * <base64_header>.<base64_payload>
	 */
	if (msg_to_sign) {
		ret = snprintk(msg_to_sign, msg_to_sign_sz, "%s.%s", b64_hdr, b64_pay);
		if ((ret < 0) || (ret >= msg_to_sign_sz)) {
			err = -ETXTBSY;
		}
	} else {
		err = -ENOMEM;
	}

	k_free(b64_hdr);
	b64_hdr = NULL;
	k_free(b64_pay);
	b64_pay = NULL;

	if (err) {
		k_free(msg_to_sign);
		return err;
	}

	uint8_t sig[ECDSA_SHA_256_SIG_SZ];
	uint8_t b64_sig[B64_SIG_SZ];

	LOG_DBG("Message to sign: %s", msg_to_sign);
	/* Perform signing */
	if (jwt->key_src == NRF_JWT_KEY_SRC_DER) {
		err = sign_message_der(jwt->der, msg_to_sign, sig);

	} else if (jwt->key_src == NRF_JWT_KEY_SRC_PSA) {
		err = sign_message_psa(jwt->signing_key_h, msg_to_sign, sig, sizeof(sig));
	} else {
		LOG_ERR("Unhandled JWT key source: %d", jwt->key_src);
		err = -1;
	}

	if (err) {
		k_free(msg_to_sign);
		LOG_ERR("Failed to sign JWT, error: %d", err);
		return -ENOEXEC;
	}

	LOG_HEXDUMP_DBG(sig, sizeof(sig), "Signature: ");

	/* Convert signature to base64 URL and display full JWT */
	err = base64_encode(b64_sig, sizeof(b64_sig), &len, sig, sizeof(sig));
	if (err) {
		LOG_ERR("base64_encode failed, error: %d", err);
		k_free(msg_to_sign);
		return -EIO;
	}

	base64_url_format(b64_sig);

	/* Get the size of the final, signed JWT: +1 for '.' and null-terminator */
	jwt_sz = strlen(msg_to_sign) + 1 + strlen(b64_sig) + 1;

	/* Allocate a buffer if not provided */
	bool alloc = false;
	if (!jwt->jwt_buf) {
		jwt->jwt_buf = k_calloc(jwt_sz, 1);
		if (!jwt->jwt_buf) {
			err = -ENOMEM;
		} else {
			jwt->jwt_sz = jwt_sz;
			alloc = true;
		}
	} else if (jwt_sz > jwt->jwt_sz) {
		err = -E2BIG;
	}

	/* JWT final form:
	 * <base64_header>.<base64_payload>.<base64_signature>
	 */
	if (err == 0) {
		ret = snprintk(jwt->jwt_buf, jwt->jwt_sz, "%s.%s", msg_to_sign, b64_sig);
		if ((ret < 0) || (ret >= jwt->jwt_sz)) {
			err = -ETXTBSY;
		}
	} else {
		err = -ENOMEM;
	}

	if (err && alloc) {
		k_free(jwt->jwt_buf);
	}
	k_free(msg_to_sign);

	LOG_DBG("JWT:\n%s", jwt->jwt_buf);

	return err;
}

int nrf_jwt_generate(struct jwt_data *const jwt)
{
	if (!jwt) {
		return -EINVAL;
	}
	if (jwt->jwt_buf && !jwt->jwt_sz) {
		return -EBADF;
	}

	if (IS_ENABLED(CONFIG_NRF_JWT_PSA) &&
	    jwt->key_src == NRF_JWT_KEY_SRC_PSA) {
		return jwt_generate(jwt);
	}

	if (IS_ENABLED(CONFIG_NRF_JWT_DER) &&
	    jwt->key_src == NRF_JWT_KEY_SRC_DER) {
		return jwt_generate(jwt);
	}

	if (jwt->key_src == NRF_JWT_KEY_SRC_MODEM) {
#if defined(CONFIG_NRF_JWT_MODEM)
		return modem_jwt_generate(jwt);
#endif
	}

	LOG_ERR("Invalid JWT key source or configuration, key_src: %d", jwt->key_src);
	return -ENOTSUP;
}

void nrf_jwt_free(struct jwt_data *const jwt)
{
	if(!jwt) {
		return;
	}

	if (jwt->key_src == NRF_JWT_KEY_SRC_MODEM) {
#if defined(CONFIG_MODEM_JWT)
		modem_jwt_free(jwt->jwt_buf);
#endif
	} else {
		k_free(jwt->jwt_buf);
	}

	jwt->jwt_buf = NULL;
	jwt->jwt_sz = 0;
}
