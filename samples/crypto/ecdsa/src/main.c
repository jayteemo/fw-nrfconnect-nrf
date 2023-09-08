/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/logging/log.h>
#include <stdio.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <psa/crypto_extra.h>
#include <zephyr/sys/base64.h>
#include <cJSON.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

#define APP_SUCCESS		(0)
#define APP_ERROR		(-1)
#define APP_SUCCESS_MESSAGE "Example finished successfully!"
#define APP_ERROR_MESSAGE "Example exited with error!"

#define PRINT_HEX(p_label, p_text, len)\
	({\
		LOG_INF("---- %s (len: %u): ----", p_label, len);\
		LOG_HEXDUMP_INF(p_text, len, "Content:");\
		LOG_INF("---- %s end  ----", p_label);\
	})

LOG_MODULE_REGISTER(ecdsa, LOG_LEVEL_DBG);

/* ====================================================================== */
/*				Global variables/defines for the ECDSA example			  */

#define NRF_CRYPTO_EXAMPLE_ECDSA_TEXT_SIZE (100)

#define NRF_CRYPTO_EXAMPLE_ECDSA_PUBLIC_KEY_SIZE (65)
#define NRF_CRYPTO_EXAMPLE_ECDSA_SIGNATURE_SIZE (64)
#define NRF_CRYPTO_EXAMPLE_ECDSA_HASH_SIZE (32)

#define BASE64_ENCODE_SZ(n) (((4 * n / 3) + 3) & ~3)

/* Below text is used as plaintext for signing/verification */
//static uint8_t m_plain_text[NRF_CRYPTO_EXAMPLE_ECDSA_TEXT_SIZE] = {
//	"Example string to demonstrate basic usage of ECDSA."
//};

static uint8_t m_pub_key[NRF_CRYPTO_EXAMPLE_ECDSA_PUBLIC_KEY_SIZE];

static uint8_t m_signature[NRF_CRYPTO_EXAMPLE_ECDSA_SIGNATURE_SIZE];

#define B64_SIG_SZ (BASE64_ENCODE_SZ(NRF_CRYPTO_EXAMPLE_ECDSA_SIGNATURE_SIZE) + 1)
static uint8_t m_b64_signature[B64_SIG_SZ] = {0};

static uint8_t m_hash[NRF_CRYPTO_EXAMPLE_ECDSA_HASH_SIZE];

static psa_key_handle_t keypair_handle;
static psa_key_handle_t pub_key_handle;
/* ====================================================================== */

int crypto_init(void)
{
	psa_status_t status;

	/* Initialize PSA Crypto */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS)
		return APP_ERROR;

	return APP_SUCCESS;
}

int crypto_finish(void)
{
	psa_status_t status;

	/* Destroy the key handle */
	status = psa_destroy_key(keypair_handle);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	status = psa_destroy_key(pub_key_handle);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	return APP_SUCCESS;
}

int generate_ecdsa_keypair(void)
{
	psa_status_t status;
	size_t olen;

	LOG_INF("Generating random ECDSA keypair...");

	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	/* Configure the key attributes */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attributes, 256);

	/* Generate a random keypair. The keypair is not exposed to the application,
	 * we can use it to signing/verification the key handle.
	 */
	status = psa_generate_key(&key_attributes, &keypair_handle);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_generate_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Export the public key */
	status = psa_export_public_key(keypair_handle, m_pub_key, sizeof(m_pub_key), &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_export_public_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_HEXDUMP_INF(m_pub_key, olen, "Public key: ");

	/* After the key handle is acquired the attributes are not needed */
	psa_reset_key_attributes(&key_attributes);

	return APP_SUCCESS;
}

int import_ecdsa_pub_key(void)
{
	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	/* Configure the key attributes */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attributes, 256);

	status = psa_import_key(&key_attributes, m_pub_key, sizeof(m_pub_key), &pub_key_handle);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_import_key failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* After the key handle is acquired the attributes are not needed */
	psa_reset_key_attributes(&key_attributes);

	return APP_SUCCESS;
}

int sign_message(char * msg)
{
	uint32_t output_len;
	psa_status_t status;

	LOG_INF("Signing a message using ECDSA...");

	/* Compute the SHA256 hash*/
	status = psa_hash_compute(PSA_ALG_SHA_256,
				  msg,
				  strlen(msg),
				  m_hash,
				  sizeof(m_hash),
				  &output_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_hash_compute failed! (Error: %d)", status);
		return APP_ERROR;
	}

	/* Sign the hash */
	status = psa_sign_hash(keypair_handle,
			       PSA_ALG_ECDSA(PSA_ALG_SHA_256),
			       m_hash,
			       sizeof(m_hash),
			       m_signature,
			       sizeof(m_signature),
			       &output_len);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_sign_hash failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("Signing the message successful!");
	LOG_INF("Message: %s", msg);
	PRINT_HEX("SHA256 hash", m_hash, sizeof(m_hash));
	PRINT_HEX("Signature", m_signature, sizeof(m_signature));

	return APP_SUCCESS;
}

int verify_message(void)
{
	psa_status_t status;

	LOG_INF("Verifying ECDSA signature...");

	/* Verify the signature of the hash */
	status = psa_verify_hash(pub_key_handle,
				 PSA_ALG_ECDSA(PSA_ALG_SHA_256),
				 m_hash,
				 sizeof(m_hash),
				 m_signature,
				 sizeof(m_signature));
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_verify_hash failed! (Error: %d)", status);
		return APP_ERROR;
	}

	LOG_INF("Signature verification was successful!");

	return APP_SUCCESS;
}

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

int main(void)
{
	int status;

	LOG_INF("Starting ECDSA example...");

	status = crypto_init();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = generate_ecdsa_keypair();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	status = import_ecdsa_pub_key();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

 	size_t len = 0;
	cJSON *jwt_hdr = cJSON_CreateObject();
	cJSON *jwt_pay = cJSON_CreateObject();

	/* Build the JWT header */
	cJSON_AddStringToObjectCS(jwt_hdr, "alg", "ES256");
	cJSON_AddStringToObjectCS(jwt_hdr, "typ", "JWT");

	/* Build the JWT payload */
	cJSON_AddStringToObjectCS(jwt_pay, "sub", "nrf-351358811125498");

	char *hdr_str = cJSON_PrintUnformatted(jwt_hdr);
	char *pay_str = cJSON_PrintUnformatted(jwt_pay);
	size_t hdr_len = strlen(hdr_str);
	size_t pay_len = strlen(pay_str);

	size_t b64_hdr_sz = BASE64_ENCODE_SZ(hdr_len) + 1;
	size_t b64_pay_sz = BASE64_ENCODE_SZ(pay_len) + 1;
	char *b64_hdr = k_calloc(1, b64_hdr_sz);
	char *b64_pay = k_calloc(1, b64_pay_sz);

	/* Convert to base64 URL */
	base64_encode(b64_pay, b64_pay_sz, &b64_pay_sz, pay_str, pay_len);
	base64_url_format(b64_hdr);
	base64_encode(b64_hdr, b64_hdr_sz, &b64_hdr_sz, hdr_str, hdr_len);
	base64_url_format(b64_pay);

	size_t msg_to_sign_sz = strlen(b64_hdr) + 1 + strlen(b64_pay) + 1;
	char *msg_to_sign = k_calloc(1, msg_to_sign_sz);

	/* Build the base64 URL JWT to sign:
	 * <base64_header>.<base64_payload>
	 */
	snprintk(msg_to_sign, msg_to_sign_sz, "%s.%s", b64_hdr, b64_pay);

	/* Perform signing, result will be in m_signature */
	status = sign_message(msg_to_sign);
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	/* Convert signature to base64 URL and display full JWT */
	base64_encode(m_b64_signature, sizeof(m_b64_signature), &len, m_signature, sizeof(m_signature));
	base64_url_format(m_b64_signature);
	LOG_INF("JWT:\n%s.%s", msg_to_sign, m_b64_signature);

	/* Verify with public key */
	status = verify_message();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	/* Cleanup */
	cJSON_Delete(jwt_pay);
	cJSON_Delete(jwt_hdr);
	cJSON_free(hdr_str);
	cJSON_free(pay_str);
	k_free(b64_hdr);
	k_free(b64_pay);
	k_free(msg_to_sign);

	status = crypto_finish();
	if (status != APP_SUCCESS) {
		LOG_INF(APP_ERROR_MESSAGE);
		return APP_ERROR;
	}

	LOG_INF(APP_SUCCESS_MESSAGE);

	return APP_SUCCESS;
}
