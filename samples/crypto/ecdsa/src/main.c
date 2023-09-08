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
#include <net/nrf_jwt.h>

#ifdef CONFIG_BUILD_WITH_TFM
#include <tfm_ns_interface.h>
#endif

LOG_MODULE_REGISTER(ecdsa, LOG_LEVEL_DBG);

#define KEY_ID 					(123)
#define JWT_SUBJECT_DEVICE_ID			"nrf-351358811125498"
#define PSA_CRYPTO_INVALID_KEY_HANDLE		 (0)
#define NRF_CRYPTO_EXAMPLE_ECDSA_PUBLIC_KEY_SIZE (65)


/* Hex header for EC public key ASN1 OID: prime256v1, NIST CURVE: P-256 */
#define PUB_KEY_DER_HDR "3059301306072A8648CE3D020106082A8648CE3D030107034200"
#define PUB_KEY_DER_SZ (sizeof(PUB_KEY_DER_HDR) + (NRF_CRYPTO_EXAMPLE_ECDSA_PUBLIC_KEY_SIZE * 2))
static char m_pub_key_der[PUB_KEY_DER_SZ];
static uint8_t m_pub_key[NRF_CRYPTO_EXAMPLE_ECDSA_PUBLIC_KEY_SIZE];
static psa_key_handle_t keypair_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;
static psa_key_handle_t import_handle = PSA_CRYPTO_INVALID_KEY_HANDLE;

int crypto_init(void)
{
	psa_status_t status;

	/* Initialize PSA Crypto */
	status = psa_crypto_init();
	if (status != PSA_SUCCESS)
		return status;

	return 0;
}

int crypto_finish(void)
{
	psa_status_t status;

	/* Destroy the key handle */
	status = psa_destroy_key(keypair_handle);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_destroy_key failed! (Error: %d)", status);
		return status;
	}

	return 0;
}

int print_hex(uint8_t *data, size_t data_sz, char * out_buf, size_t out_buf_sz)
{
#define HEX_CHARS "0123456789ABCDEF"
	if (((data_sz * 2) + 1) > out_buf_sz) {
		return -E2BIG;
	}

	size_t j = 0;

	for (size_t i = 0; i < data_sz; ++i) {
		out_buf[j++] = HEX_CHARS[data[i] / 16];
                out_buf[j++] = HEX_CHARS[data[i] % 16];
	}

	out_buf[j] = 0;

	return 0;
}

void print_pub_key_der(void)
{
#define DER_SECTION "********************************************************"
#define INST_SECTION "--------------------------------------------------------"
	int key_idx = snprintk(m_pub_key_der, sizeof(m_pub_key_der), "%s", PUB_KEY_DER_HDR);

	print_hex(m_pub_key, sizeof(m_pub_key), &m_pub_key_der[key_idx], sizeof(m_pub_key_der) - key_idx);

	LOG_INF("Public key DER:\r\n%s\r\n%s\r\n%s", DER_SECTION, m_pub_key_der, DER_SECTION);
	LOG_INF(INST_SECTION);
	LOG_INF("To create a public key PEM file:");
	LOG_INF("   echo <Public key DER> | xxd -r -p > pub_key.der");
	LOG_INF("   openssl ec -pubin -inform d -in pub_key.der -outform pem -out pub_key.pem");
	LOG_INF(INST_SECTION);
}

void export_public_key(void)
{
	psa_status_t status;
	size_t olen;

	status = psa_export_public_key(keypair_handle, m_pub_key, sizeof(m_pub_key), &olen);
	if (status != PSA_SUCCESS) {
		LOG_INF("psa_export_public_key failed! (Error: %d)", status);
		return;
	}

	LOG_HEXDUMP_INF(m_pub_key, olen, "Public key: ");

	print_pub_key_der();
}

int generate_ecdsa_keypair(void)
{
	psa_status_t status;

	LOG_INF("Generating random ECDSA keypair...");

	/* Configure the key attributes */
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	/* Configure the key attributes */
	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attributes, 256);

	/* Persistent key specific settings */
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_id(&key_attributes, KEY_ID);

	/* Generate a random keypair. The keypair is not exposed to the application,
	 * we can use it to signing/verification the key handle.
	 */
	status = psa_generate_key(&key_attributes, &keypair_handle);
	if (status != PSA_SUCCESS) {
		if (status == PSA_ERROR_ALREADY_EXISTS) {
			LOG_INF("Key with ID '%d' already exists", KEY_ID);
		} else {
			LOG_ERR("psa_generate_key failed, error: %d)", status);
		}
		return status;
	}

	/* Export the public key */
	export_public_key();

	/* After the key handle is acquired the attributes are not needed */
	psa_reset_key_attributes(&key_attributes);

	return 0;
}

int import_static_key(void)
{
	static uint8_t priv_key_data[32] = {
		0x14, 0xbc, 0xb9, 0x53, 0xa4, 0xee, 0xed, 0x50,
		0x09, 0x36, 0x92, 0x07, 0x1d, 0xdb, 0x24, 0x2c,
		0xef, 0xf9, 0x57, 0x92, 0x40, 0x4f, 0x49, 0xaa,
		0xd0, 0x7c, 0x5b, 0x3f, 0x26, 0xa7, 0x80, 0x48 };

	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_SIGN_HASH);
	psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&key_attributes, 256);

	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_id(&key_attributes, KEY_ID+1);

	LOG_HEXDUMP_INF(priv_key_data, 32, "Private Key: ");
	return psa_import_key(&key_attributes, priv_key_data, 32, &import_handle);
}

int main(void)
{
	int status;

	LOG_INF("Starting JWT example...");

	status = crypto_init();
	if (status != 0) {
		LOG_INF("crypto_init failed, error: %d", status);
		return status;
	}

	status = import_static_key();
	if (status != PSA_SUCCESS) {
		LOG_ERR("Import failed, error: %d", status);
	} else {
		LOG_INF("Static key imported!");
	}
	status = generate_ecdsa_keypair();
	if (status != PSA_SUCCESS) {
		if (status != PSA_ERROR_ALREADY_EXISTS) {
			return 0;
		}

		LOG_INF("Opening key ID '%d'...", KEY_ID);
    		status = psa_open_key(KEY_ID, &keypair_handle);

		if (status == PSA_SUCCESS) {
			export_public_key();
		} else {
			LOG_INF("psa_open_key failed, error: %d", status);
		}
	}

	if (status || (keypair_handle == PSA_CRYPTO_INVALID_KEY_HANDLE)) {
		LOG_ERR("Failed to generate or open key.");
	}

	struct jwt_data jwt = { .key_src = NRF_JWT_KEY_SRC_PSA,
				.alg = JWT_ALG_TYPE_ES256,
				.subject = JWT_SUBJECT_DEVICE_ID,
				.signing_key_h = import_handle,
				.jwt_buf = NULL,
				.exp_time_s = 0,
				.exp_delta_s = 0
	};

	status = nrf_jwt_generate(&jwt);
	if (status == 0) {
		LOG_INF("JWT:\r\n%s", jwt.jwt_buf);
	} else {
		LOG_ERR("nrf_jwt_generate() failed, error: %d", status);
	}

	nrf_jwt_free(&jwt);

	return 0;
}
