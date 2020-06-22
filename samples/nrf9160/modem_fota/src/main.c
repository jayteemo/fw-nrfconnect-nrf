/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <stdio.h>
#include <bsd.h>
#include <string.h>
#include <zephyr.h>
#include <power/reboot.h>
#include <modem/bsdlib.h>
#include <modem/lte_lc.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <modem/modem_fota.h>

#include <net/socket.h>
#include <tinycrypt/hmac_prng.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/constants.h>
#include <sys/base64.h>
#include <net/http_client.h>

#define JWT_BUFF_SIZE 256

static bool provision_device(void);
static int generate_jwt(char * jwt_buff, size_t jwt_buff_size);
static bool get_pending_job(void);
static int update_job_status(void);
static void base64_url_format(char * const base64_string);
static char * get_base64url_string(const char * const input,
				   const size_t input_size);
static char * get_device_id_string(void);
static int get_signature(const uint8_t * const data_in,
			 const size_t data_in_size,
		  	 uint8_t * data_out,
			 size_t const data_out_size);

void bsd_recoverable_error_handler(uint32_t err)
{
	printk("bsdlib recoverable error: %u\n", err);
}

void modem_fota_callback(enum modem_fota_evt_id event_id)
{
	switch (event_id) {
	case MODEM_FOTA_EVT_CHECKING_FOR_UPDATE:
		/* TODO: check for update */
		get_pending_job();
		break;

	case MODEM_FOTA_EVT_NO_UPDATE_AVAILABLE:
		break;

	case MODEM_FOTA_EVT_DOWNLOADING_UPDATE:
		/* TODO: report progress? */
		update_job_status();
		break;

	case MODEM_FOTA_EVT_RESTART_PENDING:
		 /* TODO: update job status before reboot */
		update_job_status();
		printk("Rebooting...\n");
		lte_lc_offline();
		sys_reboot(SYS_REBOOT_WARM);
		break;

	case MODEM_FOTA_EVT_ERROR:
		/* TODO: report error */
		update_job_status();
	default:
		break;
	}
}

void main(void)
{
	int err;
	char jwt[JWT_BUFF_SIZE];

	printk("Modem FOTA sample started\n");

	printk("Initializing bsdlib...\n");
	err = bsdlib_init();
	switch (err) {
	case MODEM_DFU_RESULT_OK:
		printk("Modem firmware update successful!\n");
		printk("Modem will run the new firmware after reboot\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case MODEM_DFU_RESULT_UUID_ERROR:
	case MODEM_DFU_RESULT_AUTH_ERROR:
		printk("Modem firmware update failed!\n");
		printk("Modem will run non-updated firmware on reboot.\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case MODEM_DFU_RESULT_HARDWARE_ERROR:
	case MODEM_DFU_RESULT_INTERNAL_ERROR:
		printk("Modem firmware update failed!\n");
		printk("Fatal error.\n");
		sys_reboot(SYS_REBOOT_WARM);
		break;
	case -1:
		printk("Could not initialize bsdlib.\n");
		printk("Fatal error.\n");
		return;
	default:
		break;
	}
	printk("Initialized bsdlib\n");

	/* Initialize AT command and notification libraries because
	 * CONFIG_BSD_LIBRARY_SYS_INIT is disabled and these libraries aren't
	 * initialized automatically.
	 */
	at_cmd_init();
	at_notif_init();

	err = generate_jwt(jwt,sizeof(jwt));
	if (err < 0){
		printk("Failed to generate JWT: %d\n", err);
		return;
	}
	printk("JWT: %s\n", jwt);

	printk("LTE link connecting...\n");
	err = lte_lc_init_and_connect();
	__ASSERT(err == 0, "LTE link could not be established.");
	printk("LTE link connected!\n");

	provision_device();
	get_pending_job();

	modem_fota_init(&modem_fota_callback);
	k_sleep(K_FOREVER);
}

static bool provision_device(void)
{
	return true;
}

#define DEV_ID_PREFIX "nrf-"
#define IMEI_LEN (15)
#define DEV_ID_BUFF_SIZE (sizeof(DEV_ID_PREFIX) + IMEI_LEN + 2)
/* JWT header: {"alg":"HS256","typ":"JWT"} */
#define JWT_HEADER_B64 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
/* JWT body: {"devId":"nrf-<IMEI>"}
	* TODO: the nrf-<IMEI> format is for testing/certification only
	* Device ID will become a GUID for production code.
	*/
#define JWT_PAYLOAD_TEMPLATE "{\"devId\":\"%s\"}"
#define JWT_PAYLOAD_BUFF_SIZE (sizeof(JWT_PAYLOAD_TEMPLATE) + DEV_ID_BUFF_SIZE)
#define SHARED_SECRET { \
		0x32, 0x39, 0x34, 0x41, 0x34, 0x30, 0x34, 0x45, \
		0x36, 0x33, 0x35, 0x32, 0x36, 0x36, 0x35, 0x35, \
		0x36, 0x41, 0x35, 0x38, 0x36, 0x45, 0x33, 0x32, \
		0x37, 0x32, 0x33, 0x34, 0x37, 0x35, 0x33, 0x37 }

static int generate_jwt(char * jwt_buff, size_t jwt_buff_size)
{
	if (!jwt_buff || !jwt_buff_size)
	{
		return -EINVAL;
	}

	char jwt_payload[JWT_PAYLOAD_BUFF_SIZE];
	uint8_t jwt_sig[TC_SHA256_DIGEST_SIZE];
	char * dev_id;
	char * jwt_sig_b64;
	char * jwt_payload_b64;
	int ret;
	size_t jwt_len = 0;

	dev_id = get_device_id_string();
	if (!dev_id) {
		printk("Could get device ID string\n");
		return -ENODEV;
	}

	ret = snprintf(jwt_buff,jwt_buff_size,"%s.",JWT_HEADER_B64);
	if (ret < 0 || ret >= jwt_buff_size) {
		printk("Could not format JWT header\n");
		return -ENOBUFS;
	}
	jwt_len = ret;

	ret = snprintf(jwt_payload, sizeof(jwt_payload),
		       JWT_PAYLOAD_TEMPLATE, dev_id);
	k_free(dev_id);
	dev_id = NULL;
	if (ret < 0 || ret >= sizeof(jwt_payload)) {
		printk("Could not format JWT payload\n");
		return -ENOBUFS;
	}

	printk("JWT payload: %s\n", jwt_payload);

	jwt_payload_b64 = get_base64url_string(jwt_payload,
					       strlen(jwt_payload));
	if (!jwt_payload_b64) {
		printk("Could not encode JWT payload\n");
		return -ENOMSG;
	}

	ret = snprintf(&jwt_buff[jwt_len],
		       jwt_buff_size - jwt_len,
		       "%s",
		       jwt_payload_b64);
	k_free(jwt_payload_b64);
	jwt_payload_b64 = NULL;
	if (ret < 0 || ret >= jwt_buff_size) {
		printk("Could not format JWT header\n");
		return -ENOBUFS;
	}
	jwt_len += ret;
	printk("Combined: %s\n", jwt_buff);

	ret = get_signature((uint8_t*)jwt_buff, strlen(jwt_buff),
			    jwt_sig, sizeof(jwt_sig));
	if (ret) {
		printk("Error signing JWT: %d\n", ret);
		return -EBADMSG;
	}

	jwt_sig_b64 = get_base64url_string(jwt_sig, TC_SHA256_DIGEST_SIZE);
	if (!jwt_sig_b64) {
		printk("Could not encode JWT signature\n");
		return -ENOMSG;
	}
	printk("signature: %s\n", jwt_sig_b64);

	ret = snprintf(&jwt_buff[jwt_len],
		       jwt_buff_size,
		       ".%s",
		       jwt_sig_b64);
	k_free(jwt_sig_b64);

	return strlen(jwt_buff);
}

static int get_signature(const uint8_t * const data_in,
			 const size_t data_in_size,
			 uint8_t * data_out,
			 size_t const data_out_size) {

	if (!data_in || !data_in_size || !data_out) {
		return -EINVAL;
	} else if (data_out_size < TC_SHA256_DIGEST_SIZE) {
		printk("data_out must be >= %d bytes\n",
		       TC_SHA256_DIGEST_SIZE);
		return -ENOBUFS;
	}

	struct tc_hmac_state_struct hmac;
	char shared_secret[] = SHARED_SECRET;
	int ret;

	ret = tc_hmac_set_key(&hmac, shared_secret, sizeof(shared_secret));
	if (ret != TC_CRYPTO_SUCCESS) {
		printk("tc_hmac_set_key failed: %d\n", ret);
		return -EACCES;
	}

	ret = tc_hmac_init(&hmac);
	if (ret != TC_CRYPTO_SUCCESS) {
		printk("tc_hmac_init failed: %d\n", ret);
	}

	ret = tc_hmac_update(&hmac, data_in, data_in_size);
	if (ret != TC_CRYPTO_SUCCESS) {
		printk("tc_hmac_update failed: %d\n", ret);
		return -EACCES;
	}

	ret = tc_hmac_final(data_out,data_out_size,&hmac);
	if (ret != TC_CRYPTO_SUCCESS) {
		printk("tc_hmac_final failed\n");
		return -EACCES;
	}

	printk("HMAC hex:\n");
	for (int i = 0; i < TC_SHA256_DIGEST_SIZE; ++i) {
		printk("%02X",data_out[i]);
	}
	printk("\n");

	return 0;
}

static char * get_device_id_string(void)
{
	int ret;
	enum at_cmd_state state;
	size_t dev_id_len;
	char * dev_id = k_calloc(DEV_ID_BUFF_SIZE,1);

	if (!dev_id) {
		printk("Could not allocate memory for device ID\n");
		return NULL;
	}

	ret = snprintf(dev_id, DEV_ID_BUFF_SIZE,"%s", DEV_ID_PREFIX);
	if (ret < 0 || ret >= DEV_ID_BUFF_SIZE) {
		printk("Could not format device ID\n");
		k_free(dev_id);
		return NULL;
	}
	dev_id_len = ret;

	ret = at_cmd_write("AT+CGSN",
			   &dev_id[dev_id_len],
			   DEV_ID_BUFF_SIZE - dev_id_len,
			   &state);
	if (ret) {
		printk("Failed to get IMEI: %d\n", ret);
		k_free(dev_id);
		return NULL;
	}

	dev_id_len += IMEI_LEN; /* remove /r/r from AT cmd result */
	dev_id[dev_id_len] = 0;

	return dev_id;
}
char * get_base64url_string(const char * const input, const size_t input_size)
{
	if (!input || !input_size) {
		printk("%s() Invalid input buffer\n", __func__);
		return NULL;
	}
	int ret;
	char * output_str;
	size_t output_str_len;

	(void)base64_encode(NULL,
			    0,
			    &output_str_len,
			    input,
			    input_size);
	if (output_str_len == ((size_t)-1)) {
		printk("%s() Unable to encode input string to base64\n",
		       __func__);
		return NULL;
	}

	output_str = k_calloc(output_str_len+1,1);
	if (!output_str) {
		printk("%s() Unable to allocate memory for base64 string\n",
		       __func__);
		return NULL;
	}
	ret = base64_encode(output_str,
			    output_str_len,
			    &output_str_len,
			    input,
			    input_size);
	if (ret) {
		printk("Error encoding input string to base64: %d\n", ret);
		k_free(output_str);
		return NULL;
	}
	base64_url_format(output_str);

	return output_str;
}

void base64_url_format(char * const base64_string)
{
	if (base64_string == NULL) {
		return;
	}

	char * found = NULL;

	/* replace '+' with "-" */
	for(found = base64_string; (found = strchr(found,'+'));) {
		*found = '-';
	}

	/* replace '/' with "_" */
	for(found = base64_string; (found = strchr(found,'/'));) {
		*found = '_';
	}

	/* remove trailing '=' */
	found = strchr(base64_string, '=');
	if (found) {
		*found = '\0';
	}
}

static bool get_pending_job(void)
{
	return false;
}

static int update_job_status(void)
{
	return 0;
}