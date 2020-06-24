/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <string.h>
#include <zephyr.h>
#include <stdlib.h>
#include <net/socket.h>
#include <modem/bsdlib.h>
#include <net/tls_credentials.h>
#include <net/http_client.h>
#include <modem/at_cmd.h>
#include <tinycrypt/hmac_prng.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/constants.h>
#include <sys/base64.h>
//#include <logging/log.h>
#include "fota_client_mgmt.h"

//LOG_MODULE_REGISTER(fota_client_mgmt, CONFIG_FOTA_CLIENT_MGMT_LOG_LEVEL);

/* TODO: the nrf-<IMEI> format is for testing/certification only
 * Device ID will become a GUID for production code.
 */
#define DEV_ID_PREFIX "nrf-"
#define IMEI_LEN (15)
#define DEV_ID_BUFF_SIZE (sizeof(DEV_ID_PREFIX) + IMEI_LEN + 2)

/* NOTE: The header is static from the device point of view
 * so there is no need to build JSON and encode it every time.
 */
/* JWT header: {"alg":"HS256","typ":"JWT"} */
#define JWT_HEADER_B64 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
/* JWT payload: {"devId":"nrf-<IMEI>"} */
#define JWT_PAYLOAD_TEMPLATE "{\"devId\":\"%s\"}"
#define JWT_PAYLOAD_BUFF_SIZE (sizeof(JWT_PAYLOAD_TEMPLATE) + DEV_ID_BUFF_SIZE)

/* TODO: For initial certification, a hard-coded shared secret will be used.
 * For a production release, the plan is to use the modem's built in key
 * to do the signing.
 */
#define SHARED_SECRET { \
		0x32, 0x39, 0x34, 0x41, 0x34, 0x30, 0x34, 0x45, \
		0x36, 0x33, 0x35, 0x32, 0x36, 0x36, 0x35, 0x35, \
		0x36, 0x41, 0x35, 0x38, 0x36, 0x45, 0x33, 0x32, \
		0x37, 0x32, 0x33, 0x34, 0x37, 0x35, 0x33, 0x37 }

#define GET_BASE64_LEN(n) (((4 * n / 3) + 3) & ~3)
/* <b64 header>.<b64 payload>.<b64 signature><NULL> */
#define JWT_BUFF_SIZE (sizeof(JWT_HEADER_B64) + \
		       GET_BASE64_LEN(sizeof(jwt_payload)) + 1 + \
		       GET_BASE64_LEN(sizeof(jwt_sig)) + 1)

static void base64_url_format(char * const base64_string);
static char * get_base64url_string(const char * const input,
				   const size_t input_size);
static char * get_device_id_string(void);
static int get_signature(const uint8_t * const data_in,
			 const size_t data_in_size,
		  	 uint8_t * data_out,
			 size_t const data_out_size);
static void response_cb(struct http_response *rsp,
			enum http_final_call final_data,
			void *user_data);
static int tls_setup(int fd);


#define FW_GET  "Accept: */*\r\n" \
		"Connection: keep-alive\r\n" \
		"range: bytes=0-1023\r\n"\
		"Host: api.dev.nrfcloud.com:443\r\n\r\n"
#define API_HOSTNAME "api.dev.nrfcloud.com"
#define API_HOSTNAME_TLS API_HOSTNAME
#define API_PORT 443

#define JITP_HOSTNAME "a2n7tk1kp18wix-ats.iot.us-east-1.amazonaws.com"
#define JITP_HOSTNAME_TLS JITP_HOSTNAME
#define JITP_PORT 8443
#define DO_JITP "Connection: close\r\n" \
		"Host: " JITP_HOSTNAME ":" \
		STRINGIFY(JITP_PORT) "\r\n\r\n"
#define JITP_HTTP_TIMEOUT_MS (15000)

#define SOCKET_PROTOCOL IPPROTO_TLS_1_2

#define TLS_SEC_TAG 16842753
/* TODO: assuming that the above SEC_TAG will have the right AWS CA cert
static const char cert[] = {
	#include "../cert/AmazonRootCA1"
};
*/

#define HTTP_RX_BUF_SIZE (2048*2)
static char http_rx_buf[HTTP_RX_BUF_SIZE];
static bool http_resp_rcvd;

int fota_client_provision_device(void)
{
	int fd;
	int ret;
	struct addrinfo *res;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};

	ret = getaddrinfo(JITP_HOSTNAME, NULL, &hints, &res);
	if (ret) {
		printk("getaddrinfo() failed, err %d\n", errno);
		return -EFAULT;
	}
	else
	{
		char peer_addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &res->ai_addr, peer_addr, INET_ADDRSTRLEN);
		printk("getaddrinfo() %s\n", peer_addr);
	}


	((struct sockaddr_in *)res->ai_addr)->sin_port = htons(JITP_PORT);

	fd = socket(AF_INET, SOCK_STREAM, SOCKET_PROTOCOL);
	if (fd == -1) {
		printk("Failed to open socket!\n");
		ret = -ENOTCONN;
		goto clean_up;
	}

	/* Setup TLS socket options */
	ret = tls_setup(fd);
	if (ret) {
		ret = -EACCES;
		goto clean_up;
	}

	printk("Connecting to %s\n", JITP_HOSTNAME);
	ret = connect(fd, res->ai_addr, sizeof(struct sockaddr_in));
	if (ret) {
		printk("connect() failed, err: %d\n", errno);
		ret = -ECONNREFUSED;
		goto clean_up;
	}

	struct http_request req;
	memset(&req, 0, sizeof(req));

	req.method = HTTP_POST;
	req.url = "/topics/jitp?qos=1";
	req.host = JITP_HOSTNAME;
	req.protocol = "HTTP/1.1";
	req.content_type_value = DO_JITP;
	req.response = response_cb;
	req.recv_buf = http_rx_buf;
	req.recv_buf_len = sizeof(http_rx_buf);
	http_resp_rcvd = false;

	ret = http_client_req(fd, &req, JITP_HTTP_TIMEOUT_MS, "JITP_REQ");
	printk("http_client_req returned %d\n", ret);

	if (ret < 0) {
		ret = -EIO;
		goto clean_up;
	}

	if (!http_resp_rcvd) {
		// no response = device was NOT already provisioned
		// so provisioning should be occurring...
		// wait 30s before attemping another API call
		ret = 0;
	} else {
		// probably already provisioned...

		// TODO: determine what a failure looks like

		// TODO: perhaps use the settings module to save
		// provisioned state so this call isn't made every time?

		/* NOTE: when already provisioned, the following data is rcvd:
		 * Response status Forbidden
		 * HTTP/1.1 403 Forbidden
		 * content-type: application/json
		 * content-length: 65
		 * date: Wed, 24 Jun 2020 23:10:47 GMT
		 * x-amzn-RequestId: 229ca570-9d45-e73d-6fcd-0f977ed89d9a
		 * connection: keep-alive
		 * x-amzn-ErrorType: ForbiddenException:
		 * {"message":null,"traceId":"229ca570-9d45-e73d-6fcd-0f977ed89d9a"}
		 */

		ret = 1;
	}

clean_up:
	freeaddrinfo(res);
	(void)close(fd);

	return ret;
}

int fota_client_generate_jwt(char ** jwt_out)
{
	if (!jwt_out)
	{
		return -EINVAL;
	}

	char jwt_payload[JWT_PAYLOAD_BUFF_SIZE];
	uint8_t jwt_sig[TC_SHA256_DIGEST_SIZE];
	char * dev_id;
	char * jwt_buff;
	char * jwt_sig_b64;
	char * jwt_payload_b64;
	int ret;
	size_t jwt_len = 0;

	*jwt_out = NULL;

	/* Get the device ID and add it to the payload string */
	dev_id = get_device_id_string();
	if (!dev_id) {
		printk("Could get device ID string\n");
		return -ENODEV;
	}

	ret = snprintk(jwt_payload, sizeof(jwt_payload),
		       JWT_PAYLOAD_TEMPLATE, dev_id);
	k_free(dev_id);
	dev_id = NULL;
	if (ret < 0 || ret >= sizeof(jwt_payload)) {
		printk("Could not format JWT payload\n");
		return -ENOBUFS;
	}
	printk("JWT payload: %s\n", jwt_payload);

	/* Encode payload string to base64 */
	jwt_payload_b64 = get_base64url_string(jwt_payload,
					       strlen(jwt_payload));
	if (!jwt_payload_b64) {
		printk("Could not encode JWT payload\n");
		return -ENOMSG;
	}

	/* Allocate output JWT buffer and add header and payload */
	jwt_buff = k_calloc(JWT_BUFF_SIZE,1);
	if (!jwt_buff){
		printk("Could not allocate JWT buffer.\n");
		k_free(jwt_payload_b64);
		return -ENOMEM;
	}

	ret = snprintk(jwt_buff,JWT_BUFF_SIZE,"%s.%s",
		       JWT_HEADER_B64, jwt_payload_b64);
	k_free(jwt_payload_b64);
	jwt_payload_b64 = NULL;
	if (ret < 0 || ret >= JWT_BUFF_SIZE) {
		printk("Could not format JWT header and payload.\n");
		k_free(jwt_buff);
		return -ENOBUFS;
	}
	jwt_len = ret;

	/* Get signature and append base64 encoded signature to JWT */
	ret = get_signature((uint8_t*)jwt_buff, strlen(jwt_buff),
			    jwt_sig, sizeof(jwt_sig));
	if (ret) {
		printk("Error signing JWT: %d\n", ret);
		k_free(jwt_buff);
		return -EBADMSG;
	}

	jwt_sig_b64 = get_base64url_string(jwt_sig, TC_SHA256_DIGEST_SIZE);
	if (!jwt_sig_b64) {
		printk("Could not encode JWT signature\n");
		k_free(jwt_buff);
		return -ENOMSG;
	}
	printk("signature: %s\n", jwt_sig_b64);

	ret = snprintk(&jwt_buff[jwt_len],
		       JWT_BUFF_SIZE,
		       ".%s",
		       jwt_sig_b64);
	k_free(jwt_sig_b64);
	jwt_sig_b64 = NULL;
	if (ret < 0 || ret >= (JWT_BUFF_SIZE-jwt_len)) {
		printk("Could not format JWT signature\n");
		k_free(jwt_buff);
		return -ENOBUFS;
	}

	*jwt_out = jwt_buff;
	return strlen(*jwt_out);
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

	ret = snprintk(dev_id, DEV_ID_BUFF_SIZE,"%s", DEV_ID_PREFIX);
	if (ret < 0 || ret >= DEV_ID_BUFF_SIZE) {
		printk("Could not format device ID\n");
		k_free(dev_id);
		return NULL;
	}
	dev_id_len = ret;

	at_cmd_init();

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

static void response_cb(struct http_response *rsp,
			enum http_final_call final_data,
			void *user_data)
{
	if (final_data == HTTP_DATA_MORE) {
		printk("Partial data received (%zd bytes)\n", rsp->data_len);
		if (rsp->body_start) {
			printk("BODY %s\n", rsp->body_start);
		}
	} else if (final_data == HTTP_DATA_FINAL) {
		printk("All the data received (%zd bytes)\n", rsp->data_len);

		printk("proc: %zd, content len: %zd, body found: %d, complete: %d\n",
		       rsp->processed, rsp->content_length,
		       rsp->body_found, rsp->message_complete);

		if (rsp->data_len && rsp->body_found) {
			printk("BODY: %s\n", rsp->body_start);
		}
		else if (rsp->body_found && !rsp->body_start) {
			printk("RCV BUFF: %s\n", rsp->recv_buf);
		}
	}

	http_resp_rcvd = true;

	printk("Response to %s\n", (const char *)user_data);
	printk("Response status %s\n", rsp->http_status);
}

/* Setup TLS options on a given socket */
int tls_setup(int fd)
{
	int err;
	int verify;

	/* Security tag that we have provisioned the certificate with */
	const sec_tag_t tls_sec_tag[] = {
		TLS_SEC_TAG,
	};

	/* Set up TLS peer verification */
	enum {
		NONE = 0,
		OPTIONAL = 1,
		REQUIRED = 2,
	};

	verify = REQUIRED;

	err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	if (err) {
		printk("Failed to setup peer verification, err %d\n", errno);
		return err;
	}

	/* Associate the socket with the security tag
	 * we have provisioned the certificate with.
	 */
	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag,
			 sizeof(tls_sec_tag));
	if (err) {
		printk("Failed to setup TLS sec tag, err %d\n", errno);
		return err;
	}

	err = setsockopt(fd, SOL_TLS, TLS_HOSTNAME, JITP_HOSTNAME_TLS,
				 strlen(JITP_HOSTNAME_TLS));
	if (err) {
		printk("Failed to setup TLS hostname, err %d\n", errno);
		return err;
	}
	return 0;
}