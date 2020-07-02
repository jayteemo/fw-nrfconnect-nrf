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
#include <net/aws_jobs.h> /* for enum execution_status */
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
/* JWT payload: {"deviceIdentifier":"nrf-<IMEI>"} */
#define JWT_PAYLOAD_TEMPLATE "{\"deviceIdentifier\":\"%s\"}"
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

static int generate_jwt(const char * const device_id, char ** jwt_out);
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
static int tls_setup(int fd, const char * const tls_hostname);
static int do_connect(int * const fd, struct addrinfo **addr_info,
		      const char * const hostname, const uint16_t port_num);
static int parse_pending_job_response(const char * const resp_buff,
				      struct fota_client_mgmt_job * const job);

#define API_HOSTNAME "api.dev.nrfcloud.com"
#define API_HOSTNAME_TLS API_HOSTNAME
#define API_PORT 443
#define API_HTTP_TIMEOUT_MS (15000)

// TODO: determine if it is worth adding JSON parsing library to
#define JOB_ID_BEGIN_STR	"\"jobId\":\""
#define JOB_ID_END_STR		"\""
#define FW_URI_BEGIN_STR	"\"uris\":[\""
#define FW_URI_END_STR		"\"]"
#define FW_PATH_PREFIX		"/v1/firmwares/"

#define API_UPDATE_JOB_URL_PREFIX "/v1/dfu-job-execution-statuses/"
#define API_UPDATE_JOB_TEMPLATE	 "content-type: application/json\r\n" \
				 "Authorization: Bearer %s\r\n" \
				 "Host: " API_HOSTNAME "\r\n\r\n"
#define API_UPDATE_JOB_BODY_TEMPLATE 	"{\"status\":\"%s\"," \
					"\"statusDetails\": %s}"

#define API_GET_JOB_URL_TEMPLATE "/v1/dfu-jobs/device/%s/latest-pending"
#define API_GET_JOB_TEMPLATE	 "accept: application/json\r\n" \
				 "Authorization: Bearer %s\r\n" \
				 "Host: " API_HOSTNAME "\r\n\r\n"

// TODO: switch to PROD endpoint: "a2n7tk1kp18wix-ats.iot.us-east-1.amazonaws.com"
#define JITP_HOSTNAME "a2wg6q8yw7gv5r-ats.iot.us-east-1.amazonaws.com"
#define JITP_HOSTNAME_TLS JITP_HOSTNAME
#define JITP_PORT 8443
#define JITP_URL "/topics/jitp?qos=1"
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

enum http_status {
	HTTP_STATUS_UNHANDLED = -1,
	HTTP_STATUS_NONE = 0,
	HTTP_STATUS_OK = 200,
	HTTP_STATUS_BAD_REQ = 400,
	HTTP_STATUS_UNAUTH = 401,
	HTTP_STATUS_FORBIDDEN = 403,
	HTTP_STATUS_NOT_FOUND = 404,
};

enum http_req_type {
	HTTP_REQ_TYPE_UNHANDLED,
	HTTP_REQ_TYPE_PROVISION,
	HTTP_REQ_TYPE_GET_JOB,
	HTTP_REQ_TYPE_UPDATE_JOB,
};

struct http_user_data {
	enum http_req_type type;
	union {
		struct fota_client_mgmt_job * job;
	} data;
};

// TODO: this is copied from aws_jobs.c, find better way to share this?
/** @brief Mapping of enum to strings for Job Execution Status. */
static const char *job_status_strings[] = {
	[AWS_JOBS_QUEUED]      = "QUEUED",
	[AWS_JOBS_IN_PROGRESS] = "IN_PROGRESS",
	[AWS_JOBS_SUCCEEDED]   = "SUCCEEDED",
	[AWS_JOBS_FAILED]      = "FAILED",
	[AWS_JOBS_TIMED_OUT]   = "TIMED_OUT",
	[AWS_JOBS_REJECTED]    = "REJECTED",
	[AWS_JOBS_REMOVED]     = "REMOVED",
	[AWS_JOBS_CANCELED]    = "CANCELED"
};

#define JOB_STATUS_STRING_COUNT (sizeof(job_status_strings) / \
				 sizeof(*job_status_strings))

#define HTTP_RX_BUF_SIZE (4096)
static char http_rx_buf[HTTP_RX_BUF_SIZE];
static bool http_resp_rcvd;
static enum http_status http_resp_status;

static int do_connect( int * const fd, struct addrinfo **addr_info,
		const char * const hostname, const uint16_t port_num)
{
	int ret;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};

	ret = getaddrinfo(hostname, NULL, &hints, addr_info);
	if (ret) {
		printk("getaddrinfo() failed, err %d\n", errno);
		return -EFAULT;
	}
	else
	{
		char peer_addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(*addr_info)->ai_addr, peer_addr, INET_ADDRSTRLEN);
		printk("getaddrinfo() %s\n", peer_addr);
	}


	((struct sockaddr_in *)(*addr_info)->ai_addr)->sin_port = htons(port_num);

	*fd = socket(AF_INET, SOCK_STREAM, SOCKET_PROTOCOL);
	if (*fd == -1) {
		printk("Failed to open socket!\n");
		ret = -ENOTCONN;
		goto clean_up;
	}

	/* Setup TLS socket options */
	ret = tls_setup(*fd, hostname);
	if (ret) {
		ret = -EACCES;
		goto clean_up;
	}

	printk("Connecting to %s\n", hostname);
	ret = connect(*fd, (*addr_info)->ai_addr, sizeof(struct sockaddr_in));
	if (ret) {
		printk("connect() failed, err: %d\n", errno);
		ret = -ECONNREFUSED;
		goto clean_up;
	} else {
		return 0;
	}

clean_up:
	freeaddrinfo(*addr_info);
	(void)close(*fd);
	return ret;
}

int fota_client_provision_device(void)
{
	int fd;
	int ret;
	struct addrinfo *addr_info;
	struct http_request req;
	struct http_user_data prov_data = { .type = HTTP_REQ_TYPE_PROVISION };

	memset(&req, 0, sizeof(req));
	req.method = HTTP_POST;
	req.url = JITP_URL;
	req.host = JITP_HOSTNAME;
	req.protocol = "HTTP/1.1";
	req.content_type_value = DO_JITP;
	req.response = response_cb;
	req.recv_buf = http_rx_buf;
	req.recv_buf_len = sizeof(http_rx_buf);
	http_resp_rcvd = false;
	http_resp_status = HTTP_STATUS_NONE;

	ret = do_connect(&fd, &addr_info, JITP_HOSTNAME, JITP_PORT);
	if (ret) {
		return ret;
	}

	ret = http_client_req(fd, &req, JITP_HTTP_TIMEOUT_MS, &prov_data);
	printk("http_client_req returned %d\n", ret);

	if (ret < 0) {
		ret = -EIO;
	} else if (!http_resp_rcvd) {
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

	freeaddrinfo(addr_info);
	(void)close(fd);

	return ret;
}

void fota_client_job_free(struct fota_client_mgmt_job * const job)
{
	if (!job) {
		return;
	}

	if (job->host) {
		k_free(job->host);
		job->host = NULL;
	}
	if (job->path) {
		k_free(job->path);
		job->path = NULL;
	}
	if (job->id) {
		k_free(job->id);
		job->id = NULL;
	}
}

int fota_client_get_pending_job(struct fota_client_mgmt_job * const job)
{
	if (!job) {
		return -EINVAL;
	}

	int fd;
	int ret;
	struct addrinfo *addr_info = NULL;
	struct http_user_data job_data = { .type = HTTP_REQ_TYPE_GET_JOB };
	struct http_request req;
	size_t buff_size;
	char * jwt = NULL;
	char * url = NULL;
	char * content =  NULL;
	char * device_id = get_device_id_string();

	memset(job,0,sizeof(*job));
	job_data.data.job = job;

	if (!device_id) {
		return -ENXIO;
		goto clean_up;
	}

	ret = generate_jwt(device_id,&jwt);
	if (ret < 0){
		printk("Failed to generate JWT: %d\n", ret);
		goto clean_up;
	}
	printk("JWT: %s\n", jwt);

	/* Format API URL with device ID */
	buff_size = sizeof(API_GET_JOB_URL_TEMPLATE) + strlen(device_id);
	url = k_calloc(buff_size, 1);
	if (!url) {
		ret = -ENOMEM;
	}
	ret = snprintk(url, buff_size, API_GET_JOB_URL_TEMPLATE, device_id);
	if (ret < 0 || ret >= buff_size) {
		printk("Could not format URL\n");
		return -ENOBUFS;
	}

	/* Format API content with JWT */
	buff_size = sizeof(API_GET_JOB_TEMPLATE) + strlen(jwt);
	content = k_calloc(buff_size,1);
	if (!content) {
		ret = -ENOMEM;
	}
	ret = snprintk(content, buff_size, API_GET_JOB_TEMPLATE, jwt);
	if (ret < 0 || ret >= buff_size) {
		printk("Could not format HTTP content\n");
		return -ENOBUFS;
	}

	printk("URL: %s\n", url);
	printk("Content: %s\n", content);

	/* Init HTTP request */
	memset(&req, 0, sizeof(req));
	req.method = HTTP_GET;
	req.url = url;
	req.host = API_HOSTNAME;
	req.protocol = "HTTP/1.1";
	req.content_type_value = content;
	req.response = response_cb;
	req.recv_buf = http_rx_buf;
	req.recv_buf_len = sizeof(http_rx_buf);
	http_resp_rcvd = false;
	http_resp_status = HTTP_STATUS_NONE;

	ret = do_connect(&fd, &addr_info, API_HOSTNAME, API_PORT);
	if (ret) {
		goto clean_up;
	}

	ret = http_client_req(fd, &req, JITP_HTTP_TIMEOUT_MS, &job_data);
	printk("http_client_req returned %d\n", ret);

	if (ret < 0) {
		ret = -EIO;
	} else {
		ret = 0;
		if (http_resp_status == HTTP_STATUS_NOT_FOUND) {
			/* No pending job */
		} else if (http_resp_status == HTTP_STATUS_OK) {
			job->status = AWS_JOBS_IN_PROGRESS;
			printk("job id: %s\n", job->id);
			printk("job host: %s\n", job->host);
			printk("job path: %s\n", job->path);
		} else {
			printk("Error: HTTP status %d\n", http_resp_status);
			ret = -ENODATA;
		}
	}

clean_up:
	if (addr_info) {
		freeaddrinfo(addr_info);
	}
	if (fd) {
		(void)close(fd);
	}
	if (jwt) {
		k_free(jwt);
	}
	if (device_id) {
		k_free(device_id);
	}
	if (url) {
		k_free(url);
	}
	if (content) {
		k_free(content);
	}

	return ret;
}

int fota_client_update_job(const struct fota_client_mgmt_job * job)
{
	if ( !job || !job->id ) {
		return -EINVAL;
	} else if (job->status >= JOB_STATUS_STRING_COUNT) {
		return -ENOENT;
	}

	int fd;
	int ret;
	struct addrinfo *addr_info = NULL;
	struct http_user_data job_data = { .type = HTTP_REQ_TYPE_UPDATE_JOB };
	struct http_request req;
	size_t buff_size;
	char * jwt = NULL;
	char * url = NULL;
	char * content =  NULL;
	char * payload = NULL;

	ret = generate_jwt(NULL,&jwt);
	if (ret < 0){
		printk("Failed to generate JWT: %d\n", ret);
		goto clean_up;
	}
	printk("JWT: %s\n", jwt);

	/* Format API URL with job ID */
	buff_size = sizeof(API_UPDATE_JOB_URL_PREFIX) + strlen(job->id);
	url = k_calloc(buff_size, 1);
	if (!url) {
		ret = -ENOMEM;
	}
	ret = snprintk(url, buff_size, "%s%s",
		       API_UPDATE_JOB_URL_PREFIX, job->id);
	if (ret < 0 || ret >= buff_size) {
		printk("Could not format URL\n");
		return -ENOBUFS;
	}

	/* Format API content with JWT */
	buff_size = sizeof(API_UPDATE_JOB_TEMPLATE) + strlen(jwt);
	content = k_calloc(buff_size,1);
	if (!content) {
		ret = -ENOMEM;
	}
	ret = snprintk(content, buff_size, API_UPDATE_JOB_TEMPLATE, jwt);
	if (ret < 0 || ret >= buff_size) {
		printk("Could not format HTTP content\n");
		return -ENOBUFS;
	}

	/* Create payload */
	buff_size = sizeof(API_UPDATE_JOB_BODY_TEMPLATE) +
		    strlen(job_status_strings[job->status]);
	if (job->status_details) {
		buff_size += strlen(job->status_details);
	}
	payload = k_calloc(buff_size,1);
	if (!payload) {
		ret = -ENOMEM;
	}
	ret = snprintk(payload, buff_size, API_UPDATE_JOB_BODY_TEMPLATE,
		       job_status_strings[job->status],
		       (job->status_details ? job->status_details : ""));
	if (ret < 0 || ret >= buff_size) {
		printk("Could not format HTTP payload\n");
		return -ENOBUFS;
	}

	printk("URL: %s\n", url);
	printk("Content: %s\n", content);
	printk("Payload: %s\n", payload);

	/* Init HTTP request */
	memset(&req, 0, sizeof(req));
	req.method = HTTP_PATCH;
	req.url = url;
	req.host = API_HOSTNAME;
	req.protocol = "HTTP/1.1";
	req.content_type_value = content;
	req.payload = payload;
	req.payload_len = strlen(payload);
	req.response = response_cb;
	req.recv_buf = http_rx_buf;
	req.recv_buf_len = sizeof(http_rx_buf);
	http_resp_rcvd = false;
	http_resp_status = HTTP_STATUS_NONE;

	ret = do_connect(&fd, &addr_info, API_HOSTNAME, API_PORT);
	if (ret) {
		goto clean_up;
	}

	ret = http_client_req(fd, &req, API_HTTP_TIMEOUT_MS, &job_data);
	printk("http_client_req returned %d\n", ret);

	if (ret < 0) {
		ret = -EIO;
	} else {
		ret = 0;
		if (http_resp_status == HTTP_STATUS_OK) {
			printk("Job status updated.\n");
		} else {
			printk("Error: HTTP status %d\n", http_resp_status);
			ret = -ENODATA;
		}
	}

clean_up:
	if (addr_info) {
		freeaddrinfo(addr_info);
	}
	if (fd) {
		(void)close(fd);
	}
	if (jwt) {
		k_free(jwt);
	}
	if (url) {
		k_free(url);
	}
	if (content) {
		k_free(content);
	}
	if (payload) {
		k_free(payload);
	}

	return ret;
}

static int generate_jwt(const char * const device_id, char ** jwt_out)
{
	if (!jwt_out)
	{
		return -EINVAL;
	}

	char jwt_payload[JWT_PAYLOAD_BUFF_SIZE];
	uint8_t jwt_sig[TC_SHA256_DIGEST_SIZE];
	int ret;
	char * jwt_buff;
	char * jwt_sig_b64;
	char * jwt_payload_b64;
	char * dev_id = NULL;
	size_t jwt_len = 0;

	*jwt_out = NULL;

	/* Get device ID if it was not provided */
	if (!device_id) {
		dev_id = get_device_id_string();
		if (!dev_id) {
			printk("Could get device ID string\n");
			return -ENODEV;
		}
	}

	/* Add device ID to JWT payload */
	ret = snprintk(jwt_payload, sizeof(jwt_payload),
		       JWT_PAYLOAD_TEMPLATE,
		       device_id ? device_id : dev_id);
	if (dev_id) {
		k_free(dev_id);
		dev_id = NULL;
	}
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

	/* NULL terminate at first '=' pad character */
	found = strchr(base64_string, '=');
	if (found) {
		*found = '\0';
	}
}

static void response_cb(struct http_response *rsp,
			enum http_final_call final_data,
			void *user_data)
{
	struct http_user_data * usr = NULL;

	if (user_data) {
		usr = (struct http_user_data *)user_data;
	}

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

		http_resp_rcvd = true;

		if (rsp->data_len && rsp->body_found) {
			printk("BODY: %s\n", rsp->body_start);
		}
		else if (rsp->body_found && !rsp->body_start) {
			printk("RCV BUFF: %s\n", rsp->recv_buf);
		}

		/* TODO: handle all statuses returned from API */
		if (strncmp(rsp->http_status,"Not Found", HTTP_STATUS_STR_SIZE) == 0) {
			http_resp_status = HTTP_STATUS_NOT_FOUND;
		} else if (strncmp(rsp->http_status,"Forbidden", HTTP_STATUS_STR_SIZE) == 0) {
			http_resp_status = HTTP_STATUS_FORBIDDEN;
		} else if (strncmp(rsp->http_status,"OK", HTTP_STATUS_STR_SIZE) == 0) {
			http_resp_status = HTTP_STATUS_OK;
		} else if (strncmp(rsp->http_status,"Unauthorized", HTTP_STATUS_STR_SIZE) == 0) {
			http_resp_status = HTTP_STATUS_UNAUTH;
		} else if (strncmp(rsp->http_status,"Bad Request", HTTP_STATUS_STR_SIZE) == 0) {
			http_resp_status = HTTP_STATUS_BAD_REQ;
		} else {
			http_resp_status = HTTP_STATUS_UNHANDLED;
		}
		if (!usr) {
			printk("Response to unknown request: %s\n",
			       rsp->http_status);
			return;
		}

		printk("Response to request type %d: %s\n",
		       usr->type, rsp->http_status);

		switch (usr->type) {
		case HTTP_REQ_TYPE_GET_JOB:
			// TODO: error handling
			parse_pending_job_response(rsp->recv_buf,
						   usr->data.job);
			break;
		case HTTP_REQ_TYPE_PROVISION:
		case HTTP_REQ_TYPE_UPDATE_JOB:
		default:
			break;
		}

	}
}

int parse_pending_job_response(const char * const resp_buff,
			       struct fota_client_mgmt_job * const job)
{
	char * start;
	char * end;
	size_t len;

	// TODO: error handling / cleanup

	job->host = k_calloc(sizeof(API_HOSTNAME),1);
	if (!job->host) {
		return -ENOMEM;
	}
	strncpy(job->host,API_HOSTNAME,
		sizeof(API_HOSTNAME));

	start = strstr(resp_buff,JOB_ID_BEGIN_STR);
	if (!start) {
		return -ENOMSG;
	}

	start += strlen(JOB_ID_BEGIN_STR);
	end = strstr(start,JOB_ID_END_STR);
	if (!end) {
		return -ENOMSG;
	}

	len = end - start;
	job->id = k_calloc(len + 1,1);
	strncpy(job->id,start,len);

	// Get URI/path
	start = strstr(resp_buff,FW_URI_BEGIN_STR);
	if (!start) {
		return -ENOMSG;
	}

	start += strlen(FW_URI_BEGIN_STR);
	end = strstr(start,FW_URI_END_STR);
	if (!end) {
		return -ENOMSG;
	}

	len = end - start;
	job->path = k_calloc(sizeof(FW_PATH_PREFIX) + len,1);
	if (!job->path) {
		return -ENOMEM;
	}

	strncpy(job->path,
		FW_PATH_PREFIX,
		sizeof(FW_PATH_PREFIX));
	strncpy(job->path + strlen(FW_PATH_PREFIX),
		start,len);

	return 0;
}

/* Setup TLS options on a given socket */
int tls_setup(int fd, const char * const tls_hostname)
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

	if (tls_hostname) {
		err = setsockopt(fd, SOL_TLS, TLS_HOSTNAME, tls_hostname,
				 strlen(tls_hostname));
		if (err) {
			printk("Failed to setup TLS hostname, err %d\n", errno);
			return err;
		}
	}
	return 0;
}