/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <string.h>
#include <zephyr.h>
#include <stdlib.h>
#include <stdio.h>
#include <net/socket.h>
#include <net/net_ip.h>
#include <modem/nrf_modem_lib.h>
#include <net/tls_credentials.h>
#include <modem/modem_key_mgmt.h>
#include <net/http_client.h>
#include <net/http_parser.h>
#include <net/nrf_cloud_rest.h>
#include <sys/base64.h>
#include <logging/log.h>

#include "nrf_cloud_codec.h"

LOG_MODULE_REGISTER(nrf_cloud_rest, CONFIG_NRF_CLOUD_REST_LOG_LEVEL);

#define HTTPS_PORT 443
#define BASE64_PAD_CHAR '='
#define GET_BASE64_LEN(n) ((((4 * n) / 3) + 3) & ~3)

#define AUTH_HDR_BEARER_TEMPLATE	"Authorization: Bearer %s\r\n"
#define HOST_HDR_TEMPLATE		"Host: %s\r\n"
#define HDR_ACCEPT_APP_JSON		"accept: application/json\r\n"
#define CONTENT_TYPE_TXT_PLAIN		"text/plain"
#define CONTENT_TYPE_ALL		"*/*"
#define CONTENT_TYPE_APP_JSON		"application/json"

#define API_GET_FOTA_URL_TEMPLATE	"/v1/fota-job-executions/%s/latest"
#define API_UPDATE_FOTA_URL_TEMPLATE	"/v1/fota-job-executions/%s/%s"
#define API_UPDATE_FOTA_BODY_TEMPLATE	"{\"status\":\"%s\"}"
#define API_GET_SINGLECELL_TEMPLATE	"/v1/location/single-cell?deviceIdentifier=%s&mcc=%u&mnc=%u&tac=%u&eci=%u&format=json"

#define API_GET_AGPS_BASE		"/v1/location/agps?deviceIdentifier=%s"
#define API_GET_AGPS_REQ_TYPE		"&requestType=%s"
#define API_GET_AGPS_NET_INFO		"&mcc=%u&mnc=%u&tac=%u&eci=%u"
#define API_GET_AGPS_CUSTOM_TYPE	"&customTypes=%s"
#define AGPS_NET_INFO_PRINT_SZ		(3 + 3 + 5 + 10)
#define AGPS_REQ_TYPE_STR_CUSTOM	"custom"
#define AGPS_REQ_TYPE_STR_LOC		"rtLocation"
#define AGPS_REQ_TYPE_STR_ASSIST	"rtAssistance"
/* Custom type format is a comma separated list of
 * @ref enum gps_agps_type digits
 * digits.
 */
#define AGPS_CUSTOM_TYPE_STR_SZ		(9 * 2)

#define HTTP_PROTOCOL "HTTP/1.1"
#define SOCKET_PROTOCOL IPPROTO_TLS_1_2

/** @brief Mapping of enum to strings for Job Execution Status. */
static const char *const job_status_strings[] = {
	[NRF_CLOUD_FOTA_QUEUED]      = "QUEUED",
	[NRF_CLOUD_FOTA_IN_PROGRESS] = "IN_PROGRESS",
	[NRF_CLOUD_FOTA_FAILED]      = "FAILED",
	[NRF_CLOUD_FOTA_SUCCEEDED]   = "SUCCEEDED",
	[NRF_CLOUD_FOTA_TIMED_OUT]   = "TIMED_OUT",
	[NRF_CLOUD_FOTA_REJECTED]    = "REJECTED",
	[NRF_CLOUD_FOTA_CANCELED]    = "CANCELLED",
	[NRF_CLOUD_FOTA_DOWNLOADING] = "DOWNLOADING",
};
#define JOB_STATUS_STRING_COUNT (sizeof(job_status_strings) / \
				 sizeof(*job_status_strings))

/** @brief Mapping of enum to strings for AGPS request type. */
static const char *const agps_req_type_strings[] = {
	[NRF_CLOUD_REST_AGPS_REQ_ASSISTANCE]	= AGPS_REQ_TYPE_STR_ASSIST,
	[NRF_CLOUD_REST_AGPS_REQ_LOCATION]	= AGPS_REQ_TYPE_STR_LOC,
	[NRF_CLOUD_REST_AGPS_REQ_CUSTOM]	= AGPS_REQ_TYPE_STR_CUSTOM,
};

/** @brief nRF Cloud REST API data */
struct nrf_cloud_rest_api_data
{
	/** JWT to use for authentication */
	struct jwt_data * jwt;
	/** API token for auth header (if not using JWT) */
	char *api_token;

	char *rsp_buf;
	size_t rsp_buf_sz;
};

static int http_on_status_cb(struct http_parser * parser, const char *at,
			     size_t length);

static const struct http_parser_settings parser_settings = {
	.on_status = http_on_status_cb
};

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

	/* NULL terminate at first pad character */
	found = strchr(base64_string, BASE64_PAD_CHAR);
	if (found) {
		*found = '\0';
	}
}

int base64_url_unformat(char * const base64url_string)
{
	if (base64url_string == NULL) {
		return -EINVAL;
	}

	char * found = NULL;

	/* replace '-' with "+" */
	for(found = base64url_string; (found = strchr(found,'-'));) {
		*found = '+';
	}

	/* replace '_' with "/" */
	for(found = base64url_string; (found = strchr(found,'_'));) {
		*found = '/';
	}

	/* return number of padding chars required */
	return (strlen(base64url_string) % 4);
}

static int http_on_status_cb(struct http_parser * parser, const char *at,
			     size_t length)
{
	LOG_DBG("http_on_status_cb");
	return 0;
}

static void http_response_cb(struct http_response *rsp,
			enum http_final_call final_data,
			void *user_data)
{
	struct nrf_cloud_rest_context * rest_ctx = NULL;

	if (user_data) {
		rest_ctx = (struct nrf_cloud_rest_context *)user_data;
	}

	if (rest_ctx && rsp->body_found && rsp->body_start) {
		rest_ctx->response = rsp->body_start;
	}

	if (final_data == HTTP_DATA_FINAL) {
		LOG_DBG("HTTP: All data received, status: %u %s",
			rsp->http_status_code,
			log_strdup(rsp->http_status));

		if (!rest_ctx) {
			LOG_WRN("User data not provided...");
			return;
		}

		if (rest_ctx) {
			rest_ctx->status = rsp->http_status_code;
			rest_ctx->response_len = rsp->content_length;
		}
	}
}

static int generate_auth_header(const char * const tok, char ** auth_hdr_out)
{
	if (!tok || !auth_hdr_out)
	{
		return -EINVAL;
	}

	int ret;
	size_t buff_size = sizeof(AUTH_HDR_BEARER_TEMPLATE) + strlen(tok);

	*auth_hdr_out = k_calloc(buff_size,1);
	if (!*auth_hdr_out) {
		return -ENOMEM;
	}
	ret = snprintk(*auth_hdr_out, buff_size, AUTH_HDR_BEARER_TEMPLATE, tok);
	if (ret < 0 || ret >= buff_size) {
		k_free(*auth_hdr_out);
		*auth_hdr_out = NULL;
		return -ENOBUFS;
	}

	return 0;
}

int tls_setup(int fd, const char * const tls_hostname)
{
	int err;
	int verify;
	const sec_tag_t tls_sec_tag[] = {
		CONFIG_NRF_CLOUD_SEC_TAG,
	};

	enum {
		NONE = 0,
		OPTIONAL = 1,
		REQUIRED = 2,
	};

	verify = REQUIRED;

	err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	if (err) {
		LOG_ERR("Failed to setup peer verification, error: %d", errno);
		return err;
	}

	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag,
			 sizeof(tls_sec_tag));
	if (err) {
		LOG_ERR("Failed to setup TLS sec tag, error: %d", errno);
		return err;
	}

	if (tls_hostname) {
		err = setsockopt(fd, SOL_TLS, TLS_HOSTNAME, tls_hostname,
				 strlen(tls_hostname));
		if (err) {
			LOG_ERR("Failed to setup TLS hostname, error: %d", errno);
			return err;
		}
	}
	return 0;
}

static int socket_timeouts_set(int fd)
{
	int err;

	/* Set socket timeouts (send TO also affects TCP connect) */
	struct timeval timeout = {
		.tv_sec = 60,
		.tv_usec = 0
	};

	err = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
			 &timeout, sizeof(timeout));
	if (err) {
		LOG_ERR("Failed to set socket send timeout, error: %d", errno);
		return err;
	}

	err = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
			 &timeout, sizeof(timeout));
	if (err) {
		LOG_ERR("Failed to set socket recv timeout, error: %d/n", errno);
		return err;
	}

	return 0;
}

static int do_connect(int * const fd, const char * const hostname,
		      const uint16_t port_num, const char * const ip_address)
{
	int ret;
	struct addrinfo *addr_info;
	/* Use IP to connect if provided, always use hostname for TLS (SNI) */
	const char * const connect_addr = ip_address ? ip_address : hostname;

	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_next =  NULL,
	};

	/* Make sure fd is always initialized when this function is called */
	*fd = -1;

	ret = getaddrinfo(connect_addr, NULL, &hints, &addr_info);
	if (ret) {
		LOG_ERR("getaddrinfo() failed, error: %d", errno);
		return -EFAULT;
	} else {
		char peer_addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &net_sin(addr_info->ai_addr)->sin_addr,
			  peer_addr, INET_ADDRSTRLEN);
		LOG_DBG("getaddrinfo() %s", log_strdup(peer_addr));
	}

	((struct sockaddr_in *)addr_info->ai_addr)->sin_port = htons(port_num);

	*fd = socket(AF_INET, SOCK_STREAM, SOCKET_PROTOCOL);
	if (*fd == -1) {
		LOG_ERR("Failed to open socket, error: %d", errno);
		ret = -ENOTCONN;
		goto error_clean_up;
	}

	ret = tls_setup(*fd, hostname);
	if (ret) {
		ret = -EACCES;
		goto error_clean_up;
	}

	ret = socket_timeouts_set(*fd);
	if (ret) {
		LOG_ERR("Failed to set socket timeouts, error: %d", errno);
		ret = -EINVAL;
		goto error_clean_up;
	}

	LOG_DBG("Connecting to %s", log_strdup(connect_addr));

	ret = connect(*fd, addr_info->ai_addr, sizeof(struct sockaddr_in));
	if (ret) {
		LOG_ERR("Failed to connect socket, error: %d", errno);
		ret = -ECONNREFUSED;
		goto error_clean_up;
	} else {
		freeaddrinfo(addr_info);
		return 0;
	}

error_clean_up:
	freeaddrinfo(addr_info);
	if (*fd > -1) {
		(void)close(*fd);
		*fd = -1;
	}
	return ret;
}

static void close_connection(struct nrf_cloud_rest_context * const rest_ctx)
{
	if (rest_ctx && !rest_ctx->keep_alive && rest_ctx->connect_socket >= 0) {
		(void)close(rest_ctx->connect_socket);
		rest_ctx->connect_socket = -1;
	}
}

static int do_api_call(struct http_request * http_req, struct nrf_cloud_rest_context * const rest_ctx)
{
	int err = 0;

	if (rest_ctx->connect_socket < 0) {
		err = do_connect(&rest_ctx->connect_socket,
				 http_req->host,
				 HTTPS_PORT,
				 NULL);
		if (err) {
			return err;
		}
	}

	/* Assign the user provided receive buffer into the http request */
	http_req->recv_buf	= rest_ctx->rx_buf;
	http_req->recv_buf_len	= rest_ctx->rx_buf_len;

	memset(http_req->recv_buf, 0, http_req->recv_buf_len);

	rest_ctx->response	= NULL;
	rest_ctx->response_len	= 0;

	err = http_client_req(rest_ctx->connect_socket,
			      http_req,
			      rest_ctx->timeout_ms,
			      rest_ctx);

	if (err < 0) {
		LOG_ERR("http_client_req() error: %d", err);
		err = -EIO;
	}

	err = 0;

	close_connection(rest_ctx);

	return err;
}

static void init_request(struct http_request * const req, const enum http_method meth,
			 const char * const content_type)
{
	memset(req, 0, sizeof(struct http_request));

	req->host 		= CONFIG_NRF_CLOUD_REST_HOST_NAME;
	req->protocol 		= HTTP_PROTOCOL;

	req->response		= http_response_cb;
	req->method		= meth;
	req->content_type_value	= content_type;

	req->http_cb		= &parser_settings;
}

int nrf_cloud_rest_update_fota_job(struct nrf_cloud_rest_context * const rest_ctx,
	const char * const device_id, const char * const job_id,
	const enum nrf_cloud_fota_status status)
{
	__ASSERT_NO_MSG(rest_ctx != NULL);
	__ASSERT_NO_MSG(device_id != NULL);
	__ASSERT_NO_MSG(job_id != NULL);
	__ASSERT_NO_MSG(status < JOB_STATUS_STRING_COUNT);

	int ret;
	size_t buff_sz;
	char * auth_hdr = NULL;
	char * url = NULL;
	char * payload = NULL;
	struct http_request http_req;

	init_request(&http_req, HTTP_PATCH, CONTENT_TYPE_APP_JSON);

	/* Format API URL with device and job ID */
	buff_sz = sizeof(API_UPDATE_FOTA_URL_TEMPLATE) +
		    strlen(device_id) + strlen(job_id);
	url = k_calloc(buff_sz, 1);
	if (!url) {
		ret = -ENOMEM;
		goto clean_up;
	}
	http_req.url = url;

	ret = snprintk(url, buff_sz, API_UPDATE_FOTA_URL_TEMPLATE,
		       device_id, job_id);
	if (ret < 0 || ret >= buff_sz) {
		LOG_ERR("Could not format URL");
		ret = -ENOBUFS;
		goto clean_up;
	}

	LOG_DBG("URL: %s", log_strdup(http_req.url));

	/* Format auth header */
	ret = generate_auth_header(rest_ctx->auth, &auth_hdr);
	if (ret) {
		LOG_ERR("Could not format HTTP auth header");
		goto clean_up;
	}
	char * headers[] = { HDR_ACCEPT_APP_JSON,
			     auth_hdr,
			     NULL };

	http_req.header_fields = (const char **)headers;

	/* Format payload */
	buff_sz = sizeof(API_UPDATE_FOTA_BODY_TEMPLATE) +
		  strlen(job_status_strings[status]);
	payload = k_calloc(buff_sz, 1);
	if (!payload) {
		ret = -ENOMEM;
		goto clean_up;
	}

	ret = snprintk(payload, buff_sz, API_UPDATE_FOTA_BODY_TEMPLATE,
		       job_status_strings[status]);
	if (ret < 0 || ret >= buff_sz) {
		LOG_ERR("Could not format payload");
		ret = -ENOBUFS;
		goto clean_up;
	}
	http_req.payload = payload;
	http_req.payload_len = strlen(http_req.payload);
	LOG_DBG("Payload: %s", log_strdup(http_req.payload));

	/* Make REST call */
	ret = do_api_call(&http_req, rest_ctx);
	if (ret) {
		ret = -EIO;
		goto clean_up;
	}

	LOG_DBG("API status: %d", rest_ctx->status);
	if (rest_ctx->status != HTTP_STATUS_OK) {
		ret = -EBADMSG;
		goto clean_up;
	}

	LOG_DBG("API call response len: %u bytes", rest_ctx->response_len);

clean_up:
	if (url) {
		k_free(url);
	}
	if (auth_hdr) {
		k_free(auth_hdr);
	}
	if (payload) {
		k_free(payload);
	}

	close_connection(rest_ctx);

	return ret;
}

int nrf_cloud_rest_get_fota_job(struct nrf_cloud_rest_context * const rest_ctx,
	const char * const device_id, struct nrf_cloud_fota_job_info *const job)
{
	__ASSERT_NO_MSG(rest_ctx != NULL);
	__ASSERT_NO_MSG(device_id != NULL);

	int ret;
	size_t url_sz;
	char * auth_hdr = NULL;
	char * url = NULL;
	struct http_request http_req;

	init_request(&http_req, HTTP_GET, CONTENT_TYPE_ALL);

	/* Format API URL with device ID */
	url_sz = sizeof(API_GET_FOTA_URL_TEMPLATE) +
		    strlen(device_id);
	url = k_calloc(url_sz, 1);
	if (!url) {
		ret = -ENOMEM;
		goto clean_up;
	}
	http_req.url = url;

	ret = snprintk(url, url_sz, API_GET_FOTA_URL_TEMPLATE, device_id);
	if (ret < 0 || ret >= url_sz) {
		LOG_ERR("Could not format URL");
		ret = -ENOBUFS;
		goto clean_up;
	}

	LOG_DBG("URL: %s", log_strdup(http_req.url));

	/* Format auth header */
	ret = generate_auth_header(rest_ctx->auth, &auth_hdr);
	if (ret) {
		LOG_ERR("Could not format HTTP auth header");
		goto clean_up;
	}
	char * headers[] = { HDR_ACCEPT_APP_JSON,
			     auth_hdr,
			     NULL };

	http_req.header_fields = (const char **)headers;

	/* Make REST call */
	ret = do_api_call(&http_req, rest_ctx);
	if (ret) {
		ret = -EIO;
		goto clean_up;
	}

	LOG_DBG("API status: %d", rest_ctx->status);
	if (rest_ctx->status != HTTP_STATUS_OK &&
	    rest_ctx->status != HTTP_STATUS_NOT_FOUND) {
		ret = -EBADMSG;
		goto clean_up;
	}

	LOG_DBG("API call response len: %u bytes", rest_ctx->response_len);
	if (!job) {
		ret = 0;
		goto clean_up;
	}

	job->type = NRF_CLOUD_FOTA_TYPE__INVALID;

	if (rest_ctx->status == HTTP_STATUS_OK) {
		ret = nrf_cloud_parse_rest_fota_execution(rest_ctx->response, job);
		if (ret) {
			LOG_ERR("Failed to parse job execution response: error: %d", ret);
		}
	}

clean_up:
	if (url) {
		k_free(url);
	}
	if (auth_hdr) {
		k_free(auth_hdr);
	}

	close_connection(rest_ctx);

	return ret;
}

int nrf_cloud_rest_get_single_cell_loc(struct nrf_cloud_rest_context * const rest_ctx,
	struct nrf_cloud_rest_single_cell_request const * const request,
	struct cell_based_loc_data * const result)
{
	__ASSERT_NO_MSG(rest_ctx != NULL);
	__ASSERT_NO_MSG(request != NULL);

	int ret;
	size_t url_sz;
	char * auth_hdr = NULL;
	char * url = NULL;
	struct http_request http_req;
	char * dev_id = request->device_id ? request->device_id : "na";

	init_request(&http_req, HTTP_GET, CONTENT_TYPE_TXT_PLAIN);

	/* Format API URL with device ID and cell data */
	url_sz = sizeof(API_GET_SINGLECELL_TEMPLATE) +
		    strlen(dev_id) + 3 + 3 + 5 + 11;
	url = k_calloc(url_sz, 1);
	if (!url) {
		ret = -ENOMEM;
		goto clean_up;
	}
	http_req.url = url;

	ret = snprintk(url, url_sz, API_GET_SINGLECELL_TEMPLATE,
		       dev_id, request->net_info.mcc, request->net_info.mnc,
		       request->net_info.area_code, request->net_info.cell_id);
	if (ret < 0 || ret >= url_sz) {
		LOG_ERR("Could not format URL");
		ret = -ENOBUFS;
		goto clean_up;
	}

	LOG_DBG("URL: %s", log_strdup(http_req.url));

	/* Format auth header */
	ret = generate_auth_header(rest_ctx->auth, &auth_hdr);
	if (ret) {
		LOG_ERR("Could not format HTTP auth header");
		goto clean_up;
	}
	char * headers[] = { HDR_ACCEPT_APP_JSON,
			     auth_hdr,
			     NULL };

	http_req.header_fields = (const char **)headers;

	/* Make REST call */
	ret = do_api_call(&http_req, rest_ctx);
	if (ret) {
		ret = -EIO;
		goto clean_up;
	}

	if (rest_ctx->status == HTTP_STATUS_OK) {
		ret = 0;
		if (rest_ctx->rx_buf && rest_ctx->rx_buf_len) {
			LOG_DBG("API call response len: %u bytes",
				rest_ctx->response_len);
		}
	} else {
		ret = -EBADMSG;
		goto clean_up;
	}

	if (result) {
		ret = nrf_cloud_parse_cell_location(rest_ctx->response,
						    CELL_LOC_TYPE_SINGLE,
						    result);
	}

clean_up:
	if (url) {
		k_free(url);
	}
	if (auth_hdr) {
		k_free(auth_hdr);
	}

	close_connection(rest_ctx);

	return ret;
}

int nrf_cloud_rest_get_multi_cell_loc(struct nrf_cloud_rest_context * const rest_ctx)
{
	return 0;
}

/* AGPS_TYPE_PRINT macro assumes single digit values, check for the rare case that the
 * enum is modified.
 */
BUILD_ASSERT((GPS_AGPS_UTC_PARAMETERS <= 9) && (GPS_AGPS_EPHEMERIDES <= 9) &&
	     (GPS_AGPS_ALMANAC <= 9) && (GPS_AGPS_KLOBUCHAR_CORRECTION <= 9) &&
	     (GPS_AGPS_NEQUICK_CORRECTION <= 9) && (GPS_AGPS_INTEGRITY <= 9) &&
	     (GPS_AGPS_LOCATION <= 9) && (GPS_AGPS_GPS_SYSTEM_CLOCK_AND_TOWS <= 9),
	     "AGPS enumeration values have changed, update format_agps_custom_types_str()");

#define AGPS_TYPE_PRINT(buf, type)		\
	if (pos != 0) {				\
		buf[pos++] = ',';		\
	}					\
	buf[pos++] = (char)('0' + type);

static int format_agps_custom_types_str(struct gps_agps_request const *const req, char *const types_buf)
{
	__ASSERT_NO_MSG(req != NULL);
	__ASSERT_NO_MSG(types_buf != NULL);

	int pos = 0;

	if (req->utc) {
		AGPS_TYPE_PRINT(types_buf, GPS_AGPS_UTC_PARAMETERS);
	}
	if (req->sv_mask_ephe) {
		AGPS_TYPE_PRINT(types_buf, GPS_AGPS_EPHEMERIDES);
	}
	if (req->sv_mask_alm) {
		AGPS_TYPE_PRINT(types_buf, GPS_AGPS_ALMANAC);
	}
	if (req->klobuchar) {
		AGPS_TYPE_PRINT(types_buf, GPS_AGPS_KLOBUCHAR_CORRECTION);
	}
	if (req->nequick) {
		AGPS_TYPE_PRINT(types_buf, GPS_AGPS_NEQUICK_CORRECTION);
	}
	if (req->system_time_tow) {
		AGPS_TYPE_PRINT(types_buf, GPS_AGPS_GPS_SYSTEM_CLOCK_AND_TOWS);
	}
	if (req->position) {
		AGPS_TYPE_PRINT(types_buf, GPS_AGPS_LOCATION);
	}
	if (req->integrity) {
		AGPS_TYPE_PRINT(types_buf, GPS_AGPS_INTEGRITY);
	}

	types_buf[pos] = '\0';

	return pos ? 0 : -EBADF;
}

int nrf_cloud_rest_get_agps_data(struct nrf_cloud_rest_context * const rest_ctx,
				 struct nrf_cloud_rest_agps_request const *const request)
{
	__ASSERT_NO_MSG(rest_ctx != NULL);
	__ASSERT_NO_MSG(request != NULL);

	int ret;
	size_t url_sz;
	size_t remain;
	size_t pos;
	char * auth_hdr = NULL;
	char * url = NULL;
	struct http_request http_req;
	char * dev_id = request->device_id ? request->device_id : "na";
	char const * req_type = NULL;
	char custom_types[AGPS_CUSTOM_TYPE_STR_SZ];

	if ((request->type == NRF_CLOUD_REST_AGPS_REQ_CUSTOM) &&
	    (request->agps_req == NULL)) {
		LOG_ERR("Custom request type requires AGPS request data");
		return -EINVAL;
	}

	init_request(&http_req, HTTP_GET, CONTENT_TYPE_TXT_PLAIN);

	/* Determine size of URL buffer and allocate */
	url_sz = sizeof(API_GET_AGPS_BASE) + strlen(dev_id);
	if (request->net_info) {
		url_sz += strlen(API_GET_AGPS_NET_INFO) + AGPS_NET_INFO_PRINT_SZ;
	}
	switch (request->type) {
		case NRF_CLOUD_REST_AGPS_REQ_CUSTOM:
			ret = format_agps_custom_types_str(request->agps_req,
							   custom_types);
			if (ret) {
				LOG_ERR("No AGPS types requested");
				return ret;
			}
			url_sz += strlen(API_GET_AGPS_CUSTOM_TYPE) +
				  strlen(custom_types);
			/* Fall-through */
		case NRF_CLOUD_REST_AGPS_REQ_LOCATION:
		case NRF_CLOUD_REST_AGPS_REQ_ASSISTANCE:
			req_type = agps_req_type_strings[request->type];
			url_sz += strlen(API_GET_AGPS_REQ_TYPE) + strlen(req_type);
			break;
		case NRF_CLOUD_REST_AGPS_REQ_UNSPECIFIED:
			break;

		default:
			return -EINVAL;
	}

	url = k_calloc(url_sz, 1);
	if (!url) {
		ret = -ENOMEM;
		goto clean_up;
	}
	http_req.url = url;

	/* Format API URL */
	ret = snprintk(url, url_sz, API_GET_AGPS_BASE, dev_id);
	if (ret < 0 || ret >= url_sz) {
		LOG_ERR("Could not format URL: device id");
		ret = -ENOBUFS;
		goto clean_up;
	}
	pos = ret;
	remain = url_sz - ret;

	if (req_type) {
		ret = snprintk(&url[pos], remain, API_GET_AGPS_REQ_TYPE, req_type);
		if (ret < 0 || ret >= remain) {
			LOG_ERR("Could not format URL: request type");
			ret = -ENOBUFS;
			goto clean_up;
		}
		pos += ret;
		remain -= ret;
	}

	if (request->type == NRF_CLOUD_REST_AGPS_REQ_CUSTOM) {
		ret = snprintk(&url[pos], remain, API_GET_AGPS_CUSTOM_TYPE, custom_types);
		if (ret < 0 || ret >= remain) {
			LOG_ERR("Could not format URL: custom types");
			ret = -ENOBUFS;
			goto clean_up;
		}
		pos += ret;
		remain -= ret;
	}

	if (request->net_info) {
		ret = snprintk(&url[pos], remain, API_GET_AGPS_NET_INFO,
			       request->net_info->mcc, request->net_info->mnc,
			       request->net_info->area_code, request->net_info->cell_id);
		if (ret < 0 || ret >= remain) {
			LOG_ERR("Could not format URL: network info");
			ret = -ENOBUFS;
			goto clean_up;
		}
		pos += ret;
		remain -= ret;
	}

	LOG_DBG("URL: %s", log_strdup(http_req.url));

	/* Format auth header */
	ret = generate_auth_header(rest_ctx->auth, &auth_hdr);
	if (ret) {
		LOG_ERR("Could not format HTTP auth header");
		goto clean_up;
	}
	char * headers[] = { HDR_ACCEPT_APP_JSON,
			     auth_hdr,
			     NULL };

	http_req.header_fields = (const char **)headers;

	/* Make REST call */
	ret = do_api_call(&http_req, rest_ctx);
	if (ret) {
		ret = -EIO;
		goto clean_up;
	}

	if (rest_ctx->status == HTTP_STATUS_OK) {
		ret = 0;
		if (rest_ctx->rx_buf && rest_ctx->rx_buf_len) {
			LOG_DBG("API call response len: %u bytes",
				rest_ctx->response_len);
		}
	} else if (rest_ctx->status == HTTP_STATUS_PARTIAL) {
		LOG_INF("TODO: GET REMAINING BYTES...");
	} else {
		ret = -EBADMSG;
		goto clean_up;
	}

	// TODO: return binary payload

clean_up:
	if (url) {
		k_free(url);
	}
	if (auth_hdr) {
		k_free(auth_hdr);
	}

	close_connection(rest_ctx);

	return ret;
}