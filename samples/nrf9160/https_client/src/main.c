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
#include <modem/lte_lc.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <modem/modem_key_mgmt.h>

#include <tinycrypt/hmac_prng.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/constants.h>

//#include <mbedtls/x509_crt.h>

#include <sys/base64.h>

#include "cJSON.h"
#include "cJSON_os.h"

#define DO_SECURE 	1
#define DO_GOOGLE 	0
#define DO_CERT_PROV 	1

#if DO_SECURE
	#define SOCKET_PROTOCOL IPPROTO_TLS_1_2
	#define API_PORT 443
#else
	#define SOCKET_PROTOCOL IPPROTO_TCP
	#define API_PORT 80
#endif

#if DO_CERT_PROV
	#define TLS_SEC_TAG 42
#else
	#define TLS_SEC_TAG 16842753
#endif

#if DO_GOOGLE
#define HTTP_HEAD                                                              \
		"HEAD / HTTP/1.1\r\n"                                                  \
		"Host: www.google.com:443\r\n"                                         \
		"Connection: close\r\n\r\n"
#define HOSTNAME "www.google.com"
#define HOSTNAME_TLS HOSTNAME
static const char cert[] = {
	#include "../cert/GlobalSign-Root-CA-R2" //"../cert/AmazonRootCA1"
};
#else
#define HTTP_HEAD "GET /v1/account HTTP/1.1\r\n" \
		  "Accept: application/json\r\n" \
		  "Authorization: Bearer 8d35cb3e165161e8a3b5a20ff3c48399a3f0b40a\r\n" \
		  "Connection: keep-alive\r\n" \
		  "Host: api.nrfcloud.com:443\r\n\r\n"
#define HOSTNAME "api.nrfcloud.com" //"a2n7tk1kp18wix-ats.iot.us-east-1.amazonaws.com" //
#define HOSTNAME_TLS "api.nrfcloud.com" //"a2n7tk1kp18wix-ats.iot.us-east-1.amazonaws.com" //"api.nrfcloud.com"
static const char cert[] = {
	#include "../cert/AmazonRootCA1" // "../cert/AmazonRootCA1" //#include "../cert/ClientCert"
};
#endif

#define HTTP_HEAD_LEN (sizeof(HTTP_HEAD) - 1)
#define HTTP_HDR_END "\r\n\r\n"
#define RECV_BUF_SIZE (2048*2)

#define SHARED_SECRET { \
	0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52, 0x66, 0x55, \
	0x6A, 0x58, 0x6E, 0x32, 0x72, 0x34, 0x75, 0x37, \
	0x78, 0x21, 0x41, 0x25, 0x44, 0x2A, 0x47, 0x2D, \
	0x4B, 0x61, 0x50, 0x64, 0x53, 0x67, 0x56, 0x6B }

static char shared_secret_hex[] = SHARED_SECRET;
static char * shared_secret = "294A404E635266556A586E327234753778214125442A472D4B6150645367566B";
static const char send_buf[] = HTTP_HEAD;
static char recv_buf[RECV_BUF_SIZE];

BUILD_ASSERT_MSG(sizeof(cert) < KB(4), "Certificate too large");


/* Initialize AT communications */
int at_comms_init(void)
{
	int err;

	err = at_cmd_init();
	if (err) {
		printk("Failed to initialize AT commands, err %d\n", err);
		return err;
	}

	printk("Trace cmd ret %d\n",
		at_cmd_write("AT%XMODEMTRACE=1,2\r\n",NULL,0, NULL));

	err = at_notif_init();
	if (err) {
		printk("Failed to initialize AT notifications, err %d\n", err);
		return err;
	}

	return 0;
}

#define CERT_BUFF_LEN 2048
/* Provision certificate to modem */
int cert_provision(void)
{
	int err;
	size_t cert_len = CERT_BUFF_LEN;
	unsigned char cert_buf[CERT_BUFF_LEN] = {0};
	//mbedtls_x509_crt x509_cert;
	//mbedtls_x509_crt_init( &x509_cert );
	printk("Getting PSK identity\n");
	//k_sleep( 2000 );
	err = modem_key_mgmt_read(16842753,
				  MODEM_KEY_MGMT_CRED_TYPE_IDENTITY,
				  cert_buf,
				  &cert_len);
	printk("Ret %d\n", err);
	//k_sleep( 2000 );
	if ( err == 0 ) {
		//cert_buf[cert_len+1] = 0;
		printk("PSK-identity %s\n", cert_buf);
		/*err = mbedtls_x509_crt_parse(&x509_cert, &cert_buf, cert_len);
		if (err == 0) {
			printk("CERT PARSED!");
		} else {
			printk("Failed to parse device cert %d", err);
		}*/
	} else {
		printk("Failed to read device cert %d", err);
	}
	//mbedtls_x509_crt_free(&x509_cert);
#if DO_CERT_PROV

	bool exists;
	u8_t unused;

	err = modem_key_mgmt_exists(TLS_SEC_TAG,
				    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				    &exists, &unused);
	if (err) {
		printk("Failed to check for certificates err %d\n", err);
		return err;
	}

	if (exists) {
		/* For the sake of simplicity we delete what is provisioned
		 * with our security tag and reprovision our certificate.
		 */
		err = modem_key_mgmt_delete(TLS_SEC_TAG,
					    MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN);
		if (err) {
			printk("Failed to delete existing certificate, err %d\n",
			       err);
		}
	}

	printk("Provisioning certificate\n");

	/*  Provision certificate to the modem */
	err = modem_key_mgmt_write(TLS_SEC_TAG,
				   MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN,
				   cert, sizeof(cert) - 1);
	if (err) {
		printk("Failed to provision certificate, err %d\n", err);
		return err;
	}
#endif
	return 0;
}

/* Setup TLS options on a given socket */
int tls_setup(int fd)
{
#if DO_SECURE
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
/*
	err = setsockopt(fd, SOL_TLS, TLS_HOSTNAME, HOSTNAME_TLS,
				 strlen(HOSTNAME_TLS));
	if (err) {
		printk("Failed to setup TLS hostname, err %d\n", errno);
		return err;
	}*/
#endif
	return 0;
}

void main(void)
{
	int err;
	int fd;
	char *p;
	int bytes;
	size_t off;
	struct addrinfo *res;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};
#if 0
	cJSON_Init();

	//printk("HTTPS client sample started\n\r");
	/*
	#define SHARED_SECRET = { \
		0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52, 0x66, 0x55, \
		0x6A, 0x58, 0x6E, 0x32, 0x72, 0x34, 0x75, 0x37, \
		0x78, 0x21, 0x41, 0x25, 0x44, 0x2A, 0x47, 0x2D, \
		0x4B, 0x61, 0x50, 0x64, 0x53, 0x67, 0x56, 0x6B }

	// SHARED_SECRET "294A404E635266556A586E327234753778214125442A472D4B6150645367566B"
	{
		"alg": "HS256",
		"typ": "JWT"
	}
	{
		"deviceIdentifier":"nrf-352656100300204"
		"tenantId":"851bd200-a89d-4076-9226-bb621828b4f3"
	}
*/
#define JWT_HDR_ALG_KEY   "alg"
#define JWT_HDR_ALG_VALUE "HS256"
#define JWT_HDR_TYP_KEY    "typ"
#define JWT_HDR_TYP_VALUE  "JWT"

#define JWT_PAYLOAD_DEV_ID_KEY    "deviceIdentifier"
#define JWT_PAYLOAD_DEV_ID_VALUE  "nrf-352656100300204"

#define JWT_PAYLOAD_TENNANT_KEY	  "tenantId"
#define JWT_PAYLOAD_TENNANT_VALUE "851bd200-a89d-4076-9226-bb621828b4f3"

	cJSON *jwt_hdr = cJSON_CreateObject();
	cJSON *jwt_payload = cJSON_CreateObject();

	cJSON *jwt_ten_id = cJSON_CreateString(JWT_PAYLOAD_TENNANT_VALUE);
	cJSON *jwt_dev_id = cJSON_CreateString(JWT_PAYLOAD_DEV_ID_VALUE);

	cJSON *jwt_alg_val = cJSON_CreateString(JWT_HDR_ALG_VALUE);
	cJSON *jwt_typ_val = cJSON_CreateString(JWT_HDR_TYP_VALUE);

	cJSON_AddItemToObject(jwt_payload, JWT_PAYLOAD_TENNANT_KEY, jwt_ten_id );
	cJSON_AddItemToObject(jwt_payload, JWT_PAYLOAD_DEV_ID_KEY, jwt_dev_id );

	cJSON_AddItemToObject(jwt_hdr, JWT_HDR_ALG_KEY, jwt_alg_val );
	cJSON_AddItemToObject(jwt_hdr, JWT_HDR_TYP_KEY, jwt_typ_val );

	struct tc_hmac_state_struct hmac;
	tc_hmac_init(&hmac);
	//if ( tc_hmac_set_key(&hmac, shared_secret, sizeof(shared_secret)) == TC_CRYPTO_SUCCESS )
	if ( tc_hmac_set_key(&hmac, shared_secret, strlen(shared_secret)) == TC_CRYPTO_SUCCESS )
	{
		printk("HMAC key initialized.\n");
	}

	char * hdr_str = cJSON_PrintUnformatted(jwt_hdr);
	char * payload_str = cJSON_PrintUnformatted(jwt_payload);

	printk("JSON hdr: \n");
	printk("%s\n", hdr_str);
	printk("JSON payload: \n");
	printk("%s\n", payload_str);

	printk("secret hex:\n");
		for (int i = 0; i < TC_SHA256_DIGEST_SIZE; ++i)
		{
			printk("%02X-",shared_secret_hex[i]);
		}
		printk("\n");

	char * secret_enc = NULL;
	char * trim_pad = NULL;
	size_t secret_enc_size = 0;
	int ret;
	base64_encode(NULL,0, &secret_enc_size,
			shared_secret, strlen(shared_secret));
		      //shared_secret, sizeof(shared_secret));
	secret_enc = k_calloc(secret_enc_size+1,1);
	ret = base64_encode(secret_enc,secret_enc_size, &secret_enc_size,
			shared_secret, strlen(shared_secret));
		      //shared_secret, sizeof(shared_secret));
	trim_pad =  strchr(secret_enc, '=');
	if (trim_pad) {
		*trim_pad = '\0';
	}
	printk("secret enc: %s\n", secret_enc);

	char * hdr_enc = NULL;
	size_t hdr_enc_size = 0;
	char * payload_enc = NULL;
	size_t payload_enc_size = 0;

	base64_encode(NULL,0, &hdr_enc_size,
		      hdr_str, strlen(hdr_str));
	hdr_enc = k_calloc(hdr_enc_size+1,1);
	ret = base64_encode(hdr_enc,hdr_enc_size, &hdr_enc_size,
		      hdr_str, strlen(hdr_str));
	trim_pad =  strchr(hdr_enc, '=');
	if (trim_pad) {
		*trim_pad = '\0';
	}

	base64_encode(NULL,0, &payload_enc_size,
		      payload_str, strlen(payload_str));
	payload_enc = k_calloc(payload_enc_size+1,1);
	ret = base64_encode(payload_enc,payload_enc_size, &payload_enc_size,
		      payload_str, strlen(payload_str));
	trim_pad =  strchr(payload_enc, '=');
	if (trim_pad) {
		*trim_pad = '\0';
	}

	printk("JWT: \n");
	printk("%s.%s\n", hdr_enc, payload_enc);
	cJSON_FreeString(hdr_str);
	cJSON_FreeString(payload_str);

	//size_t combined_buff_size = strlen(hdr_enc)+strlen(payload_enc)+1+1;
	//char * combined_str = k_calloc(combined_buff_size,1);
	//snprintk(combined_str,combined_buff_size,"%s.%s", hdr_enc,payload_enc);
	const char * const combined_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRJZCI6Ijg1MWJkMjAwLWE4OWQtNDA3Ni05MjI2LWJiNjIxODI4YjRmMyIsImRldmljZUlkZW50aWZpZXIiOiJucmYtMzUyNjU2MTAwMzAwMjA0In0";
	printk("Combined: %s\n", combined_str);

	if (tc_hmac_update(&hmac, combined_str, strlen(combined_str)) != TC_CRYPTO_SUCCESS) {
		printk("HMAC COMBINED update failed\n");
		goto clean_up;
	}
/*
	if (tc_hmac_update(&hmac, hdr_enc, strlen(hdr_enc)) != TC_CRYPTO_SUCCESS) {
		printk("HMAC HDR update failed\n");
		goto clean_up;
	}

	if (tc_hmac_update(&hmac, ".", 1) != TC_CRYPTO_SUCCESS) {
		printk("HMAC DOT update failed\n");
		goto clean_up;
	}

	if (tc_hmac_update(&hmac, payload_enc, strlen(payload_enc)) != TC_CRYPTO_SUCCESS) {
		printk("HMAC PAYLOAD update failed\n");
		goto clean_up;
	}
*/
	uint8_t hmac_res[TC_SHA256_DIGEST_SIZE];
	char * hmac_enc;
	size_t hmac_enc_size;

	if (tc_hmac_final(hmac_res,TC_SHA256_DIGEST_SIZE,&hmac) != TC_CRYPTO_SUCCESS) {
		printk("HMAC final failed\n");
		goto clean_up;
	}
	else
	{
		printk("HMAC hex:\n");
		for (int i = 0; i < TC_SHA256_DIGEST_SIZE; ++i)
		{
			printk("%02X",hmac_res[i]);
		}
		printk("\n");
	}


	base64_encode(NULL,0, &hmac_enc_size,
		      hmac_res, TC_SHA256_DIGEST_SIZE);
	printk("hmac enc SIZE %d\n",hmac_enc_size);
	hmac_enc = k_calloc(hmac_enc_size+1,1);
	ret = base64_encode(hmac_enc,hmac_enc_size, &hmac_enc_size,
		      hmac_res, TC_SHA256_DIGEST_SIZE);
	trim_pad =  strchr(hmac_enc, '=');
	if (trim_pad) {
		*trim_pad = '\0';
	}

	printk("FULL JWT:\n\n%s.%s.%s\n\n",hdr_enc, payload_enc, hmac_enc);
#endif
	err = bsdlib_init();
	if (err) {
		printk("Failed to initialize bsdlib!");
		return;
	}

	/* Initialize AT comms in order to provision the certificate */
	err = at_comms_init();
	if (err) {
		return;
	}

	/* Provision certificates before connecting to the LTE network */
	err = cert_provision();
	if (err) {
		return;
	}

	printk("Waiting for network...");
	err = lte_lc_init_and_connect();
	if (err) {
		printk("Failed to connect to the LTE network, err %d\n", err);
		return;
	}
	printk("LTE connected.\n");

	err = getaddrinfo(HOSTNAME, NULL, &hints, &res);
	if (err) {
		printk("getaddrinfo() failed, err %d\n", errno);
		return;
	}
	else
	{
		char peer_addr[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &res->ai_addr, peer_addr, INET_ADDRSTRLEN);
		printk("getaddrinfo() %s\n", peer_addr);
	}


	((struct sockaddr_in *)res->ai_addr)->sin_port = htons(API_PORT);

	fd = socket(AF_INET, SOCK_STREAM, SOCKET_PROTOCOL);
	if (fd == -1) {
		printk("Failed to open socket!\n");
		goto clean_up;
	}

	/* Setup TLS socket options */
	err = tls_setup(fd);
	if (err) {
		goto clean_up;
	}

	printk("Connecting to %s\n", HOSTNAME);
	err = connect(fd, res->ai_addr, sizeof(struct sockaddr_in));
	if (err) {
		printk("connect() failed, err: %d\n", errno);
		goto clean_up;
	}

	off = 0;
	do {
		bytes = send(fd, &send_buf[off], HTTP_HEAD_LEN - off, 0);
		if (bytes < 0) {
			printk("send() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (off < HTTP_HEAD_LEN);

	printk("Sent %d bytes\n", off);

	off = 0;
	do {
		bytes = recv(fd, &recv_buf[off], RECV_BUF_SIZE - off, 0);
		if (bytes < 0) {
			printk("recv() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (bytes != 0 /* peer closed connection */);

	printk("Received %d bytes\n", off);
	printk("\n%s\n", recv_buf);
	/* Print HTTP response */
	p = strstr(recv_buf, "\r\n");
	if (p) {
		off = p - recv_buf;
		recv_buf[off + 1] = '\0';
		printk("\n>\t %s\n\n", recv_buf);
	}

	printk("Finished, closing socket.\n");

clean_up:
	freeaddrinfo(res);
	(void)close(fd);
}
