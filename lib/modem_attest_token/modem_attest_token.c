/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <string.h>
#include <zephyr.h>
#include <stdlib.h>
#include <stdio.h>
#include <modem/nrf_modem_lib.h>
#include <modem/at_cmd.h>
#include <sys/base64.h>
#include <tinycbor/cbor.h>
#include <tinycbor/cbor_buf_reader.h>
#include <modem/modem_attest_token.h>

#define GET_BASE64_LEN(n) (((4 * n / 3) + 3) & ~3)
#define BASE64_PAD_CHAR '='
#define AT_ATTEST_CMD "AT%ATTESTTOKEN"

/* Attestation message format:
 * Tag (55799)
 * Array (len 5)
 * - INT: msg type (NRF_ID_SRVC_MSG_TYPE_ID_V1)
 * - BSTR: device UUID
 * - INT: device type
 * - BSTR: FW UUID
 * - BSTR: nonce
 */
#define ATTEST_MAP_LEN 5

#define ATTEST_TOKEN_RESP_LEN 200
BUILD_ASSERT(
	ATTEST_TOKEN_RESP_LEN <= CONFIG_AT_CMD_RESPONSE_MAX_LEN,
	"Max AT cmd response length is too small for attestation token response");

static int parse_resp(char *const resp, char **attest, char **cose)
{
	if (!resp || !attest || !cose) {
		return -EINVAL;
	}

	char *cose_end = NULL;
	char *attest_end = NULL;

	*cose = NULL;

	*attest = strchr(resp, '"');
	if (!(*attest)) {
		return -EBADMSG;
	}
	/* Move beyond first quotation mark */
	*attest = *attest + 1;

	attest_end = strchr(*attest, '.');
	if (!(*attest_end)) {
		return -EBADMSG;
	}

	/* Replace . with a NULL */
	*attest_end = '\0';

	*cose = attest_end + 1;
	cose_end = strchr(*cose, '"');
	if (!cose_end) {
		return -EBADMSG;
	}

	/* Replace " with a NULL */
	*cose_end = '\0';

	return 0;
}

int modem_attest_token_get(struct nrf_attestation_token *const token)
{
	if (!token) {
		return -EINVAL;
	}

	int ret = 0;
	enum at_cmd_state state;
	char *cmd_resp = NULL;
	char *attest = NULL;
	char *cose = NULL;

	token->attest = NULL;
	token->cose = NULL;

	/* Init require modules */
	ret = nrf_modem_lib_init(NORMAL_MODE);
	if (ret) {
		return ret;
	}

	ret = at_cmd_init();
	if (ret) {
		return ret;
	}

	/* Allocate response buffer and send cmd */
	cmd_resp = k_calloc(ATTEST_TOKEN_RESP_LEN, 1);
	if (!cmd_resp) {
		ret = -ENOMEM;
		goto cleanup;
	}

	/* Execute AT command to get attestation token */
	ret = at_cmd_write(AT_ATTEST_CMD, cmd_resp, ATTEST_TOKEN_RESP_LEN,
			   &state);
	if (ret) {
		ret = -EBADMSG;
		goto cleanup;
	}

	/* Parse response to get attestation token and COSE strings */
	ret = parse_resp(cmd_resp, &attest, &cose);
	if (ret) {
		ret = -ENOMSG;
		goto cleanup;
	}

	/* Allocate and copy attest token string */
	size_t sz = strlen(attest) + 1;

	token->attest = k_calloc(sz, 1);
	if (!token->attest) {
		ret = -ENOMEM;
	} else {
		memcpy(token->attest, attest, sz);
	}

	/* Allocate and copy COSE string */
	sz = strlen(cose) + 1;
	token->cose = k_calloc(sz, 1);
	if (!token->cose) {
		ret = -ENOMEM;
		if (token->attest) {
			k_free(token->attest);
			token->attest = NULL;
		}
	} else {
		memcpy(token->cose, cose, sz);
	}
cleanup:

	if (cmd_resp) {
		k_free(cmd_resp);
	}

	return ret;
}

#if defined(CONFIG_MODEM_ATTEST_TOKEN_PARSING)
static int base64_url_unformat(char *const base64url_string)
{
	if (base64url_string == NULL) {
		return -EINVAL;
	}

	char *found = NULL;

	/* replace '-' with "+" */
	for (found = base64url_string; (found = strchr(found, '-'));) {
		*found = '+';
	}

	/* replace '_' with "/" */
	for (found = base64url_string; (found = strchr(found, '_'));) {
		*found = '/';
	}

	/* return number of padding chars required */
	return (strlen(base64url_string) % 4);
}

static int base64url_to_binary(const char *const base64url_str, char **bin_buf,
			       size_t *bin_buf_sz)
{
	int err = 0;
	char *b64_str = NULL;
	size_t b64_str_sz = 0;
	size_t base64url_str_len = strlen(base64url_str);
	int pad_chars = base64url_str_len % 4;

	if (pad_chars >= 2) {
		pad_chars = 4 - pad_chars;
	} else {
		pad_chars = 0;
	}

	b64_str_sz = pad_chars + base64url_str_len + 1;

	*bin_buf = NULL;

	/* The decoder does not handle b64 url formatted strings.
	 * Allocate a buffer to hold a non-url formatted b64 string
	 * so it can be properly decoded to binary.
	 */
	b64_str = k_calloc(b64_str_sz, 1);
	if (!b64_str) {
		err = -ENOMEM;
		goto cleanup;
	}

	/* Copy and un-format, then add pad characters if necessary */
	memcpy(b64_str, base64url_str, base64url_str_len);
	base64_url_unformat(b64_str);
	if (pad_chars) {
		memset(&b64_str[base64url_str_len], BASE64_PAD_CHAR, pad_chars);
	}

	/* Determine size of binary buffer */
	err = base64_decode(NULL, 0, bin_buf_sz, b64_str, b64_str_sz - 1);
	if (!(*bin_buf_sz)) {
		err = -EBADMSG;
		goto cleanup;
	}

	/* Allocate and decode */
	*bin_buf = k_calloc(*bin_buf_sz, 1);
	if (!(*bin_buf)) {
		err = -ENOMEM;
		goto cleanup;
	}
	err = base64_decode(*bin_buf, *bin_buf_sz, bin_buf_sz, b64_str,
			    b64_str_sz - 1);

	if (err) {
		err = -EIO;
		goto cleanup;
	}

cleanup:
	if (b64_str) {
		k_free(b64_str);
	}
	if (err && *bin_buf) {
		k_free(*bin_buf);
		*bin_buf = NULL;
		*bin_buf_sz = 0;
	}

	return err;
}

static int get_cbor_int(CborValue *value, int *const int_val)
{
	__ASSERT_NO_MSG(value != NULL);
	__ASSERT_NO_MSG(int_val != 0);

	CborError err_cbor;

	if (value->type != CborIntegerType) {
		return -EBADMSG;
	}

	err_cbor = cbor_value_get_int(value, int_val);
	if (err_cbor != CborNoError) {
		return -EIO;
	}

	(void)cbor_value_advance(value);

	return 0;
}

static int get_cbor_byte_string(CborValue *value, char *const buf,
				size_t buf_sz, size_t *const value_sz)
{
	__ASSERT_NO_MSG(value != NULL);
	__ASSERT_NO_MSG(buf != NULL);
	__ASSERT_NO_MSG(buf_sz != 0);
	__ASSERT_NO_MSG(value_sz != NULL);

	CborError err_cbor;

	if (value->type != CborByteStringType) {
		return -EBADMSG;
	}

	*value_sz = buf_sz;
	err_cbor = cbor_value_copy_byte_string(value, buf, value_sz, value);
	if (err_cbor != CborNoError) {
		return -EIO;
	}

	return 0;
}

static int get_attest_data(CborValue *value,
			   struct nrf_attestation_data *const data)
{
	int err = 0;
	CborValue map_value;
	CborTag tag;
	CborError err_cbor;
	size_t bstr_sz = 0;
	int map_len = 0;
	int int_val;

	if (value->type != CborTagType) {
		return -ENOMSG;
	}

	/* Check for the expected tag */
	err_cbor = cbor_value_get_tag(value, &tag);
	if (err_cbor != CborNoError || tag != CborSignatureTag) {
		return -EBADMSG;
	}

	err_cbor = cbor_value_advance_fixed(value);
	if (err_cbor != CborNoError) {
		return -EBADMSG;
	}

	/* Check for the expected type and length */
	if (value->type != CborArrayType) {
		return -ENOMSG;
	}

	err_cbor = cbor_value_get_array_length(value, &map_len);
	if (err_cbor != CborNoError || map_len != ATTEST_MAP_LEN) {
		return -EBADMSG;
	}

	/* Enter the array */
	err_cbor = cbor_value_enter_container(value, &map_value);
	if (err_cbor != CborNoError) {
		return -EACCES;
	}

	/* Get msg type */
	err = get_cbor_int(&map_value, &int_val);
	if (err) {
		return err;
	} else if (int_val != NRF_ID_SRVC_MSG_TYPE_ID_V1) {
		return -EBADMSG;
	}
	data->msg_type = (enum nrf_id_srvc_msg_type)int_val;

	/* Get device UUID */
	err = get_cbor_byte_string(&map_value, data->device_uuid,
				   sizeof(data->device_uuid), &bstr_sz);
	if (err || bstr_sz != sizeof(data->device_uuid)) {
		return -EBADMSG;
	}

	/* Get device type */
	err = get_cbor_int(&map_value, &int_val);
	if (err) {
		return err;
	}
	data->msg_type = (enum nrf_device_type)int_val;

	/* Get FW UUID */
	err = get_cbor_byte_string(&map_value, data->fw_uuid,
				   sizeof(data->fw_uuid), &bstr_sz);
	if (err || bstr_sz != sizeof(data->fw_uuid)) {
		return -EBADMSG;
	}

	/* Get nonce */
	err = get_cbor_byte_string(&map_value, data->nonce, sizeof(data->nonce),
				   &bstr_sz);
	if (err || bstr_sz != sizeof(data->nonce)) {
		return -EBADMSG;
	}

	/* Exit array */
	err_cbor = cbor_value_leave_container(value, &map_value);
	if (err_cbor != CborNoError) {
		return -EACCES;
	}

	return 0;
}

int modem_attest_token_parse(struct nrf_attestation_token const *const token_in,
			     struct nrf_attestation_data *const data_out)
{
	if (!token_in || !data_out || !token_in->attest) {
		return -EINVAL;
	}

	size_t bin_buf_sz = 0;
	char *bin_buf = NULL;
	struct cbor_buf_reader reader;
	CborError err_cbor;
	CborParser parser;
	CborValue value;
	int err = 0;

	/* Convert to binary and send to CBOR reader/parser */
	err = base64url_to_binary(token_in->attest, &bin_buf, &bin_buf_sz);
	if (err) {
		goto cleanup;
	}

	cbor_buf_reader_init(&reader, (uint8_t *)bin_buf, bin_buf_sz);

	err_cbor = cbor_parser_init(&reader.r, 0, &parser, &value);
	if (err_cbor != CborNoError) {
		err = -EIO;
		goto cleanup;
	}

	/* Get attestation token data */
	err = get_attest_data(&value, data_out);
	if (err) {
		memset(data_out, 0, sizeof(*data_out));
		data_out->dev_type = NRF_DEVICE_TYPE_INVALID;
		data_out->msg_type = NRF_ID_SRVC_MSG_TYPE_INVALID;
	}

cleanup:
	if (bin_buf) {
		k_free(bin_buf);
	}

	return err;
}

int modem_attest_token_get_device_uuid(struct nrf_device_uuid *uuid)
{
	if (uuid == NULL) {
		return -EINVAL;
	}

	int err;
	struct nrf_attestation_token a_tok;
	struct nrf_attestation_data a_data;

	err = modem_attest_token_get(&a_tok);
	if (err) {
		return err;
	}

	err = modem_attest_token_parse(&a_tok, &a_data);
	if (err) {
		goto cleanup;
	}

	for (int i = 0; i < NRF_DEVICE_UUID_SZ; ++i) {
		int sz = sprintf(&uuid->str[i * 2], "%02X",
				 a_data.device_uuid[i]);
		if (sz != 2) {
			err = -EIO;
			goto cleanup;
		}
	}

cleanup:
	if (a_tok.attest) {
		k_free(a_tok.attest);
	}
	if (a_tok.cose) {
		k_free(a_tok.cose);
	}

	return err;
}
#endif