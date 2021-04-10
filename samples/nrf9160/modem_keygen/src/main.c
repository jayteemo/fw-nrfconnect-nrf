/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <string.h>
#include <zephyr.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <modem/nrf_modem_lib.h>
#include <modem/at_cmd.h>
#include <modem/at_notif.h>
#include <sys/base64.h>
#include <tinycbor/cbor.h>
#include <tinycbor/cbor_buf_reader.h>

#define XSTR(a) STR(a)
#define STR(a) #a
#define GET_BASE64_LEN(n) (((4 * n / 3) + 3) & ~3)

#define BASE64_PAD_CHAR	'='
#define MODEM_SLOT	CONFIG_SEC_TAG

#define AT_DELETE_KEY_CMD "AT%CMNG=3," XSTR(MODEM_SLOT) ",2"

#define AT_KEYGEN_CMD "AT%KEYGEN=" \
		      XSTR(MODEM_SLOT) \
		      ",2," \
		      XSTR(CONFIG_KEYGEN_TYPE) \
		      ",\"O=Nordic Semiconductor,L=PDX,C=no\",\"101010000\""

/* AT%KEYGEN=14,2,0 */
#define EXAMPLE_RESP  "\"MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0x" \
			"MjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o_EX" \
			"nw62bnQWr8-JqsNh_HZxS3k3bMD4KZ8-qxnvgeoiqQ5zAycEP_Wcmzqypvwyf3qW" \
			"MrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0E" \
			"AwIFAANIADBFAiEAv7OLZ_dXbszfhhjcLMUT72wTmw-z6GlgWxVhyWgR27ACIAvY" \
			"_lPu3yfYZY5AL6uYTkUFp4GQkbSOUC_lsHyCxOuG.0oRDoQEmoQRBIVhL2dn3hQl" \
			"QUDYxVDkxRPCAIhIbZAFifUERWCBwKj1W8FsvclMdZQgl4gBB4unZMYw0toU6uQZ" \
			"uXHLoDFAbhyLuHetYFWbiyxNZsnzSWEDUiTl7wwFt0hEsCiEQsxj-hCtpBk8Za8U" \
			"XfdAycpx2faCOPJIrkfmiSS8-Y6_2tTAoAMN1BiWiTOimY1wZE3Ud\""

static char at_cmd_buf[CONFIG_AT_CMD_RESPONSE_MAX_LEN];

struct cbor_payload {
	char * buf;
	size_t sz;
};

/* the first 2 BSTRs in the COSE data are additional CBOR payloads */
#define CBOR_PAYLOADS_TO_SAVE 3
struct cbor_payload cbor_payloads[CBOR_PAYLOADS_TO_SAVE];
static int cbor_cnt = 0;

static int parse_cbor_buffer(const char * const bin_buf, const size_t bin_buf_sz);

/* Initialize AT communications */
int at_comms_init(void)
{
	int err;

	err = at_cmd_init();
	if (err) {
		printk("Failed to initialize AT commands, err %d\n", err);
	}

	return 0;
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

int base64url_to_binary(const char *const base64url_str, char **bin_buf, size_t *bin_buf_sz)
{
	int err = 0;
	char * b64_str = NULL;
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
	b64_str = k_calloc(b64_str_sz,1);
	if (!b64_str) {
		printk("Could not allocate %d bytes\n", b64_str_sz);
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
		printk("Invalid base64 string, error: %d\n", err);
		err = -EBADMSG;
		goto cleanup;
	}

	/* Allocate and decode */
	*bin_buf = k_calloc(*bin_buf_sz, 1);
	if (!(*bin_buf)) {
		printk("Could not allocate %u bytes\n", *bin_buf_sz);
		err = -ENOMEM;
		goto cleanup;
	}
	err = base64_decode(*bin_buf, *bin_buf_sz, bin_buf_sz,
			    b64_str, b64_str_sz - 1);

	if (err) {
		printk("base64_decode error: %d\n", err);
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

int get_cbor_string(const CborValue * const str_val, char **buf, size_t *buf_sz)
{
	if (!str_val  || !buf || !buf_sz) {
		return -EINVAL;
	}

	CborType type = cbor_value_get_type(str_val );
	if (type != CborByteStringType && type != CborTextStringType){
		return -EBADMSG;
	}

	*buf_sz = 0;
	*buf = NULL;

	CborError err_cbor = cbor_value_calculate_string_length(str_val , buf_sz);

	if (err_cbor != CborNoError) {
		printk("cbor_value_calculate_string_length err: %d\n", err_cbor);
		return -EIO;
	}

	*buf = k_calloc(*buf_sz, 1);
	if (!(*buf)) {
		printk("Out of memory\n");
		return -ENOMEM;
	}

	if (type == CborByteStringType) {
		err_cbor = cbor_value_copy_byte_string(str_val , *buf, buf_sz, NULL);
	} else {
		err_cbor = cbor_value_copy_text_string(str_val , *buf, buf_sz, NULL);
	}
	if (err_cbor != CborNoError) {
		printk("CBOR copy string err: %d\n", err_cbor);
		k_free(*buf);
		*buf = NULL;
		*buf_sz = 0;
		return -EIO;
	}

	return 0;
}

char * bin_to_hex_str(const char * const bin_buf, const size_t bin_sz)
{
	if (!bin_buf || !bin_sz){
		return NULL;
	}

	const char * const HEX_CHARS = "0123456789ABCDEF";
	size_t hex_sz = (bin_sz * 2) + 1;
	char * hex_buf = k_calloc(hex_sz, 1);

	if(!hex_buf) {
		printk("Out of memory\n");
		return NULL;
	}

	for (int i = 0; i < bin_sz; ++i) {
		hex_buf[i*2]   = HEX_CHARS[bin_buf[i] >> 4];
		hex_buf[i*2+1] = HEX_CHARS[bin_buf[i] & 0x0F];
	}
	hex_buf[hex_sz-1] = '\0';
	return hex_buf;
}

char * bin_to_base64url_str(const char * const bin_buf, const size_t bin_sz)
{
	if (!bin_buf || !bin_sz){
		return NULL;
	}

	int err;
	size_t b64_sz = GET_BASE64_LEN(bin_sz) + 1; /* plus NULL */;
	char * b64_buf = k_calloc(b64_sz, 1);

	if (!b64_buf) {
		printk("Out of memory\n");
		return NULL;
	}

	err = base64_encode(b64_buf, b64_sz, &b64_sz, bin_buf, bin_sz);
	if (err) {
		printk("base64_encode err: %d\n", err);
		k_free(b64_buf);
		return NULL;

	} else {
		base64_url_format(b64_buf);
	}

	return b64_buf;
}

int print_cbor_values(CborValue * cbor_val)
{
	int err = 0;
	size_t len = 0;

	while (!cbor_value_at_end(cbor_val)) {
		switch (cbor_val->type) {
		case CborTagType:
		{
			CborTag tag;
			cbor_value_get_tag(cbor_val, &tag);
			printk("... tag: %llu\n", tag);
			break;
		}
		case CborMapType:
		{
			cbor_value_get_map_length(cbor_val, &len);
			printk("... Map: len %u\n", len);
			/* fall through */
		}
		case CborArrayType:
		{
			CborValue recursed;

			if (!len) {
				cbor_value_get_array_length(cbor_val, &len);
				printk("... Map: len %u\n", len);
			}

			err = cbor_value_enter_container(cbor_val, &recursed);
			if (err)
				return err;

			err = print_cbor_values(&recursed);
			if (err)
				return err;

			err = cbor_value_leave_container(cbor_val, &recursed);
			if (err)
				return err;

			continue;
		}
		case CborByteStringType:
		{
			size_t bin_sz = 0;
			char * bin_buf = NULL;
			char * ascii = NULL;

			err = get_cbor_string(cbor_val, &bin_buf, &bin_sz);
			if (err) {
				break;
			}

			if (cbor_cnt++ < CBOR_PAYLOADS_TO_SAVE) {
				printf("... BSTR saved.\n");
				cbor_payloads[cbor_cnt-1].buf = bin_buf;
				cbor_payloads[cbor_cnt-1].sz = bin_sz;
			} else {
				printf("... BSTR hex:\n");
				ascii = bin_to_hex_str(bin_buf, bin_sz);
				if (ascii){
					printf("%s\n", ascii);
					k_free(ascii);
				}

				k_free(bin_buf);
			}

			break;
		}
		case CborIntegerType:
		{
			int val = 0;
			cbor_value_get_int(cbor_val, &val);
			printk("... Int: %d\n", val);
			break;
		}
		case CborTextStringType:
		{
			char * str = NULL;
			size_t str_sz = 0;
			err = get_cbor_string(cbor_val, &str, &str_sz);
			if (err) {
				break;
			}

			printf("... Str:\n%s\n", str);
			k_free(str);

			break;
		}
		default:
		{
			printk("Parsing not implemented for type: %d\n", cbor_val->type);
			break;
		}
		}
		err = cbor_value_advance_fixed(cbor_val);
		if (err) {
			break;
		}
	}

	return err;
}

int parse_cbor_buffer(const char * const bin_buf, const size_t bin_buf_sz)
{
	struct cbor_buf_reader reader;
	CborError err_cbor;
	CborParser parser;
	CborValue value;

	cbor_buf_reader_init(&reader, (uint8_t *)bin_buf, bin_buf_sz);
	err_cbor = cbor_parser_init(&reader.r, 0, &parser, &value);

	if (err_cbor != CborNoError) {
		printk("cbor_parser_init err: %d\n", err_cbor);
		return -EIO;
	}

	if(!cbor_value_is_valid(&value)) {
		printk("Invalid cbor value\n");
		return -EINVAL;
	}

	return print_cbor_values(&value);
}

int parse_keygen_resp(char * const resp, char **key, char **sig)
{
	if (!resp || !key || !sig) {
		return -EINVAL;
	}

	char * sig_end = NULL;
	char * key_end = NULL;

	*sig = NULL;

	*key = strchr(resp, '"');
	if (!(*key)) {
		printk("Unexpected response format\n");
		return -EBADMSG;
	}
	*key = *key + 1; /* Move beyond first quotation mark */

	*sig = strchr(*key,'.');
	if (!(*sig)) {
		printk("No signature found\n");

		key_end = strchr(*key,'"');
		if (!key_end) {
			printk("Unexpected response format\n");
			return -EBADMSG;
		}

		*key_end = '\0';
		return 0;
	}

	**sig = '\0';
	*sig = *sig + 1;

	sig_end = strchr(*sig,'"');
	if (!sig_end) {
		printk("Unexpected response format\n");
		return -EBADMSG;
	}

	*sig_end = '\0';
	return 0;
}

void main(void)
{
	int err;
	size_t bin_buf_sz =  0;
	char * bin_buf = NULL;
	char * sig = NULL;
	char * key = NULL;

#if !IS_ENABLED(CONFIG_PARSE_EXAMPLE_KEYGEN_OUTPUT)
	enum at_cmd_state state;

	err = nrf_modem_lib_init(NORMAL_MODE);
	if (err) {
		printk("Failed to initialize modem library: %d\n", err);
		return;
	}

	err = at_comms_init();
	if (err) {
		printk("Failed to init modem AT comms: %d\n", err);
		return;
	}

	printk("Sending AT cmd: %s\n", AT_KEYGEN_CMD);
	err = at_cmd_write(AT_KEYGEN_CMD, at_cmd_buf, sizeof(at_cmd_buf), &state);
	if (err == -8){
		/* delete and retry */
		printk("Deleting existing key in slot %d\n", MODEM_SLOT);
		err = at_cmd_write(AT_DELETE_KEY_CMD, NULL, 0, &state);
		if (err) {
			printk("Failed to delete key, err: %d\n", err);
			return;
		}

		err = at_cmd_write(AT_KEYGEN_CMD, at_cmd_buf, sizeof(at_cmd_buf), &state);
		if (err) {
			printk("Could not generate key\n");
			return;
		}
	} else if (err) {
		printk("AT cmd err: %d\n", err);
		return;
	}

	printk("AT cmd resp: %s\n", at_cmd_buf);
#else
	strcpy(at_cmd_buf, EXAMPLE_RESP);
#endif

	err = parse_keygen_resp(at_cmd_buf, &key, &sig);
	if (err) {
		printk("parsing failed");
		return;
	}

	printk("Payload:\n%s\n", key);
	printk("Cose   :\n%s\n", sig);

	err = base64url_to_binary(sig, &bin_buf, &bin_buf_sz);

	if (err) {
		printk("Failed to decode base64 string: %d\n", err);
		return;
	}

	char * hex_str = bin_to_hex_str(bin_buf, bin_buf_sz);
	if (hex_str) {
		printk("CBOR HEX: \n%s\n", hex_str);
		k_free(hex_str);
		hex_str = NULL;
	}

	err = parse_cbor_buffer(bin_buf, bin_buf_sz);

	if (bin_buf) {
		k_free(bin_buf);
	}

	for (int cnt = 0; cnt < CBOR_PAYLOADS_TO_SAVE; ++cnt) {
		if (cbor_payloads[0].buf && cbor_payloads[cnt].sz) {
			printk("\nParse CBOR %d:\n", cnt);
			err = parse_cbor_buffer(cbor_payloads[cnt].buf,
						cbor_payloads[cnt].sz);

			k_free(cbor_payloads[cnt].buf);
		}
	}

	printk("Finished!\n");
}
