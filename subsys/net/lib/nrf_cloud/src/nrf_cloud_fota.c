/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include "nrf_cloud_fota.h"
#include "nrf_cloud_mem.h"

#include <zephyr.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <net/mqtt.h>
#include <net/socket.h>
#include <net/nrf_cloud.h>
#include <net/fota_download.h>
#include <net/cloud.h>
#include <logging/log.h>
#include <sys/util.h>

#if defined(CONFIG_BSD_LIBRARY)
#include <nrf_socket.h>
#endif

LOG_MODULE_REGISTER(nrf_cloud_fota, CONFIG_NRF_CLOUD_LOG_LEVEL);

#define TOPIC_FOTA_RCV    "/jobs/rcv"
#define TOPIC_FOTA_REQ    "/jobs/req"
#define TOPIC_FOTA_UPDATE "/jobs/update"

struct nrf_cloud_fota_job {
	char * mqtt_payload;
	size_t mqtt_payload_size;

	enum nrf_cloud_fota_type type;
	enum nrf_cloud_fota_status status;

	char * id;
	char * host;
	char * path;
	int file_size;
};

static void http_fota_handler(const struct fota_download_evt *evt);

static struct mqtt_client * client_mqtt;
static nrf_cloud_fota_callback_t event_cb;

static struct mqtt_topic topic_rcv = { .qos = MQTT_QOS_1_AT_LEAST_ONCE };
static struct mqtt_topic topic_update = { .qos = MQTT_QOS_1_AT_LEAST_ONCE };
static struct mqtt_topic topic_req = { .qos = MQTT_QOS_1_AT_LEAST_ONCE };

static const struct mqtt_subscription_list sub_list = {
	.list = &topic_rcv,
	.list_count = 1,
	.message_id = NRF_CLOUD_FOTA_SUBSCRIBE_ID,
};

static struct nrf_cloud_fota_job current_fota;
static struct mqtt_client *const client;
static bool initialized;

int nrf_cloud_fota_init(struct mqtt_client *const client, nrf_cloud_fota_callback_t cb)
{
	int err;

	if (client == NULL || cb == NULL) {
		return -EINVAL;
	}

	client_mqtt = client;
	event_cb = cb;

	if (initialized){
		return 0;
	}

	err = fota_download_init(http_fota_handler);
	if (err != 0) {
		LOG_ERR("fota_download_init error %d", err);
		return err;
	}

	initialized = true;
	return 0;
}
static void reset_topic(struct mqtt_utf8 * const topic)
{
	if (!topic) {
		return;
	}

	if (topic->utf8) {
		nrf_cloud_free((void *)topic->utf8);
		topic->utf8 = NULL;
	}
	topic->size = 0;
}

static void reset_topics(void)
{
	reset_topic(&topic_rcv.topic);
	reset_topic(&topic_update.topic);
	reset_topic(&topic_req.topic);
}

static int build_topic(const struct mqtt_utf8 * const endpoint,
		       const char * const topic_str,
		       struct mqtt_utf8 * const topic_out)
{
	int ret;

	char * buf;
	size_t size = endpoint->size + strlen(topic_str) + 1;

	buf = nrf_cloud_calloc(size, 1);

	if (!buf) {
		ret = -ENOMEM;
		reset_topic(topic_out);
		return ret;
	}

	ret = snprintf(buf, size, "%s%s",
		       endpoint->utf8, topic_str);

	if (ret <= 0 || ret >= size) {
		ret = -E2BIG;
		nrf_cloud_free(buf);
		return ret;
	}

	topic_out->utf8 = buf;
	topic_out->size = ret;

	return 0;
}

int nrf_cloud_fota_endpoint_set(const struct mqtt_utf8 * const endpoint)
{
	int ret;

	if (endpoint == NULL || endpoint->utf8 == NULL ||
	    endpoint->size == 0)  {
		return -EINVAL;
	}

	reset_topics();

	ret = build_topic(endpoint,TOPIC_FOTA_RCV, &topic_rcv.topic);
	if (ret) {
		goto error_cleanup;
	}

	ret = build_topic(endpoint,TOPIC_FOTA_UPDATE, &topic_update.topic);
	if (ret) {
		goto error_cleanup;
	}

	ret = build_topic(endpoint,TOPIC_FOTA_REQ, &topic_req.topic);
	if (ret) {
		goto error_cleanup;
	}

	return 0;

error_cleanup:
	reset_topics();
	return ret;
}

void nrf_cloud_fota_endpoint_clear(void)
{
	reset_topics();
}

int nrf_cloud_fota_subscribe(void)
{
	if (topic_rcv.topic.size == 0 || topic_rcv.topic.utf8 == NULL) {
		return -EFAULT;
	}

	return mqtt_subscribe(client, &sub_list);
}

int nrf_cloud_fota_unsubscribe(void)
{
	if (topic_rcv.topic.size == 0 || topic_rcv.topic.utf8 == NULL) {
		return -EFAULT;
	}

	return mqtt_unsubscribe(client, &sub_list);
}

static void http_fota_handler(const struct fota_download_evt *evt)
{
	__ASSERT_NO_MSG(evt != NULL);

	switch (evt->id) {
	case FOTA_DOWNLOAD_EVT_FINISHED:
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_PENDING:
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_DONE:
		break;

	case FOTA_DOWNLOAD_EVT_ERROR:
		break;

	case FOTA_DOWNLOAD_EVT_PROGRESS:
		break;
	default:
		break;
	}
}

static int parse_job(struct nrf_cloud_fota_job * const job)
{
	char * save_ptr = NULL;
	char * end_ptr = &job->mqtt_payload[job->mqtt_payload_size - 1];
	char * tok;

	/* Job format:
	 * [“jobExecutionId”,firmwareType,fileSize,”host”,”path”]
	 *
	 * Example:
	 * [“abcd1234”,0,1234,”dev.nrfcloud.com”,v1/firmwares/appfw.bin"]
	 */

	/* Get execution ID */
	job->id = strtok_r(job->mqtt_payload, "[\",]", &save_ptr);
	if (!job->id) {
		goto handle_error;
	}

	/* Get fw type */
	tok = strtok_r(NULL, ",", &save_ptr);
	if (!tok) {
		goto handle_error;
	}
	errno = 0;
	job->type = (int)strtol(tok, &end_ptr,10);
	if (errno) {
		goto handle_error;
	}

	/* Get file size */
	tok = strtok_r(NULL, ",", &save_ptr);
	if (!tok) {
		goto handle_error;
	}
	errno = 0;
	job->file_size = (int)strtol(tok, &end_ptr,10);
	if (errno) {
		goto handle_error;
	}

	/* Get hostname */
	job->host = strtok_r(NULL, "\",", &save_ptr);
	if (!job->host) {
		goto handle_error;
	}

	/* Get file path */
	job->path = strtok_r(NULL, "\",]", &save_ptr);
	if (!job->path) {
		goto handle_error;
	}

	return 0;

handle_error:

	nrf_cloud_free(job->mqtt_payload);
	memset(job, 0, sizeof(*job));

	return -EINVAL;
}

int nrf_cloud_fota_mqtt_evt_handler(const struct mqtt_evt * evt)
{
	int ret;

	switch (evt->type) {
	case MQTT_EVT_PUBLISH: {
		int err = 0;
		const struct mqtt_publish_param *p = &evt->param.publish;

		struct mqtt_puback_param ack = {
			.message_id = p->message_id
		};

		if (strstr(topic_rcv.topic.utf8,
			   p->message.topic.topic.utf8) == NULL) {
			return 1;
		}

		LOG_DBG("MQTT_EVT_PUBLISH: id = %d len = %d",
			p->message_id,
			p->message.payload.len);

		if (current_fota.mqtt_payload) {
			LOG_DBG("Job in progress... skipping");
			goto send_ack;
		}

		current_fota.mqtt_payload_size = p->message.payload.len;
		current_fota.mqtt_payload =
			nrf_cloud_calloc(current_fota.mqtt_payload_size,1);

		if (!current_fota.mqtt_payload) {
			LOG_ERR("Unable to allocate memory for job");
			err = -ENOMEM;
			goto send_ack;
		}

		ret = mqtt_readall_publish_payload(client,
				current_fota.mqtt_payload,
				current_fota.mqtt_payload_size);
		if (ret) {
			LOG_ERR("Error reading MQTTT payload: %d", ret);
			err = ret;
			goto send_ack;
		}

		ret = parse_job(&current_fota);
		if (ret) {
			err = ret;
			goto send_ack;
		}

send_ack:
		ret = mqtt_publish_qos1_ack(client, &ack);
		return (err ? err : ret);
	}
	case MQTT_EVT_SUBACK:
	case MQTT_EVT_PUBACK:
	case MQTT_EVT_CONNACK:
	case MQTT_EVT_DISCONNECT:
	case MQTT_EVT_PUBREC:
	case MQTT_EVT_PUBREL:
	case MQTT_EVT_PUBCOMP:
	case MQTT_EVT_UNSUBACK:
	case MQTT_EVT_PINGRESP:
	break;
	}

	return 0;
}