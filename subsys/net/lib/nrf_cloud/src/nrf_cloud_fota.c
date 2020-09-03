/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include "nrf_cloud_fota.h"
#include "nrf_cloud_mem.h"
#include "nrf_cloud_transport.h"

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

#define JOB_UPDATE_MSG_TEMPLATE "[\"%s\",%d,%s]"
#define JOB_UPDATE_PROGRESS_TEMPLATE "[\"%s\",%d,%d]"

#define DOWNLOAD_COMPLETE_VAL 100
struct nrf_cloud_fota_job {
	char * mqtt_payload;
	size_t mqtt_payload_size;

	enum nrf_cloud_fota_status status;

	enum nrf_cloud_fota_type type;
	char * id;
	char * host;
	char * path;
	int file_size;

	enum nrf_cloud_fota_error error;
	int dl_progress;
};

static void http_fota_handler(const struct fota_download_evt *evt);
static void send_event(const enum nrf_cloud_fota_evt_id id,
		       const struct nrf_cloud_fota_job * const job);

static void cleanup_job(struct nrf_cloud_fota_job * const job);
static int start_job(struct nrf_cloud_fota_job * const job);
static int update_job(struct nrf_cloud_fota_job * const job);

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

static int build_topic(const char * const client_id,
		       const struct mqtt_utf8 * const endpoint,
		       const char * const topic_str,
		       struct mqtt_utf8 * const topic_out)
{
	int ret;

	char * buf;
	size_t size = endpoint->size + strlen(client_id) +
		      strlen(topic_str) + 1;

	buf = nrf_cloud_calloc(size, 1);

	if (!buf) {
		ret = -ENOMEM;
		reset_topic(topic_out);
		return ret;
	}

	ret = snprintf(buf, size, "%s%s%s",
		       endpoint->utf8, client_id, topic_str);

	if (ret <= 0 || ret >= size) {
		ret = -E2BIG;
		nrf_cloud_free(buf);
		return ret;
	}

	topic_out->utf8 = buf;
	topic_out->size = ret;

	return 0;
}

int nrf_cloud_fota_endpoint_set(const char * const client_id,
				const struct mqtt_utf8 * const endpoint)
{
	int ret;

	if (endpoint == NULL || endpoint->utf8 == NULL ||
	    endpoint->size == 0 || client_id == NULL)  {
		return -EINVAL;
	}

	reset_topics();

	ret = build_topic(client_id, endpoint, TOPIC_FOTA_RCV,
			  &topic_rcv.topic);
	if (ret) {
		goto error_cleanup;
	}

	ret = build_topic(client_id, endpoint,TOPIC_FOTA_UPDATE,
			  &topic_update.topic);
	if (ret) {
		goto error_cleanup;
	}

	ret = build_topic(client_id, endpoint,TOPIC_FOTA_REQ,
			  &topic_req.topic);
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

	LOG_DBG("Subscribing to topic: %s", topic_rcv.topic.utf8);

	return mqtt_subscribe(client_mqtt, &sub_list);
}

int nrf_cloud_fota_unsubscribe(void)
{
	if (topic_rcv.topic.size == 0 || topic_rcv.topic.utf8 == NULL) {
		return -EFAULT;
	}

	return mqtt_unsubscribe(client_mqtt, &sub_list);
}

static void http_fota_handler(const struct fota_download_evt *evt)
{
	__ASSERT_NO_MSG(evt != NULL);


	switch (evt->id) {
	case FOTA_DOWNLOAD_EVT_FINISHED:
		/* MCUBOOT: download finished, update job status and reboot */
		current_fota.dl_progress = DOWNLOAD_COMPLETE_VAL;
		update_job(&current_fota);
		send_event(NRF_FOTA_EVT_DL_PROGRESS,&current_fota);
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_PENDING:
		/* MODEM: update job status and reboot */
		current_fota.status = NRF_FOTA_IN_PROGRESS;
		update_job(&current_fota);
		send_event(NRF_FOTA_EVT_ERASE_PENDING,&current_fota);
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_DONE:
		/* MODEM: don't care? */
		current_fota.status = NRF_FOTA_IN_PROGRESS;
		send_event(NRF_FOTA_EVT_ERASE_DONE,&current_fota);
		break;

	case FOTA_DOWNLOAD_EVT_ERROR:
		current_fota.error = NRF_FOTA_ERROR_DOWNLOAD;
		current_fota.status = NRF_FOTA_FAILED;
		update_job(&current_fota);
		send_event(NRF_FOTA_EVT_ERROR,&current_fota);
		cleanup_job(&current_fota);
		break;

	case FOTA_DOWNLOAD_EVT_PROGRESS:
		/* Only if CONFIG_FOTA_DOWNLOAD_PROGRESS_EVT is enabled */
		current_fota.status = NRF_FOTA_DOWNLOADING;
		current_fota.dl_progress = evt->progress;
		update_job(&current_fota);
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
	 * [“abcd1234”,0,1234,”dev.nrfcloud.com”,"v1/firmwares/appfw.bin"]
	 */
	LOG_DBG("Parsing: %s", log_strdup(job->mqtt_payload));

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

static void send_event(const enum nrf_cloud_fota_evt_id id,
		       const struct nrf_cloud_fota_job * const job)
{
	__ASSERT_NO_MSG(job != NULL);

	struct nrf_cloud_fota_evt evt =
	{
		.id = id,
		.status =  job->status,
		.type = job->type
	};

	switch (id)
	{
	case NRF_FOTA_EVT_ERROR:
		evt.evt_data.error = job->error;
		break;
	case NRF_FOTA_EVT_DL_PROGRESS:
		evt.evt_data.dl_progress = job->dl_progress;
		break;
	default:
		break;
	}

	event_cb(&evt);
}

static int start_job(struct nrf_cloud_fota_job * const job)
{
	__ASSERT_NO_MSG(job != NULL);

	int ret;
	int sec_tag = -1;

#if defined(DOWNLOAD_CLIENT_TLS)
	sec_tag = CONFIG_NRF_CLOUD_SEC_TAG
#endif
	ret = fota_download_start(job->host, job->path, sec_tag, 0, NULL);
	if (ret) {
		LOG_ERR("Failed to start FOTA download: %d", ret);
		job->status = NRF_FOTA_FAILED;
		job->error = NRF_FOTA_ERROR_DOWNLOAD_START;
		send_event(NRF_FOTA_EVT_ERROR, job);
	} else {
		job->dl_progress = 0;
		job->status = NRF_FOTA_DOWNLOADING;
		send_event(NRF_FOTA_EVT_START, job);
	}

	return ret;
}

static void cleanup_job(struct nrf_cloud_fota_job * const job)
{
	__ASSERT_NO_MSG(job != NULL);

	if (job->mqtt_payload) {
		nrf_cloud_free(job->mqtt_payload);
		job->mqtt_payload = NULL;
	}
	memset(job,0,sizeof(*job));
}

#define UPDATE_PAYLOAD_SIZE 255
static int update_job(struct nrf_cloud_fota_job * const job)
{
	__ASSERT_NO_MSG(job != NULL);

	int ret;
	char payload[UPDATE_PAYLOAD_SIZE];
	struct mqtt_publish_param param = {
		.message_id = NRF_CLOUD_FOTA_UPDATE_ID,
		.dup_flag = 0,
		.retain_flag = 0,
	};

	param.message.payload.data = payload;
	param.message.topic = topic_update;

	if (job->status == NRF_FOTA_DOWNLOADING) {
		ret = snprintf(payload, UPDATE_PAYLOAD_SIZE,
			 JOB_UPDATE_PROGRESS_TEMPLATE,
			 job->id, job->status, job->dl_progress);
	} else {
		ret = snprintf(payload, UPDATE_PAYLOAD_SIZE,
			 JOB_UPDATE_MSG_TEMPLATE,
			 job->id, job->status, "\"\"");
	}

	if (ret <= 0 || ret >= UPDATE_PAYLOAD_SIZE) {
		return -E2BIG;
	}

	param.message.payload.len = ret;
	LOG_DBG("Topic: %s",
		log_strdup(param.message.topic.topic.utf8));
	LOG_DBG("Payload (%d bytes): %s",
		param.message.payload.len,
		log_strdup(param.message.payload.data));

	ret = mqtt_publish(client_mqtt, &param);
	if (ret) {
		LOG_ERR("Publish failed: %d", ret);
	}

	return ret;
}

int nrf_cloud_fota_mqtt_evt_handler(const struct mqtt_evt * evt)
{
	if (topic_rcv.topic.utf8 == NULL || topic_rcv.topic.size == 0) {
		/* Ignore MQTT until a topic has been set */
		return 1;
	}

	int ret;

	switch (evt->type) {
	case MQTT_EVT_PUBLISH: {
		int err = 0;
		bool start = false;
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

		current_fota.mqtt_payload_size = p->message.payload.len + 1;
		current_fota.mqtt_payload =
			nrf_cloud_calloc(current_fota.mqtt_payload_size,1);

		if (!current_fota.mqtt_payload) {
			LOG_ERR("Unable to allocate memory for job");
			err = -ENOMEM;
			goto send_ack;
		}

		ret = mqtt_readall_publish_payload(client_mqtt,
				current_fota.mqtt_payload,
				p->message.payload.len);
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

		start = true;
send_ack:
		if (p->message.topic.qos == MQTT_QOS_0_AT_MOST_ONCE) {
			LOG_DBG("No ack required");
		} else {
			ret = mqtt_publish_qos1_ack(client_mqtt, &ack);
			if (ret) {
				LOG_ERR("MQTT ACK failed: %d", ret);
			}
		}

		if (start) {
			(void)start_job(&current_fota);
			(void)update_job(&current_fota);
		}

		return (err ? err : ret);
	}
	case MQTT_EVT_SUBACK:
	{
		if (evt->param.suback.message_id != NRF_CLOUD_FOTA_SUBSCRIBE_ID) {
			return 1;
		}
		LOG_DBG("MQTT_EVT_SUBACK");
		break;
	}
	case MQTT_EVT_UNSUBACK:
	{
		if (evt->param.unsuback.message_id != NRF_CLOUD_FOTA_SUBSCRIBE_ID) {
			return 1;
		}
		LOG_DBG("MQTT_EVT_UNSUBACK");
		break;
	}
	case MQTT_EVT_PUBACK:
	{
		bool apply = false;

		if (evt->param.puback.message_id != NRF_CLOUD_FOTA_UPDATE_ID) {
			return 1;
		}
		LOG_DBG("MQTT_EVT_PUBACK");

		switch (current_fota.status)
		{
		case NRF_FOTA_SUCCEEDED:
			apply = true;
			/* fall-through */
		case NRF_FOTA_FAILED:
		case NRF_FOTA_REJECTED:
		case NRF_FOTA_CANCELED:
		case NRF_FOTA_TIMED_OUT:
			cleanup_job(&current_fota);
			break;
		default:
			break;
		}
		if (apply) {
			nct_apply_update();
		}
	}
	case MQTT_EVT_CONNACK:
	case MQTT_EVT_DISCONNECT:
	case MQTT_EVT_PUBREC:
	case MQTT_EVT_PUBREL:
	case MQTT_EVT_PUBCOMP:
	case MQTT_EVT_PINGRESP:
		return 1;
	break;
	}

	return 0;
}