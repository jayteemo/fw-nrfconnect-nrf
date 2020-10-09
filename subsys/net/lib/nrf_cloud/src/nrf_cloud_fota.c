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
#include <settings/settings.h>
#include <power/reboot.h>

#if defined(CONFIG_BOOTLOADER_MCUBOOT)
#include <dfu/mcuboot.h>
#endif

#if defined(CONFIG_BSD_LIBRARY)
//#include <nrf_socket.h>
#include <modem/bsdlib.h>
#include <bsd.h>
#endif

LOG_MODULE_REGISTER(nrf_cloud_fota, CONFIG_NRF_CLOUD_LOG_LEVEL);

#define TOPIC_FOTA_RCV    "/jobs/rcv"
#define TOPIC_FOTA_REQ    "/jobs/req"
#define TOPIC_FOTA_UPDATE "/jobs/update"

#define JOB_UPDATE_MSG_TEMPLATE "[\"%s\",%d,%s]"
#define JOB_UPDATE_PROGRESS_TEMPLATE "[\"%s\",%d,%d]"

#define JOB_REQUEST_LATEST_PAYLOAD "[\"\"]"
#define JOB_REQUEST_ID_TEMPLATE "[\"%s\"]"

#define UPDATE_PAYLOAD_SIZE 255

// Version 4 UUID: 32 bytes, 4 hyphens, NULL
#define JOB_ID_STRING_SIZE (32 + 4 + 1)

enum fota_validate_status {
	NRF_FOTA_VALIDATE_NONE = 0,
	NRF_FOTA_VALIDATE_PENDING,
	NRF_FOTA_VALIDATE_PASS,
	NRF_FOTA_VALIDATE_FAIL,
	NRF_FOTA_VALIDATE_UNKNOWN,
	NRF_FOTA_VALIDATE_DONE
};

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
	/* tracking for CONFIG_NRF_CLOUD_FOTA_PROGRESS_PCT_INCREMENT */
	int sent_dl_progress;
};

struct settings_fota_job {
	enum fota_validate_status validate;
	enum nrf_cloud_fota_type type;
	char id[JOB_ID_STRING_SIZE];
};

static void http_fota_handler(const struct fota_download_evt *evt);
static void send_event(const enum nrf_cloud_fota_evt_id id,
		       const struct nrf_cloud_fota_job * const job);

static void cleanup_job(struct nrf_cloud_fota_job * const job);
static int start_job(struct nrf_cloud_fota_job * const job);
static int send_job_update(struct nrf_cloud_fota_job * const job);
static int publish(const struct mqtt_publish_param * const pub);
static bool is_fota_active(void);
static int save_validate_status(const char * const job_id,
			   const enum nrf_cloud_fota_type job_type,
			   const enum fota_validate_status status);
static int fota_settings_set(const char *key, size_t len_rd,
			     settings_read_cb read_cb, void *cb_arg);

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

static enum fota_download_evt_id last_fota_dl_evt = FOTA_DOWNLOAD_EVT_ERROR;
static struct nrf_cloud_fota_job current_fota;
static struct settings_fota_job saved_job = { .type = NRF_FOTA_TYPE__INVALID };
static bool initialized;

#define SETTINGS_KEY_FOTA "fota"
#define SETTINGS_FULL_FOTA NRF_CLOUD_SETTINGS_NAME \
			   "/" \
			   SETTINGS_KEY_FOTA
#define SETTINGS_FOTA_JOB "job"
#define SETTINGS_FULL_FOTA_JOB SETTINGS_FULL_FOTA \
			       "/" \
			       SETTINGS_FOTA_JOB

SETTINGS_STATIC_HANDLER_DEFINE(fota, SETTINGS_FULL_FOTA, NULL,
			       fota_settings_set, NULL, NULL);

static int fota_settings_set(const char *key, size_t len_rd,
			     settings_read_cb read_cb, void *cb_arg)
{
	if (!key) {
		LOG_DBG("Key is NULL");
		return -EINVAL;
	}

	LOG_DBG("Settings key: %s, size: %d", log_strdup(key), len_rd);

	if (!strncmp(key, SETTINGS_FOTA_JOB, strlen(SETTINGS_FOTA_JOB)) &&
	    (len_rd == sizeof(saved_job))) {
		if (read_cb(cb_arg, (void *)&saved_job, len_rd) == len_rd) {
			LOG_DBG("Saved job: %s, type: %d, validate: %d",
				log_strdup(saved_job.id), saved_job.type,
				saved_job.validate);
			return 0;
		}
	}
	return -ENOTSUP;
}

enum fota_validate_status get_modem_update_status(void)
{
	enum fota_validate_status ret = NRF_FOTA_VALIDATE_UNKNOWN;

#if defined(CONFIG_BSD_LIBRARY)
	int modem_dfu_res = bsdlib_get_init_ret();

	/* Handle return values relating to modem firmware update */
	switch (modem_dfu_res) {
	case MODEM_DFU_RESULT_OK:
		LOG_DBG("Modem FOTA OK");
		ret = NRF_FOTA_VALIDATE_PASS;
		break;
	case MODEM_DFU_RESULT_UUID_ERROR:
	case MODEM_DFU_RESULT_AUTH_ERROR:
	case MODEM_DFU_RESULT_HARDWARE_ERROR:
	case MODEM_DFU_RESULT_INTERNAL_ERROR:
		LOG_ERR("Modem FOTA error: %d", modem_dfu_res);
		ret = NRF_FOTA_VALIDATE_FAIL;
		break;
	default:
		LOG_DBG("Modem FOTA result unknown: %d", modem_dfu_res);
		break;
	}
#endif /* CONFIG_BSD_LIBRARY */

	return ret;
}
int nrf_cloud_fota_init(nrf_cloud_fota_callback_t cb)
{
	int err;
	enum fota_validate_status validate = NRF_FOTA_VALIDATE_UNKNOWN;

	if (cb == NULL) {
		LOG_ERR("Invalid parameter");
		return -EINVAL;
	}

	event_cb = cb;

	if (initialized){
		return 0;
	}

	err = fota_download_init(http_fota_handler);
	if (err != 0) {
		LOG_ERR("fota_download_init error %d", err);
		return err;
	}

	err = settings_load_subtree(settings_handler_fota.name);
	if (err) {
		LOG_ERR("Cannot load settings: %d", err);
	}

	if (saved_job.validate == NRF_FOTA_VALIDATE_PENDING) {
#if defined(CONFIG_BOOTLOADER_MCUBOOT)
		if (!boot_is_img_confirmed()) {
			err = boot_write_img_confirmed();
			if (err) {
				LOG_ERR("FOTA update confirmation failed: %d",
					err);
				/* If this fails then MCUBOOT will revert
				* to the previous image on reboot
				*/
				validate = NRF_FOTA_VALIDATE_FAIL;
			} else {
				LOG_DBG("FOTA update confirmed");
				validate = NRF_FOTA_VALIDATE_PASS;
			}
		}
#endif

		if (saved_job.type == NRF_FOTA_MODEM) {
			validate = get_modem_update_status();
		}

		/* save status and update when cloud connection is ready */
		save_validate_status(saved_job.id, saved_job.type, validate);

		if (saved_job.type == NRF_FOTA_MODEM) {
			/* Reboot is required */
			LOG_INF("Rebooting to complete modem FOTA");
			sys_reboot(SYS_REBOOT_COLD);
		}
	}

	initialized = true;
	return err;
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

int nrf_cloud_fota_endpoint_set(struct mqtt_client *const client,
				const char * const client_id,
				const struct mqtt_utf8 * const endpoint)
{
	int ret;

	if (client == NULL || endpoint == NULL ||
	    endpoint->utf8 == NULL || endpoint->size == 0 ||
	    client_id == NULL)  {
		return -EINVAL;
	}

	client_mqtt = client;

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

	/* Report status of saved job now that the endpoint is available */
	if (saved_job.type != NRF_FOTA_TYPE__INVALID) {

		struct nrf_cloud_fota_job job = { .type = saved_job.type,
						  .id = saved_job.id };

		switch (saved_job.validate) {
		case NRF_FOTA_VALIDATE_UNKNOWN:
			job.error = NRF_FOTA_ERROR_UNABLE_TO_VALIDATE;
			/* fall-through */
		case NRF_FOTA_VALIDATE_PASS:
			job.status = NRF_FOTA_SUCCEEDED;
			break;
		case NRF_FOTA_VALIDATE_FAIL:
			job.status = NRF_FOTA_FAILED;
			break;
		default:
			LOG_ERR("Unexpected job validation status: %d",
				saved_job.validate);
			save_validate_status(job.id, job.type, NRF_FOTA_VALIDATE_DONE);
			job.type = NRF_FOTA_TYPE__INVALID;
			break;
		}

		if (job.type != NRF_FOTA_TYPE__INVALID) {
			int err = send_job_update(&job);
			if (err) {
				LOG_ERR("Error sending job update: %d", err);
			}
		}
	}

	return 0;

error_cleanup:
	reset_topics();
	return ret;
}

void nrf_cloud_fota_endpoint_clear(void)
{
	client_mqtt = NULL;
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

static bool is_fota_active(void)
{
	return (current_fota.mqtt_payload != NULL &&
		current_fota.mqtt_payload_size != 0);
}

static int save_validate_status(const char * const job_id,
			   const enum nrf_cloud_fota_type job_type,
			   const enum fota_validate_status validate)
{
	__ASSERT_NO_MSG(job_id != NULL);

	int ret;

	LOG_DBG("%s() - %s, %d, %d",
		log_strdup(__func__), log_strdup(job_id), job_type, validate);

	if (validate == NRF_FOTA_VALIDATE_DONE) {
		/* Saved FOTA job has been validated, clear it */
		saved_job.type = NRF_FOTA_TYPE__INVALID;
		saved_job.validate = NRF_FOTA_VALIDATE_NONE;
		memset(saved_job.id, 0, sizeof(saved_job.id));
	} else {
		saved_job.type = job_type;
		saved_job.validate = validate;
		if (job_id != saved_job.id) {
			strncpy(saved_job.id, job_id, sizeof(saved_job.id));
		}
	}

	ret = settings_save_one(SETTINGS_FULL_FOTA_JOB, &saved_job,
				sizeof(saved_job));
	if (ret) {
		LOG_ERR("settings_save_one failed: %d", ret);
	}

	return ret;
}

static void http_fota_handler(const struct fota_download_evt *evt)
{
	__ASSERT_NO_MSG(evt != NULL);

	LOG_DBG("%s() - evt %d", log_strdup(__func__), evt->id);

	switch (evt->id) {
	case FOTA_DOWNLOAD_EVT_FINISHED:
		/* MCUBOOT: download finished, update job status and reboot */
		current_fota.status = NRF_FOTA_IN_PROGRESS;
		save_validate_status(current_fota.id, current_fota.type,
				NRF_FOTA_VALIDATE_PENDING);
		send_job_update(&current_fota);
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_PENDING:
		/* MODEM: update job status and reboot */
		current_fota.status = NRF_FOTA_IN_PROGRESS;
		save_validate_status(current_fota.id, current_fota.type,
				NRF_FOTA_VALIDATE_PENDING);
		send_job_update(&current_fota);
		send_event(NRF_FOTA_EVT_ERASE_PENDING,&current_fota);
		break;

	case FOTA_DOWNLOAD_EVT_ERASE_DONE:
		/* MODEM: this event is received when the initial
		 * fragment is downloaded and dfu_target_modem_init() is
		 * called.
		 */
		send_event(NRF_FOTA_EVT_ERASE_DONE,&current_fota);
		break;

	case FOTA_DOWNLOAD_EVT_ERROR:
		if (last_fota_dl_evt == FOTA_DOWNLOAD_EVT_ERASE_DONE) {
			current_fota.status = NRF_FOTA_REJECTED;
		} else {
			current_fota.status = NRF_FOTA_FAILED;
			current_fota.error = NRF_FOTA_ERROR_DOWNLOAD;
		}
		save_validate_status(current_fota.id, current_fota.type,
				NRF_FOTA_VALIDATE_DONE);
		send_job_update(&current_fota);
		send_event(NRF_FOTA_EVT_ERROR,&current_fota);
		cleanup_job(&current_fota);
		break;

	case FOTA_DOWNLOAD_EVT_PROGRESS:
		current_fota.status = NRF_FOTA_DOWNLOADING;
		current_fota.dl_progress = evt->progress;

		/* Do not send complete status more than once */
		if ((current_fota.sent_dl_progress == 100) &&
		    (current_fota.dl_progress == 100)) {
			break;
		}

		/* Reset if new progress is less than previous */
		if (current_fota.sent_dl_progress >
		    current_fota.dl_progress) {
			current_fota.sent_dl_progress = 0;
		}

		/* Only send progress update when finished and if increment
		 * threshold is met
		 */
		if (current_fota.dl_progress != 100 &&
		    ((current_fota.dl_progress -
		      current_fota.sent_dl_progress) <
		     CONFIG_NRF_CLOUD_FOTA_PROGRESS_PCT_INCREMENT)) {
			break;
		}

		current_fota.sent_dl_progress = current_fota.dl_progress;
		send_job_update(&current_fota);
		break;
	default:
		break;
	}

	last_fota_dl_evt = evt->id;
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
	if (job->type < NRF_FOTA_TYPE__FIRST ||
	    job->type >= NRF_FOTA_TYPE__INVALID) {
		LOG_ERR("Invalid FOTA type: %d", job->type);
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

	/* Get file path
	 * Note: MCUboot bootloader updates can have
	 * two paths separated by a space
	 */
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
	int fragment_size = 0;

#if IS_ENABLED(CONFIG_NRF_CLOUD_FOTA_HTTPS_DOWNLOADS)
	sec_tag = CONFIG_NRF_CLOUD_SEC_TAG;
	fragment_size = 1024;
#endif

	ret = fota_download_start(job->host, job->path, sec_tag, NULL, fragment_size);
	if (ret) {
		LOG_ERR("Failed to start FOTA download: %d", ret);
		job->status = NRF_FOTA_FAILED;
		job->error = NRF_FOTA_ERROR_DOWNLOAD_START;
		send_event(NRF_FOTA_EVT_ERROR, job);
	} else {
		job->dl_progress = 0;
		job->sent_dl_progress = 0;
		job->status = NRF_FOTA_DOWNLOADING;
		send_event(NRF_FOTA_EVT_START, job);
	}

	return ret;
}

static void cleanup_job(struct nrf_cloud_fota_job * const job)
{
	__ASSERT_NO_MSG(job != NULL);
	LOG_DBG("%s() - ID: %s", log_strdup(__func__),
		job->id ? log_strdup(job->id) : "N/A");

	if (job->mqtt_payload) {
		nrf_cloud_free(job->mqtt_payload);
	}
	memset(job,0,sizeof(*job));
	job->type = NRF_FOTA_TYPE__INVALID;
}

static int publish(const struct mqtt_publish_param * const pub)
{
	__ASSERT_NO_MSG(pub != NULL);

	int ret;
	LOG_DBG("Topic: %s",
		log_strdup(pub->message.topic.topic.utf8));
	LOG_DBG("Payload (%d bytes): %s",
		pub->message.payload.len,
		log_strdup(pub->message.payload.data));

	ret = mqtt_publish(client_mqtt, pub);
	if (ret) {
		LOG_ERR("Publish failed: %d", ret);
	}
	return ret;
}

static const char * const get_error_string(const enum nrf_cloud_fota_error err)
{
	switch (err) {
		case NRF_FOTA_ERROR_DOWNLOAD_START:
			return "\"Failed to start download\"";
		case NRF_FOTA_ERROR_DOWNLOAD:
			return "\"Error during download\"";
		case NRF_FOTA_ERROR_UNABLE_TO_VALIDATE:
			return "\"FOTA update not validated\"";
		case NRF_FOTA_ERROR_NONE:
		default:
			return "\"\"";

	}
}

static int send_job_update(struct nrf_cloud_fota_job * const job)
{
	__ASSERT_NO_MSG(job != NULL);
	__ASSERT_NO_MSG(client_mqtt != NULL);

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
			 job->id, job->status, get_error_string(job->error));
	}

	if (ret <= 0 || ret >= UPDATE_PAYLOAD_SIZE) {
		return -E2BIG;
	}

	param.message.payload.len = ret;

	return publish(&param);
}

int nrf_cloud_fota_update_check(void)
{
	if (client_mqtt == NULL) {
		return -ENXIO;
	}
	if (topic_req.topic.utf8 == NULL || topic_req.topic.size == 0) {
		return -EADDRNOTAVAIL;
	}

	struct mqtt_publish_param param = {
		.message_id = NRF_CLOUD_FOTA_REQUEST_ID,
		.dup_flag = 0,
		.retain_flag = 0,
	};

	param.message.payload.data = JOB_REQUEST_LATEST_PAYLOAD;
	param.message.payload.len = strlen(JOB_REQUEST_LATEST_PAYLOAD);
	param.message.topic = topic_req;

	return publish(&param);
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

		if (is_fota_active()) {
			LOG_INF("Job in progress... skipping");
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
			ret = start_job(&current_fota);
			(void)send_job_update(&current_fota);
			if (ret) {
				cleanup_job(&current_fota);
				ret = 0;
			}
		}

		return (err ? err : ret);
	}
	case MQTT_EVT_SUBACK:
	{
		if (evt->param.suback.message_id !=
		    NRF_CLOUD_FOTA_SUBSCRIBE_ID) {
			return 1;
		}
		LOG_DBG("MQTT_EVT_SUBACK");

		nrf_cloud_fota_update_check();

		break;
	}
	case MQTT_EVT_UNSUBACK:
	{
		if (evt->param.unsuback.message_id !=
		    NRF_CLOUD_FOTA_SUBSCRIBE_ID) {
			return 1;
		}
		LOG_DBG("MQTT_EVT_UNSUBACK");
		break;
	}
	case MQTT_EVT_PUBACK:
	{
		bool do_update_check = false;

		if ((evt->param.puback.message_id !=
		    NRF_CLOUD_FOTA_UPDATE_ID) &&
		    (evt->param.puback.message_id !=
		    NRF_CLOUD_FOTA_REQUEST_ID)) {
			return 1;
		}

		LOG_DBG("MQTT_EVT_PUBACK: msg id %d",
			evt->param.puback.message_id);

		if (evt->param.puback.message_id ==
		    NRF_CLOUD_FOTA_REQUEST_ID) {
			    /* Nothing to do */
			    break;
		}

		do_update_check = !is_fota_active();

		switch (saved_job.validate) {
		case NRF_FOTA_VALIDATE_PASS:
		case NRF_FOTA_VALIDATE_UNKNOWN:
		case NRF_FOTA_VALIDATE_FAIL:
			save_validate_status(saved_job.id,saved_job.type,
					NRF_FOTA_VALIDATE_DONE);
			break;
		case NRF_FOTA_VALIDATE_PENDING:
			/* this event should cause reboot */
			send_event(NRF_FOTA_EVT_DONE,&current_fota);
			cleanup_job(&current_fota);
			do_update_check = false;
			break;
		default:
			break;
		}

		if (do_update_check) {
			/* this shouldn't be needed as the
			 * backend will send jobs automatically
			 * when one completes
			 */
			//nrf_cloud_fota_update_check();
		}

		break;
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