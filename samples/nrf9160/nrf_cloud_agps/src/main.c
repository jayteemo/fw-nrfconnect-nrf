/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <stdio.h>
#include <modem/lte_lc.h>
#include <net/cloud.h>
#include <net/socket.h>
#include <dk_buttons_and_leds.h>
#include <drivers/gps.h>
#include <power/reboot.h>
#include <net/download_client.h>

#include <logging/log.h>

LOG_MODULE_REGISTER(nrf_cloud_agps_sample,
		    CONFIG_NRF_CLOUD_AGPS_SAMPLE_LOG_LEVEL);

static struct cloud_backend *cloud_backend;
static struct device *gps_dev;
static uint64_t start_search_timestamp;
static uint64_t fix_timestamp;
static struct k_delayed_work gps_start_work;
static struct k_delayed_work reboot_work;

static void gps_start_work_fn(struct k_work *work);

static struct download_client dlc;
static char * agps_file;
static size_t agps_file_rcvd_size;
static size_t agps_file_total_size;

static int download_client_callback(const struct download_client_evt *event)
{
	static bool first_fragment = true;
	size_t offset;
	int err;

	if (event == NULL) {
		return -EINVAL;
	}

	switch (event->id) {
	case DOWNLOAD_CLIENT_EVT_FRAGMENT: {
		if (first_fragment) {

			if (agps_file) {
				k_free(agps_file);
				agps_file = NULL;
			}

			agps_file_rcvd_size = 0;
			agps_file_total_size = 0;

			err = download_client_file_size_get(&dlc, &agps_file_total_size);
			if (err != 0) {
				LOG_ERR("download_client_file_size_get err: %d",
					err);
				return err;
			} else {
				LOG_INF("download_client_file_size_get: %d",
					agps_file_total_size);
				agps_file = k_calloc(1, agps_file_total_size);
				if (!agps_file) {
					LOG_ERR("No memory for AGPS file");
					return -ENOMEM;
				}
			}
			first_fragment = false;
		}

		memcpy(&agps_file[agps_file_rcvd_size],event->fragment.buf, event->fragment.len);
		agps_file_rcvd_size += event->fragment.len;
		LOG_INF("Rcvd %d/%d", agps_file_rcvd_size, agps_file_total_size );
	break;
	}

	case DOWNLOAD_CLIENT_EVT_DONE:
		LOG_INF("DOWNLOAD_CLIENT_EVT_DONE");
		err = download_client_disconnect(&dlc);
		if (err != 0) {
			LOG_ERR("download_client_disconnect err: %d", err);
			return err;
		}

		first_fragment = true;

		err = gps_process_agps_data(agps_file, agps_file_rcvd_size);
		if (err != 0) {
			LOG_ERR("gps_process_agps_data err: %d", err);
			return err;
		}
		break;

	case DOWNLOAD_CLIENT_EVT_ERROR: {
		LOG_ERR("Download client error: %d", event->error);
		download_client_disconnect(&dlc);
		break;
	}
	default:
		break;
	}

	return 0;
}

static void cloud_send_msg(void)
{
	int err;

	LOG_DBG("Publishing message: %s", log_strdup(CONFIG_CLOUD_MESSAGE));

	struct cloud_msg msg = {
		.qos = CLOUD_QOS_AT_MOST_ONCE,
		.endpoint.type = CLOUD_EP_TOPIC_MSG,
		.buf = CONFIG_CLOUD_MESSAGE,
		.len = sizeof(CONFIG_CLOUD_MESSAGE)
	};

	err = cloud_send(cloud_backend, &msg);
	if (err) {
		LOG_ERR("cloud_send failed, error: %d", err);
	}
}

static void gps_start_work_fn(struct k_work *work)
{
	int err;
	struct gps_config gps_cfg = {
		.nav_mode = GPS_NAV_MODE_PERIODIC,
		.power_mode = GPS_POWER_MODE_DISABLED,
		.timeout = 120,
		.interval = 240,
		.priority = true,
	};

	ARG_UNUSED(work);

	err = gps_start(gps_dev, &gps_cfg);
	if (err) {
		LOG_ERR("Failed to start GPS, error: %d", err);
		return;
	}

	LOG_INF("Periodic GPS search started with interval %d s, timeout %d s",
		gps_cfg.interval, gps_cfg.timeout);
}

static void on_agps_needed(struct gps_agps_request request)
{
	int err;

	err = gps_agps_request(request, GPS_SOCKET_NOT_PROVIDED);
	if (err) {
		LOG_ERR("Failed to request A-GPS data, error: %d", err);
		return;
	}
}

static void cloud_event_handler(const struct cloud_backend *const backend,
				const struct cloud_event *const evt,
				void *user_data)
{
	ARG_UNUSED(backend);
	ARG_UNUSED(user_data);

	switch (evt->type) {
	case CLOUD_EVT_CONNECTING:
		LOG_INF("CLOUD_EVT_CONNECTING");
		break;
	case CLOUD_EVT_CONNECTED:
		LOG_INF("CLOUD_EVT_CONNECTED");
		break;
	case CLOUD_EVT_READY:
		LOG_INF("CLOUD_EVT_READY");
		k_delayed_work_submit(&gps_start_work, K_NO_WAIT);
		break;
	case CLOUD_EVT_DISCONNECTED:
		LOG_INF("CLOUD_EVT_DISCONNECTED");
		break;
	case CLOUD_EVT_ERROR:
		LOG_INF("CLOUD_EVT_ERROR");
		break;
	case CLOUD_EVT_DATA_SENT:
		LOG_INF("CLOUD_EVT_DATA_SENT");
		break;
	case CLOUD_EVT_DATA_RECEIVED:
		LOG_INF("CLOUD_EVT_DATA_RECEIVED");

		/* Convenience functionality for remote testing.
		 * The device is reset if it receives "{"reboot":true}"
		 * from the cloud. The command can be sent using the terminal
		 * card on the device pgae on nrfcloud.com.
		 */
		if (evt->data.msg.buf[0] == '{') {
			int ret = strncmp(evt->data.msg.buf,
				      "{\"reboot\":true}",
				      strlen("{\"reboot\":true}"));

			if (ret == 0) {
				k_delayed_work_submit(&reboot_work, K_NO_WAIT);
			}
			break;
		}

		int err = gps_process_agps_data(evt->data.msg.buf,
						evt->data.msg.len);
		if (err) {
			LOG_INF("Unable to process agps data, error: %d", err);
		}
		break;
	case CLOUD_EVT_PAIR_REQUEST:
		LOG_INF("CLOUD_EVT_PAIR_REQUEST");
		break;
	case CLOUD_EVT_PAIR_DONE:
		LOG_INF("CLOUD_EVT_PAIR_DONE");
		break;
	case CLOUD_EVT_FOTA_DONE:
		LOG_INF("CLOUD_EVT_FOTA_DONE");
		break;
	default:
		LOG_INF("Unknown cloud event type: %d", evt->type);
		break;
	}
}

static void print_pvt_data(struct gps_pvt *pvt_data)
{
	char buf[300];
	size_t len;

	len = snprintf(buf, sizeof(buf),
		      "\r\n\tLongitude:  %f\r\n\t"
		      "Latitude:   %f\r\n\t"
		      "Altitude:   %f\r\n\t"
		      "Speed:      %f\r\n\t"
		      "Heading:    %f\r\n\t"
		      "Date:       %02u-%02u-%02u\r\n\t"
		      "Time (UTC): %02u:%02u:%02u\r\n",
		      pvt_data->longitude, pvt_data->latitude,
		      pvt_data->altitude, pvt_data->speed, pvt_data->heading,
		      pvt_data->datetime.day, pvt_data->datetime.month,
		      pvt_data->datetime.year, pvt_data->datetime.hour,
		      pvt_data->datetime.minute, pvt_data->datetime.seconds);
	if (len < 0) {
		LOG_ERR("Could not construct PVT print");
	} else {
		LOG_INF("%s", log_strdup(buf));
	}
}

static void print_satellite_stats(struct gps_pvt *pvt_data)
{
	uint8_t tracked = 0;
	uint32_t tracked_sats = 0;
	static uint32_t prev_tracked_sats;
	char print_buf[100];
	size_t print_buf_len;

	for (int i = 0; i < GPS_PVT_MAX_SV_COUNT; ++i) {
		if ((pvt_data->sv[i].sv > 0) &&
		    (pvt_data->sv[i].sv < 33)) {
			tracked++;
			tracked_sats |= BIT(pvt_data->sv[i].sv - 1);
		}
	}

	if ((tracked_sats == 0) || (tracked_sats == prev_tracked_sats)) {
		if (tracked_sats != prev_tracked_sats) {
			prev_tracked_sats = tracked_sats;
			LOG_DBG("Tracking no satellites");
		}

		return;
	}

	prev_tracked_sats = tracked_sats;
	print_buf_len = snprintk(print_buf, sizeof(print_buf), "Tracking:  ");

	for (size_t i = 0; i < 32; i++) {
		if (tracked_sats & BIT(i)) {
			print_buf_len +=
				snprintk(&print_buf[print_buf_len - 1],
					 sizeof(print_buf) - print_buf_len,
					 "%d  ", i + 1);
			if (print_buf_len < 0) {
				LOG_ERR("Failed to print satellite stats");
				break;
			}
		}
	}

	LOG_INF("%s", log_strdup(print_buf));
	LOG_DBG("Searching for %lld seconds",
		(k_uptime_get() - start_search_timestamp) / 1000);
}

static void send_nmea(char *nmea)
{
	int err;
	char buf[150];
	struct cloud_msg msg = {
		.qos = CLOUD_QOS_AT_MOST_ONCE,
		.endpoint.type = CLOUD_EP_TOPIC_MSG,
		.buf = buf,
	};

	msg.len = snprintf(buf, sizeof(buf),
		"{"
			"\"appId\":\"GPS\","
			"\"data\":\"%s\","
			"\"messageType\":\"DATA\""
		"}", nmea);
	if (msg.len < 0) {
		LOG_ERR("Failed to create GPS cloud message");
		return;
	}

	err = cloud_send(cloud_backend, &msg);
	if (err) {
		LOG_ERR("Failed to send message to cloud, error: %d", err);
		return;
	}

	LOG_INF("GPS position sent to cloud");
}

static void gps_handler(struct device *dev, struct gps_event *evt)
{
	ARG_UNUSED(dev);

	switch (evt->type) {
	case GPS_EVT_SEARCH_STARTED:
		LOG_INF("GPS_EVT_SEARCH_STARTED");
		start_search_timestamp = k_uptime_get();
		break;
	case GPS_EVT_SEARCH_STOPPED:
		LOG_INF("GPS_EVT_SEARCH_STOPPED");
		break;
	case GPS_EVT_SEARCH_TIMEOUT:
		LOG_INF("GPS_EVT_SEARCH_TIMEOUT");
		break;
	case GPS_EVT_OPERATION_BLOCKED:
		LOG_INF("GPS_EVT_OPERATION_BLOCKED");
		break;
	case GPS_EVT_OPERATION_UNBLOCKED:
		LOG_INF("GPS_EVT_OPERATION_UNBLOCKED");
		break;
	case GPS_EVT_AGPS_DATA_NEEDED:
		LOG_INF("GPS_EVT_AGPS_DATA_NEEDED");
		on_agps_needed(evt->agps_request);
		break;
	case GPS_EVT_PVT:
		print_satellite_stats(&evt->pvt);
		break;
	case GPS_EVT_PVT_FIX:
		fix_timestamp = k_uptime_get();

		LOG_INF("---------       FIX       ---------");
		LOG_INF("Time to fix: %d seconds",
			(uint32_t)(fix_timestamp - start_search_timestamp) / 1000);
		print_pvt_data(&evt->pvt);
		LOG_INF("-----------------------------------");
		break;
	case GPS_EVT_NMEA_FIX:
		send_nmea(evt->nmea.buf);
		break;
	default:
		break;
	}
}

static void reboot_work_fn(struct k_work *work)
{
	LOG_WRN("Rebooting in 2 seconds...");
	k_sleep(K_SECONDS(2));
	sys_reboot(0);
}

static void work_init(void)
{
	k_delayed_work_init(&gps_start_work, gps_start_work_fn);
	k_delayed_work_init(&reboot_work, reboot_work_fn);
}

static int modem_configure(void)
{
	int err = 0;

	if (IS_ENABLED(CONFIG_LTE_AUTO_INIT_AND_CONNECT)) {
		/* Do nothing, modem is already turned on
		 * and connected.
		 */
	} else {
		LOG_INF("Connecting to LTE network. This may take minutes.");

#if defined(CONFIG_LTE_POWER_SAVING_MODE)
		err = lte_lc_psm_req(true);
		if (err) {
			LOG_ERR("PSM request failed, error: %d", err);
			return err;
		}

		LOG_INF("PSM mode requested");
#endif

		err = lte_lc_init_and_connect();
		if (err) {
			LOG_ERR("LTE link could not be established, error: %d",
				err);
			return err;
		}

		LOG_INF("Connected to LTE network");
	}

	return err;
}

static void button_handler(uint32_t button_states, uint32_t has_changed)
{
	if (has_changed & button_states & DK_BTN1_MSK) {
		cloud_send_msg();
		k_delayed_work_submit(&reboot_work, K_SECONDS(3));
	} else if (has_changed & ~button_states & DK_BTN1_MSK) {
		k_delayed_work_cancel(&reboot_work);
	}
}

void main(void)
{
	int err;
#if 0
	/* By default POLLERR, POLLNVAL and POLLUHP are alway polled for */
	struct pollfd fds[] = {
		{
			.events = POLLIN
		}
	};

	LOG_INF("nRF Cloud and A-GPS sample has started");

	cloud_backend = cloud_get_binding("NRF_CLOUD");
	__ASSERT(cloud_backend, "Could not get binding to cloud backend");

	err = cloud_init(cloud_backend, cloud_event_handler);
	if (err) {
		LOG_ERR("Cloud backend could not be initialized, error: %d",
			err);
		return;
	}
#endif
	work_init();

	err = modem_configure();
	if (err) {
		LOG_ERR("Modem configuration failed with error %d",
			err);
		return;
	}

	gps_dev = device_get_binding("NRF9160_GPS");
	if (gps_dev == NULL) {
		LOG_ERR("Could not get binding to nRF9160 GPS");
		return;
	}

	err = gps_init(gps_dev, gps_handler);
	if (err) {
		LOG_ERR("Could not initialize GPS, error: %d", err);
		return;
	}

	err = download_client_init(&dlc, download_client_callback);

	struct download_client_cfg config = {
		.sec_tag = 16842753,
		.apn = NULL
	};

	// "https://agps-test.s3.amazonaws.com/agps-payload.bin"
	// https://api.coha.nrfcloud.com/v1/location/agps\?deviceIdentifier\=3 -H "Authorization: Bearer xxx" -H "Range: bytes=0-1400" -v
	err = download_client_connect(&dlc, "api.coha.nrfcloud.com", &config);
	if (err != 0) {
		LOG_ERR("download_client_connect error: %d", err);
		return;
	}

	err = download_client_start(&dlc, "v1/location/agps\?deviceIdentifier=3", 0);
	if (err != 0) {
		LOG_ERR("download_client_start error: %d", err);
		download_client_disconnect(&dlc);
		return;
	}

#if 0
	err = dk_buttons_init(button_handler);
	if (err) {
		LOG_ERR("Buttons could not be initialized, error: %d", err);
		LOG_WRN("Continuing without button funcitonality");
	}

	err = cloud_connect(cloud_backend);
	if (err) {
		LOG_ERR("Cloud connection failed, error: %d", err);
		return;
	}

	/* The cloud connection is polled in a thread in the backend.
	 * Events will be received to cloud_event_handler() when data is
	 * received from the cloud.
	 */
	fds[0].fd = cloud_backend->config->socket;

	while (true) {
		err = poll(fds, ARRAY_SIZE(fds),
			   cloud_keepalive_time_left(cloud_backend));
		if (err < 0) {
			LOG_ERR("poll() returned an error: %d", err);
			continue;
		}

		if (err == 0) {
			(void)cloud_ping(cloud_backend);
			continue;
		}

		if ((fds[0].revents & POLLIN) == POLLIN) {
			(void)cloud_input(cloud_backend);
		}

		if ((fds[0].revents & POLLNVAL) == POLLNVAL) {
			LOG_ERR("Socket error: POLLNVAL");
			LOG_ERR("The cloud socket was unexpectedly closed");
			return;
		}

		if ((fds[0].revents & POLLHUP) == POLLHUP) {
			LOG_ERR("Socket error: POLLHUP");
			LOG_ERR("Connection was closed, possibly by cloud");
			return;
		}

		if ((fds[0].revents & POLLERR) == POLLERR) {
			LOG_ERR("Socket error: POLLERR");
			LOG_ERR("Cloud connection was unexpectedly closed");
			return;
		}
	}
#endif
}
