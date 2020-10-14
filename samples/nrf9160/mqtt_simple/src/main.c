/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <stdio.h>
#include <drivers/uart.h>
#include <string.h>

#include <net/mqtt.h>
#include <net/socket.h>
#include <lte_lc.h>
#include <logging/log.h>
#if defined(CONFIG_LWM2M_CARRIER)
#include <lwm2m_carrier.h>
#else
#include <at_cmd.h>
#include <at_notif.h>
#include <dk_buttons_and_leds.h>
#endif

LOG_MODULE_REGISTER(mqtt_simple, CONFIG_MQTT_SIMPLE_LOG_LEVEL);

#define DISCONNECT_STR "disconnect"
#define LTE_CONNECT_RETRY_DELAY_S 480

/* Buffers for MQTT client. */
static u8_t rx_buffer[CONFIG_MQTT_MESSAGE_BUFFER_SIZE];
static u8_t tx_buffer[CONFIG_MQTT_MESSAGE_BUFFER_SIZE];
static u8_t payload_buf[CONFIG_MQTT_PAYLOAD_BUFFER_SIZE];

/* The mqtt client struct */
static struct mqtt_client client;

/* MQTT Broker details. */
static struct sockaddr_storage broker;

/* Connected flag */
static bool connected;

/* File descriptor */
static struct pollfd fds;

#if defined(CONFIG_BSD_LIBRARY)

/**@brief Recoverable BSD library error. */
void bsd_recoverable_error_handler(uint32_t err)
{
	LOG_ERR("bsdlib recoverable error: %u", (unsigned int)err);
}

#endif /* defined(CONFIG_BSD_LIBRARY) */

#if defined(CONFIG_LWM2M_CARRIER)
K_SEM_DEFINE(carrier_registered, 0, 1);
#if defined(CONFIG_MQTT_LIB_TLS)
static atomic_t carrier_requested_disconnect;
#endif
int lwm2m_carrier_event_handler(const lwm2m_carrier_event_t *event)
{
	switch (event->type) {
	case LWM2M_CARRIER_EVENT_BSDLIB_INIT:
		LOG_INF("LWM2M_CARRIER_EVENT_BSDLIB_INIT");
		break;
	case LWM2M_CARRIER_EVENT_CONNECTING:
		LOG_INF("LWM2M_CARRIER_EVENT_CONNECTING");
		break;
	case LWM2M_CARRIER_EVENT_CONNECTED:
		LOG_INF("LWM2M_CARRIER_EVENT_CONNECTED");
		break;
	case LWM2M_CARRIER_EVENT_DISCONNECTING:
		LOG_INF("LWM2M_CARRIER_EVENT_DISCONNECTING");
		break;
	case LWM2M_CARRIER_EVENT_BOOTSTRAPPED:
		LOG_INF("LWM2M_CARRIER_EVENT_BOOTSTRAPPED");
		break;
	case LWM2M_CARRIER_EVENT_DISCONNECTED:
		LOG_INF("LWM2M_CARRIER_EVENT_DISCONNECTED");
		break;
	case LWM2M_CARRIER_EVENT_READY:
		LOG_INF("LWM2M_CARRIER_EVENT_READY");
		k_sem_give(&carrier_registered);
		break;
	case LWM2M_CARRIER_EVENT_FOTA_START:
		LOG_INF("LWM2M_CARRIER_EVENT_FOTA_START");
#if defined(CONFIG_MQTT_LIB_TLS)
		/* Due to limitations in the number of secure sockets,
		 * the cloud socket has to be closed when the carrier
		 * library initiates firmware upgrade download.
		 */
		atomic_set(&carrier_requested_disconnect, 1);
		mqtt_disconnect(&client);
#endif
		break;
	case LWM2M_CARRIER_EVENT_REBOOT:
		LOG_INF("LWM2M_CARRIER_EVENT_REBOOT");
		break;
	case LWM2M_CARRIER_EVENT_ERROR:
		LOG_ERR("LWM2M_CARRIER_EVENT_ERROR: code %d, value %d",
			((lwm2m_carrier_event_error_t *)event->data)->code,
			((lwm2m_carrier_event_error_t *)event->data)->value);
		break;
	}

	return 0;
}
#endif /* defined(CONFIG_LWM2M_CARRIER) */

/**@brief Function to print strings without null-termination
 */
static void data_print(u8_t *prefix, u8_t *data, size_t len)
{
	char buf[len + 1];

	memcpy(buf, data, len);
	buf[len] = 0;
	LOG_INF("%s%s", log_strdup(prefix), log_strdup(buf));
}

/**@brief Function to publish data on the configured topic
 */
static int data_publish(struct mqtt_client *c, enum mqtt_qos qos,
	u8_t *data, size_t len)
{
	struct mqtt_publish_param param;

	param.message.topic.qos = qos;
	param.message.topic.topic.utf8 = CONFIG_MQTT_PUB_TOPIC;
	param.message.topic.topic.size = strlen(CONFIG_MQTT_PUB_TOPIC);
	param.message.payload.data = data;
	param.message.payload.len = len;
	param.message_id = sys_rand32_get();
	param.dup_flag = 0;
	param.retain_flag = 0;

	data_print("Publishing: ", data, len);
	LOG_INF("to topic: %s len: %u",
		CONFIG_MQTT_PUB_TOPIC,
		(unsigned int)strlen(CONFIG_MQTT_PUB_TOPIC));

	return mqtt_publish(c, &param);
}

/**@brief Function to subscribe to the configured topic
 */
static int subscribe(void)
{
	struct mqtt_topic subscribe_topic = {
		.topic = {
			.utf8 = CONFIG_MQTT_SUB_TOPIC,
			.size = strlen(CONFIG_MQTT_SUB_TOPIC)
		},
		.qos = MQTT_QOS_1_AT_LEAST_ONCE
	};

	const struct mqtt_subscription_list subscription_list = {
		.list = &subscribe_topic,
		.list_count = 1,
		.message_id = 1234
	};

	LOG_INF("Subscribing to: %s len %u", CONFIG_MQTT_SUB_TOPIC,
		(unsigned int)strlen(CONFIG_MQTT_SUB_TOPIC));

	return mqtt_subscribe(&client, &subscription_list);
}

/**@brief Function to read the published payload.
 */
static int publish_get_payload(struct mqtt_client *c, size_t length)
{
	if (length > sizeof(payload_buf)) {
		return -EMSGSIZE;
	}

	return mqtt_readall_publish_payload(c, payload_buf, length);
}

/**@brief MQTT client event handler
 */
void mqtt_evt_handler(struct mqtt_client *const c,
		      const struct mqtt_evt *evt)
{
	int err;

	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		if (evt->result != 0) {
			LOG_ERR("MQTT connect failed %d", evt->result);
			break;
		}

		connected = true;
		LOG_INF("MQTT client connected");
		subscribe();
		break;

	case MQTT_EVT_DISCONNECT:
		LOG_INF("MQTT client disconnected %d", evt->result);

		connected = false;
		break;

	case MQTT_EVT_PUBLISH: {
		const struct mqtt_publish_param *p = &evt->param.publish;
		bool disconnect = false;

		LOG_INF("MQTT PUBLISH result=%d len=%d",
			evt->result, p->message.payload.len);
		err = publish_get_payload(c, p->message.payload.len);
		if (err >= 0) {
			data_print("Received: ", payload_buf,
				p->message.payload.len);

			if (strncmp(payload_buf, DISCONNECT_STR,
			    strlen(DISCONNECT_STR)) == 0) {
				disconnect = true;
			    }
			/* Echo back received data */
			data_publish(&client, MQTT_QOS_1_AT_LEAST_ONCE,
				payload_buf, p->message.payload.len);
		} else {
			LOG_ERR("mqtt_read_publish_payload: Failed! %d", err);
			disconnect = true;
		}
		if (disconnect) {
			LOG_INF("Disconnecting MQTT client...");
			err = mqtt_disconnect(c);
			if (err) {
				LOG_ERR("Could not disconnect: %d", err);
			}
		}
	} break;

	case MQTT_EVT_PUBACK:
		if (evt->result != 0) {
			LOG_ERR("MQTT PUBACK error %d", evt->result);
			break;
		}

		LOG_INF("PUBACK packet id: %u", evt->param.puback.message_id);
		break;

	case MQTT_EVT_SUBACK:
		if (evt->result != 0) {
			LOG_ERR("MQTT SUBACK error %d", evt->result);
			break;
		}

		LOG_INF("SUBACK packet id: %u", evt->param.suback.message_id);
		break;

	default:
		LOG_INF("Unhandled MQTT event type: %d", evt->type);
		break;
	}
}

/**@brief Resolves the configured hostname and
 * initializes the MQTT broker structure
 */
static void broker_init(void)
{
	int err;
	struct addrinfo *result;
	struct addrinfo *addr;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM
	};

	err = getaddrinfo(CONFIG_MQTT_BROKER_HOSTNAME, NULL, &hints, &result);
	if (err) {
		LOG_ERR("getaddrinfo failed %d", err);
		return;
	}

	addr = result;
	err = -ENOENT;

	/* Look for address of the broker. */
	while (addr != NULL) {
		/* IPv4 Address. */
		if (addr->ai_addrlen == sizeof(struct sockaddr_in)) {
			struct sockaddr_in *broker4 =
				((struct sockaddr_in *)&broker);
			char ipv4_addr[NET_IPV4_ADDR_LEN];

			broker4->sin_addr.s_addr =
				((struct sockaddr_in *)addr->ai_addr)
				->sin_addr.s_addr;
			broker4->sin_family = AF_INET;
			broker4->sin_port = htons(CONFIG_MQTT_BROKER_PORT);

			inet_ntop(AF_INET, &broker4->sin_addr.s_addr,
				  ipv4_addr, sizeof(ipv4_addr));
			LOG_INF("IPv4 Address found %s", log_strdup(ipv4_addr));

			break;
		} else {
			LOG_ERR("ai_addrlen = %u should be %u or %u",
				(unsigned int)addr->ai_addrlen,
				(unsigned int)sizeof(struct sockaddr_in),
				(unsigned int)sizeof(struct sockaddr_in6));
		}

		addr = addr->ai_next;
		break;
	}

	/* Free the address. */
	freeaddrinfo(result);
}

/**@brief Initialize the MQTT client structure
 */
static void client_init(struct mqtt_client *client)
{
	mqtt_client_init(client);

	broker_init();

	/* MQTT client configuration */
	client->broker = &broker;
	client->evt_cb = mqtt_evt_handler;
	client->client_id.utf8 = (u8_t *)CONFIG_MQTT_CLIENT_ID;
	client->client_id.size = strlen(CONFIG_MQTT_CLIENT_ID);
	client->password = NULL;
	client->user_name = NULL;
	client->protocol_version = MQTT_VERSION_3_1_1;

	/* MQTT buffers configuration */
	client->rx_buf = rx_buffer;
	client->rx_buf_size = sizeof(rx_buffer);
	client->tx_buf = tx_buffer;
	client->tx_buf_size = sizeof(tx_buffer);

	/* MQTT transport configuration */
#if defined(CONFIG_MQTT_LIB_TLS)
	client->transport.type = MQTT_TRANSPORT_SECURE;

	/* TODO: add TLS config if secure transport is needed
	 * struct mqtt_sec_config *tls_config;
	 */
#else
	client->transport.type = MQTT_TRANSPORT_NON_SECURE;
#endif

}

/**@brief Initialize the file descriptor structure used by poll.
 */
static int fds_init(struct mqtt_client *c)
{
	if (c->transport.type == MQTT_TRANSPORT_NON_SECURE) {
		fds.fd = c->transport.tcp.sock;
	} else {
#if defined(CONFIG_MQTT_LIB_TLS)
		fds.fd = c->transport.tls.sock;
#else
		return -ENOTSUP;
#endif
	}

	fds.events = POLLIN;

	return 0;
}

#if !IS_ENABLED(CONFIG_LWM2M_CARRIER)
static void sms_receiver_notif_parse(void *ctx, const char *notif)
{
	int err;
	int length = strlen(notif);

	if ((length < 12) || (strncmp(notif, "+CMT:", 5) != 0)) {
		return;
	}

	err = at_cmd_write("AT+CNMA=1", NULL, 0, NULL);
	if (err) {
		LOG_ERR("Unable to ACK SMS notification");
	} else {
		LOG_INF("SMS ACKed");
	}
}

static int init_sms(void)
{
	int err = at_notif_register_handler(NULL, sms_receiver_notif_parse);
	if (err) {
		LOG_ERR("Failed to register AT handler, err %d", err);
		return err;
	}

	return at_cmd_write("AT+CNMI=3,2,0,1", NULL, 0, NULL);
}

static void send_sms(void)
{
	int err;
	char sms[] = "AT+CMGS=<n>\r<SMS content>_";

	sms[sizeof(sms) - 2] = '\x1a';

	LOG_INF("Sending SMS...");
	err = at_cmd_write(sms, NULL, 0, NULL);
	if (err < 0) {
		LOG_ERR("Failed to send SMS, error: %d", err);
		return;
	}

	LOG_INF("SMS sent");
}

static void button_handler(u32_t button_states, u32_t has_changed)
{
	u8_t btn_num;

	while (has_changed) {
		btn_num = 0;

		/* Get bit position for next button that changed state. */
		for (u8_t i = 0; i < 32; i++) {
			if (has_changed & BIT(i)) {
				btn_num = i + 1;
				break;
			}
		}

		/* Button number has been stored, remove from bitmask. */
		has_changed &= ~(1UL << (btn_num - 1));

		LOG_DBG("Button num: %u, state: %lu",
			btn_num, (button_states & BIT(btn_num - 1)));

		/* button one, pressed */
		if (btn_num == 1 &&button_states == 1) {
			send_sms();
		}
	}
}
#endif

/**@brief Configures modem to provide LTE link. Blocks until link is
 * successfully established.
 */
static int modem_configure(void)
{
#if defined(CONFIG_LTE_LINK_CONTROL)
	if (IS_ENABLED(CONFIG_LTE_AUTO_INIT_AND_CONNECT)) {
		/* Do nothing, modem is already turned on
		 * and connected.
		 */
	} else {
#if defined(CONFIG_LWM2M_CARRIER)
		/* Wait for the LWM2M_CARRIER to configure the modem and
		 * start the connection.
		 */
		LOG_INF("Waitng for carrier registration...");
		k_sem_take(&carrier_registered, K_FOREVER);
		LOG_INF("Registered!");
#else /* defined(CONFIG_LWM2M_CARRIER) */
		int err;

		err = init_sms();
		if (err) {
			LOG_ERR("Could not enable SMS");
			return err;
		} else {
			LOG_INF("SMS enabled");
		}

		LOG_INF("LTE Link Connecting...");
		err = lte_lc_init_and_connect();
		if (err) {
			LOG_INF("Failed to establish LTE connection: %d", err);
			return err;
		}
		LOG_INF("LTE Link Connected!");
#endif /* defined(CONFIG_LWM2M_CARRIER) */
	}
#endif /* defined(CONFIG_LTE_LINK_CONTROL) */

	return 0;
}

#define POLL_TIMEOUT_MS 500
void main(void)
{
	int err;
	uint32_t connect_attempt = 0;
	s64_t start_time;

	LOG_INF("The MQTT simple sample started");

#if !IS_ENABLED(CONFIG_LWM2M_CARRIER)
	dk_buttons_init(button_handler);
#endif

	do {
		err = modem_configure();
		if (err) {
			LOG_INF("Retrying in %d seconds.\n",
				LTE_CONNECT_RETRY_DELAY_S);
			k_sleep(K_SECONDS(LTE_CONNECT_RETRY_DELAY_S));
		}
	} while (err);

	start_time = k_uptime_get();
	client_init(&client);

do_connect:

#if defined(CONFIG_MQTT_LIB_TLS)
	if (atomic_get(&carrier_requested_disconnect)) {
		/* A disconnect was requested to free up the TLS socket
		 * used by the cloud.  If enabled, the carrier library
		 * (CONFIG_LWM2M_CARRIER) will perform FOTA updates in
		 * the background and reboot the device when complete.
		 */
		return;
	}
#endif

	if (connect_attempt > 0) {
		LOG_INF("Reconnecting in %d seconds...",
			CONFIG_MQTT_RECONNECT_DELAY_S);
		k_sleep(K_SECONDS(CONFIG_MQTT_RECONNECT_DELAY_S));
	}
	err = mqtt_connect(&client);
	if (err != 0) {
		LOG_ERR("mqtt_connect %d", err);
		goto do_connect;
	}

	err = fds_init(&client);
	if (err != 0) {
		LOG_ERR("fds_init %d", err);
		return;
	}

	while (1) {

#if !IS_ENABLED(CONFIG_LWM2M_CARRIER)
		s64_t time = start_time;
		if (start_time &&
		    (k_uptime_delta(&time) >= K_SECONDS(30))) {
			send_sms();
			/* only once */
			start_time = 0;
		}
#endif

		err = poll(&fds, 1, POLL_TIMEOUT_MS);
		if (err < 0) {
			LOG_ERR("poll %d", errno);
			break;
		}

		if (err == 0) {
			if (mqtt_keepalive_time_left(&client) <
			    (POLL_TIMEOUT_MS + 5000)) {
				mqtt_live(&client);
			}
			continue;
		}

		if ((fds.revents & POLLIN) == POLLIN) {
			err = mqtt_input(&client);
			if (err != 0) {
				LOG_ERR("mqtt_input %d", err);
				break;
			}
		}

		if ((fds.revents & POLLERR) == POLLERR) {
			LOG_ERR("POLLERR");
			break;
		}

		if ((fds.revents & POLLNVAL) == POLLNVAL) {
			LOG_ERR("POLLNVAL");
			break;
		}
	}

	(void)mqtt_disconnect(&client);

	++connect_attempt;
	goto do_connect;
}
