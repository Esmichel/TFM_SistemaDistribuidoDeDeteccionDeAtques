#ifndef REQUESTER_H
#define REQUESTER_H


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include "esp_err.h"
#include "mqtt_client.h"
#include "esp_log.h"
#include "string.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "cJSON.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "../tools/centralized_config.h"

#define BROKER_URI "mqtt://192.168.1.103"
#define REQUEST_TOPIC "rabbitmq/exchange/devices_request_exchange"
#define RESPONSE_TOPIC_FORMAT "rabbitmq/queue/%s"
#define DISCOVERY_TOPIC "sistema/nuevos_dispositivos"
#define MONITORING_TOPIC "sistema/monitores/%s"
#define ARP_TOPIC "sistema/arptable/%s"
#define ALERT_TOPIC "sistema/alertas/%s"

void mqtt_app_start();

void device_a_publish_request();

void send_mqtt_message(const char* topic, const char* payload);

void mqtt_app_stop();

#endif
