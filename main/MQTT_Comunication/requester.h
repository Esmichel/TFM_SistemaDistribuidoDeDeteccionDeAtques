#ifndef REQUESTER_H
#define REQUESTER_H

#include "esp_err.h"

#define BROKER_URI "mqtt://192.168.1.103"
#define REQUEST_TOPIC "rabbitmq/exchange/devices_request_exchange"
#define RESPONSE_TOPIC_FORMAT "rabbitmq/queue/%s"
#define DISCOVERY_TOPIC "sistema/nuevos_dispositivos"
#define MONITORING_TOPIC "sistema/monitores/%s"
#define ARP_TOPIC "sistema/arptable/%s"

void mqtt_app_start();

void device_a_publish_request();

void send_mqtt_message(const char* topic, const char* payload);

void mqtt_app_stop();

#endif
