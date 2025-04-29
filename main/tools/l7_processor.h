#ifndef L7_PROCESSOR_H
#define L7_PROCESSOR_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
//#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <math.h>
#include <sys/socket.h>
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_log.h"
#include "centralized_config.h"
#include "./attack_detection/mac_spoofing.h"
#include "../sniffer_module.h"
#include "../MQTT_Comunication/network_status.h"

void l7_processor_init(void);
void process_wifi_frame(const uint8_t *frame, uint16_t length, wifi_packet_t *wifi_pkt);
void process_ip_packet(const uint8_t *payload, uint16_t length, wifi_packet_t *wifi_pkt);
void process_tcp_packet(const uint8_t *payload, uint16_t length);
void process_layer_7_data(const uint8_t *payload, uint16_t length);

#define ETH_TYPE_IP 0x0800

#endif
