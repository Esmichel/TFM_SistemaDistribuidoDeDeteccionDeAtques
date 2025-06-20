#ifndef NETWORK_STATUS_H
#define NETWORK_STATUS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "cJSON.h"
#include "requester.h"
#include "esp_system.h"
#include "esp_wifi_types.h"
#include "esp_event.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "mbedtls/base64.h"
#include "../../main/sniffer_module.h"
#include "../../main/tools/base64encoding.h"
#include "../../main/tools/hash_function.h"
#include "../../main/tools/arp_table.h"
#include "../../main/tools/centralized_config.h"

#define MAX_PACKET_SIZE 2048
#define MAX_MAC_ADDRESS_LEN 18

void send_wifi_packet_json(wifi_packet_t *wifi_pkt);
void send_network_status(void);
//void build_wifi_packet_message(wifi_promiscuous_pkt_t *packet);
char *mac_to_string(uint8_t *mac);
void send_mqtt_message(const char *topic, const char *payload);
void build_arp_table_json_payload(arp_entry_t *arp_table, int arp_table_size, char *type);
void build_attack_alert_payload(wifi_packet_t *wifi_pkt, char *attack);
void send_alert(const wifi_packet_t *pkt, const char *fmt, ...);
void build_monitoring_payload();


#endif