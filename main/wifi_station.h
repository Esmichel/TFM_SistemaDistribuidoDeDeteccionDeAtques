#ifndef WIFI_STATION_H
#define WIFI_STATION_H

#include "esp_wifi.h"
#include <stdio.h>
#include <stdbool.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_err.h"
#include "esp_system.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "../components/mqtt_communication/network_status.h"
#include "./tools/mac_address_module.h"
#include "tools/centralized_config.h"

void wifi_init_sta(bool connect_to_ap);
void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
bool wait_for_wifi_connection();
void switch_wifi_mode(bool enable_sniffer);
void revert_to_normal_mode(void *arg);
void start_dedicated_listening_mode(const wifi_packet_t *evil_pkt);

#endif