#ifndef EVIL_TWIN_H
#define EVIL_TWIN_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "sdkconfig.h"
#include "esp_mac.h"
#include "../../components/mqtt_communication/network_status.h"
#include "../tools/centralized_config.h"
#include "../sniffer_module.h"
#include "../wifi_station.h"

#define MAX_MESH_ID_LEN 64
#define MAX_APS 60

typedef struct
{
    uint8_t mac[6];
    char ssid[50];
    int8_t signal_strength;
    uint32_t timestamp;
    uint32_t last_alert_ts; // Timestamp (en ms) de la última alerta emitida
    uint8_t mesh_id[MAX_MESH_ID_LEN];
    uint8_t mesh_id_len;
} detected_ap_t;
typedef struct
{
    detected_ap_t aps[MAX_APS]; // Array of detected APs
    int current_index;
} ap_history_t;

void initialize_evil_twin();

void add_ap_to_history(ap_history_t *history, const uint8_t *mac, const char *ssid, int8_t signal_strength, uint32_t timestamp, const wifi_packet_t *pkt);

bool detect_evil_twin(ap_history_t *history, const uint8_t *mac, const char *ssid, int8_t signal_strength);

void analyze_evil_twin(const wifi_packet_t *wifi_pkt);

void update_evil_twin_config();

#endif
