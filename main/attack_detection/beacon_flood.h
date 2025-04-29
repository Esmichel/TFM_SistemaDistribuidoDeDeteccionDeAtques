#ifndef BEACON_FLOOD_H
#define BEACON_FLOOD_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include <string.h>
#include "esp_log.h"
#include "../detection_methods/frequency_analysis.h"
#include "../tools/hash_function.h"
#include "../tools/centralized_config.h"
#include "../sniffer_module.h"

typedef struct {
    char ssid[33];    
    uint8_t bssid[6];
    frequency_tracker_t frequency_tracker;
} beacon_stats_t;

void detect_beacon_flood(wifi_packet_t *pkt);

void reset_beacon_stats();

void initialize_beacon_detection();

#endif 