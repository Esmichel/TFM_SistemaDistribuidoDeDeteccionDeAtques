#ifndef BEACON_FLOOD_H
#define BEACON_FLOOD_H

#include <stdint.h>
#include <stdbool.h>
#include "sniffer_module.h"
#include "../detection_methods/frequency_analysis.h"


typedef struct {
    char ssid[33];    
    uint8_t bssid[6];
    frequency_tracker_t frequency_tracker;
} beacon_stats_t;


void detect_beacon_flood(wifi_packet_t *pkt);

void reset_beacon_stats();

void initialize_beacon_detection();

#endif 