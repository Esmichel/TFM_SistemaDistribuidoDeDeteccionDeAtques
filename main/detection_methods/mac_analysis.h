#ifndef MAC_ANALYSIS_H
#define MAC_ANALYSIS_H

#include <stdint.h>
#include <stdbool.h>
#include "../tools/centralized_config.h"

// #define MAC_HISTORY_SIZE 50    
// #define TIME_WINDOW 5000       
// #define SPOOFING_TIME_THRESHOLD 1000 
// #define BROADCAST_MAC ((uint8_t[]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})



typedef struct {
    uint8_t mac[6];
    uint32_t first_seen;
    uint32_t last_seen;
    int count;
} mac_entry_t;

typedef struct {
    mac_entry_t entries[MAC_HISTORY_SIZE];
    int current_index;
} mac_history_t;

typedef struct {
    bool spoofing_detected;
    int active_macs;
    int affected_targets;
} mac_analysis_result_t;

void init_mac_history(mac_history_t *history);
void add_mac_to_history(mac_history_t *history, const uint8_t *mac, uint32_t timestamp);
mac_analysis_result_t analyze_mac_activity(mac_history_t *history, const uint8_t *src_mac, const uint8_t *dst_mac, uint32_t timestamp);
void init_mac_analysis(void);

#endif
