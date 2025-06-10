#ifndef FREQUENCY_ANALYSIS_H
#define FREQUENCY_ANALYSIS_H

#include <stdint.h>
#include "../tools/centralized_config.h"

// #define TIME_WINDOW  5000 
// #define ATTACK_TYPE_COUNT  5 
// #define MAX_TRACKED_SOURCES 50
#define MAX_EVENTS_PER_SOURCE 60
typedef struct
{
    uint8_t mac[6];
    uint32_t timestamps[MAX_EVENTS_PER_SOURCE];
    uint32_t count; // nº de timestamps válidos en ventana
    bool alerted;   // si ya hemos alertado para esta entry
} frequency_entry_t;

typedef struct
{
    frequency_entry_t entries[MAX_TRACKED_SOURCES];
    uint32_t num_entries;
    uint32_t time_window;      // ms
    uint32_t attack_threshold; // nº eventos para alerta
} frequency_tracker_t;

void init_frequency_tracker(frequency_tracker_t *tracker, uint32_t time_window_ms, uint32_t attack_threshold);
void reconfigure_frequency_tracker(frequency_tracker_t *tracker, uint32_t time_window_ms, uint32_t attack_threshold);
void update_frequency(frequency_tracker_t *tracker, const uint8_t source_mac[6], uint32_t current_time_ms);
bool detect_high_frequency_once(frequency_tracker_t *tracker, const uint8_t source_mac[6], uint32_t current_time_ms);
bool detect_high_frequency(frequency_tracker_t *tracker, const uint8_t source_mac[6], uint32_t current_time_ms);
uint32_t get_tracker_count(const frequency_tracker_t *t, const uint8_t key[6]);

#endif
