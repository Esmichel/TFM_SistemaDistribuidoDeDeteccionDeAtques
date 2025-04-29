#ifndef FREQUENCY_ANALYSIS_H
#define FREQUENCY_ANALYSIS_H

#include <stdint.h>
#include "../tools/centralized_config.h"

// #define TIME_WINDOW  5000 
// #define ATTACK_TYPE_COUNT  5 
// #define MAX_TRACKED_SOURCES 50

typedef enum {
    ATTACK_TYPE_DEAUTH,
    ATTACK_TYPE_MAC_SPOOFING,
    ATTACK_TYPE_BROADCAST,
    ATTACK_TYPE_MASS_DEAUTH,
    ATTACK_TYPE_BEACON_FLOOD
} attack_type_t;

static const uint32_t ATTACK_THRESHOLDS[ATTACK_TYPE_COUNT] = {
    10,  
    8,  
    15,
    30,
    100
};

typedef struct {
    uint32_t attack_counts[ATTACK_TYPE_COUNT];
    uint32_t last_timestamp;
} attack_frequency_t;



typedef struct {
    uint32_t source;
    uint32_t attack_count;
    uint32_t last_timestamp;
} frequency_entry_t;

typedef struct {
    frequency_entry_t entries[MAX_TRACKED_SOURCES];
    int count;
    uint32_t time_window;
    uint32_t attack_threshold;
} frequency_tracker_t;


void init_frequency_analysis(attack_frequency_t *frequency_data);
void update_attack_count(attack_frequency_t *frequency_data, uint32_t timestamp, attack_type_t attack_type);
bool detect_attack_frequency(attack_frequency_t *frequency_data, uint32_t timestamp, attack_type_t attack_type);
void clear_frequency_data(attack_frequency_t *frequency_data);
void init_frequency_tracker(frequency_tracker_t *tracker, uint32_t time_window, uint32_t attack_threshold);
void update_frequency(frequency_tracker_t *tracker, uint32_t *source, uint32_t timestamp);
void clear_frequency_tracker(frequency_tracker_t *tracker);
bool detect_high_frequency(frequency_tracker_t *tracker, uint32_t *source, uint32_t timestamp);
void initialize_frequency_analysis();

#endif
