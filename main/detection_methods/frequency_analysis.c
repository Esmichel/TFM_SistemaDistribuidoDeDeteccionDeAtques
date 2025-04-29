#include "frequency_analysis.h"

#include "esp_log.h"
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

static const char *TAG = "frequency_analysis";
// loaded config values
int time_window_frequency = 0;

void initialize_frequency_analysis()
{
    AppConfig *config = get_config();
    time_window_frequency = config->time_window_frequency;
}

void init_frequency_analysis(attack_frequency_t *frequency_data)
{
    AppConfig *config = get_config();
    time_window_frequency = config->time_window_frequency;
    memset(frequency_data, 0, sizeof(attack_frequency_t));
}

void update_attack_count(attack_frequency_t *frequency_data, uint32_t timestamp, attack_type_t attack_type)
{
    if (timestamp / time_window_frequency > frequency_data->last_timestamp / time_window_frequency)
    {
        ESP_LOGI(TAG, "Resetting attack counts (New Time Window) - Previous: %d, Current: %d",
                 frequency_data->last_timestamp, timestamp);
        memset(frequency_data->attack_counts, 0, sizeof(frequency_data->attack_counts));
    }

    frequency_data->attack_counts[attack_type]++;
    frequency_data->last_timestamp = timestamp;
}

bool detect_attack_frequency(attack_frequency_t *frequency_data, uint32_t timestamp, attack_type_t attack_type)
{
    if (frequency_data->attack_counts[attack_type] > ATTACK_THRESHOLDS[attack_type])
    {
        return true;
    }
    return false;
}

void clear_frequency_data(attack_frequency_t *frequency_data)
{
    memset(frequency_data, 0, sizeof(attack_frequency_t));
}

void init_frequency_tracker(frequency_tracker_t *tracker, uint32_t time_window_frequency, uint32_t attack_threshold)
{
    memset(tracker, 0, sizeof(frequency_tracker_t));
    tracker->time_window = time_window_frequency;
    tracker->attack_threshold = attack_threshold;
}

static frequency_entry_t *find_or_create_entry(frequency_tracker_t *tracker, uint32_t *source, uint32_t timestamp)
{
    for (int i = 0; i < tracker->count; i++)
    {
        if (tracker->entries[i].source == *source)
        {
            return &tracker->entries[i];
        }
    }

    // Add new source if space available
    /*if (tracker->count < MAX_TRACKED_SOURCES)
    {
        frequency_entry_t *new_entry = &tracker->entries[tracker->count++];
        memcpy(new_entry->source, source, sizeof(new_entry->source));
        new_entry->attack_count = 0;
        new_entry->last_timestamp = timestamp;
        ESP_LOGI(TAG, "Tracking new source: %02X:%02X:%02X:%02X:%02X:%02X",
                 source[0], source[1], source[2], source[3], source[4], source[5]);
        return new_entry;
    }*/

    ESP_LOGW(TAG, "Maximum sources tracked, unable to add new entry.");
    return NULL; 
}

void update_frequency(frequency_tracker_t *tracker, uint32_t *source, uint32_t timestamp)
{
    frequency_entry_t *entry = find_or_create_entry(tracker, source, timestamp);
    if (!entry)
        return;

    if (timestamp / tracker->time_window > entry->last_timestamp / tracker->time_window)
    {
        ESP_LOGI(TAG, "Resetting attack count for source %02X:%02X:%02X:%02X:%02X:%02X",
                 source[0], source[1], source[2], source[3], source[4], source[5]);
        entry->attack_count = 0;
        entry->last_timestamp = timestamp;
    }

    entry->attack_count++;
}

bool detect_high_frequency(frequency_tracker_t *tracker, uint32_t *source, uint32_t timestamp)
{
    frequency_entry_t *entry = find_or_create_entry(tracker, source, timestamp);
    if (!entry)
        return false;

    if (entry->attack_count > tracker->attack_threshold)
    {
        ESP_LOGW(TAG, "Attack detected from %02X:%02X:%02X:%02X:%02X:%02X - Count: %d, Threshold: %d",
                 source[0], source[1], source[2], source[3], source[4], source[5],
                 entry->attack_count, tracker->attack_threshold);
        return true;
    }
    return false;
}

void clear_frequency_tracker(frequency_tracker_t *tracker)
{
    memset(tracker, 0, sizeof(frequency_tracker_t));
}
