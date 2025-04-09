#include "beacon_flood.h"
#include "esp_log.h"
#include "detection_methods/frequency_analysis.h"
#include <string.h>
#include <sys/time.h>
#include "../tools/hash_function.h"

#define ATTACK_TYPE_BEACON_FLOOD 4 
#define BEACON_EXPIRATION_TIME 60000 

static const char *TAG = "beacon_flood";
beacon_stats_t beacon_stats; 
frequency_entry_t *frequency_tracker_entry;

bool is_entry_stale(uint32_t last_timestamp, uint32_t current_timestamp)
{
    return (current_timestamp - last_timestamp > BEACON_EXPIRATION_TIME);
}


void detect_beacon_flood(wifi_packet_t *pkt)
{
    if (pkt->subtype != 0x08)
        return;

    uint32_t timestamp = pkt->timestamp;

    char ssid[33];
    if (pkt->ssid[0] == 0)
    {
        snprintf(ssid, sizeof(ssid), "<Hidden>");
    }
    else
    {
        strncpy(ssid, (char *)pkt->ssid, sizeof(ssid) - 1);
        ssid[32] = '\0';
    }
    uint32_t ssid_hash = hash_ssid((char *)ssid);

    for (int i = 0; i < MAX_TRACKED_SOURCES; i++)
    {
        /*if (is_entry_stale(beacon_stats.frequency_tracker.entries[i].last_timestamp, timestamp))
        {
            // Clean up expired entry
            memset(&beacon_stats.frequency_tracker.entries[i], 0, sizeof(frequency_entry_t)); // Reset the entry
            beacon_stats.frequency_tracker.count--;                                                                // Decrease tracked sources count
        }*/
    }

    frequency_tracker_entry = NULL;
    for (int i = 0; i < beacon_stats.frequency_tracker.count; i++)
    {
        if (beacon_stats.frequency_tracker.entries[i].source == ssid_hash)
        {
            frequency_tracker_entry = &beacon_stats.frequency_tracker.entries[i];
            break;
        }
    }

    if (frequency_tracker_entry == NULL)
    {
        if (beacon_stats.frequency_tracker.count < MAX_TRACKED_SOURCES)
        {

            frequency_tracker_entry = &beacon_stats.frequency_tracker.entries[beacon_stats.frequency_tracker.count];
            memset(frequency_tracker_entry, 0, sizeof(frequency_entry_t));
            frequency_tracker_entry->source = ssid_hash;
            //frequency_tracker_entry->source[sizeof(frequency_tracker_entry->source) - 1] = '\0';
            frequency_tracker_entry->last_timestamp = timestamp;

            beacon_stats.frequency_tracker.count++;
            ESP_LOGI(TAG, "hash : %d and ssid : %s", ssid_hash, ssid);
            ESP_LOGI(TAG, "New source added: %d", frequency_tracker_entry->source);
            ESP_LOGI(TAG, "All tracked sources:");
            for (int i = 0; i < beacon_stats.frequency_tracker.count; i++)
            {
                ESP_LOGI(TAG, " - %d", beacon_stats.frequency_tracker.entries[i].source);
            }
        }
        else
        {
            ESP_LOGW(TAG, "Maximum number of tracked beacons reached, cannot add new SSID");
            return;
        }
    }

    update_frequency(&beacon_stats.frequency_tracker, &ssid_hash, timestamp);
    if (frequency_tracker_entry->attack_count == 0) {
        ESP_LOGW(TAG, "Attack count is 0, no action taken");
    } else if (frequency_tracker_entry->attack_count % 10 == 0 ){
        ESP_LOGI(TAG, "Beacon Flood Count for SSID %d: %d with timestamp %d",
            frequency_tracker_entry->source,
            frequency_tracker_entry->attack_count, timestamp);
    }

    if (detect_high_frequency(&beacon_stats.frequency_tracker, &ssid_hash, timestamp))
    {
        ESP_LOGW(TAG, "Beacon Flood Attack Detected! SSID: %d, BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
                 frequency_tracker_entry->source,
                 pkt->src_mac[0], pkt->src_mac[1], pkt->src_mac[2],
                 pkt->src_mac[3], pkt->src_mac[4], pkt->src_mac[5]);
    }
}

void initialize_beacon_detection()
{
    memset(&beacon_stats, 0, sizeof(beacon_stats));
    init_frequency_tracker(&beacon_stats.frequency_tracker, 5000, 50);
    for (int i = 0; i < MAX_TRACKED_SOURCES; i++)
    {
        memset(&beacon_stats.frequency_tracker.entries[i], 0, sizeof(frequency_entry_t));
    }
    beacon_stats.frequency_tracker.count = 0;
}
