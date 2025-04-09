#include "mac_analysis.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "mac_analysis";
void init_mac_history(mac_history_t *history) {
    memset(history, 0, sizeof(mac_history_t));
}

void add_mac_to_history(mac_history_t *history, const uint8_t *mac, uint32_t timestamp) {
    for (int i = 0; i < MAC_HISTORY_SIZE; i++) {
        if (memcmp(history->entries[i].mac, mac, 6) == 0) {
            history->entries[i].last_seen = timestamp;
            history->entries[i].count++;
            return;
        }
    }

    memcpy(history->entries[history->current_index].mac, mac, 6);
    history->entries[history->current_index].first_seen = timestamp;
    history->entries[history->current_index].last_seen = timestamp;
    history->entries[history->current_index].count = 1;
    history->current_index = (history->current_index + 1) % MAC_HISTORY_SIZE;
}

mac_analysis_result_t analyze_mac_activity(mac_history_t *history, const uint8_t *src_mac, const uint8_t *dst_mac, uint32_t timestamp) {
    mac_analysis_result_t result = {0};

    int active_macs = 0;
    int affected_targets = 0;

    for (int i = 0; i < MAC_HISTORY_SIZE; i++) {
        if (history->entries[i].last_seen == 0) {
            continue;
        }

        if ((timestamp - history->entries[i].last_seen) < TIME_WINDOW) {
            active_macs++;
        }

        if (memcmp(history->entries[i].mac, src_mac, 6) == 0) {
            if ((timestamp - history->entries[i].last_seen) < SPOOFING_TIME_THRESHOLD) {
                result.spoofing_detected = true;
            }
        }

        if (memcmp(history->entries[i].mac, dst_mac, 6) == 0) {
            affected_targets++;
            ESP_LOGI(TAG, "Affected targets: %d", affected_targets);
        }
    }

    result.active_macs = active_macs;
    result.affected_targets = affected_targets;

    return result;
}
