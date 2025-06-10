#include "beacon_flood.h"
#include "tools/centralized_config.h"
#include "detection_methods/frequency_analysis.h"
#include "../../components/mqtt_communication/network_status.h"
#include "esp_log.h"
#include <string.h>
#include <stdint.h>

#define TAG "beacon_flood"


typedef struct
{
    frequency_tracker_t per_source_tracker;
    frequency_tracker_t global_tracker;
    uint32_t beacon_expiration_time;
} beacon_stats_t;

static beacon_stats_t beacon_stats;

void initialize_beacon_detection(void)
{
    const AppConfig *cfg = get_config();
    beacon_stats.beacon_expiration_time = cfg->beacon_expiration_time;

    init_frequency_tracker(
        &beacon_stats.per_source_tracker,
        cfg->time_window,
        cfg->beacon_per_source_threshold
        // cfg->max_tracked_sources
    );
    init_frequency_tracker(
        &beacon_stats.global_tracker,
        cfg->time_window,
        cfg->beacon_global_threshold
        // 1
    );

    ESP_LOGI(TAG,
             "BeaconFlood init: expire=%ums, window=%ums, "
             "per-src-thr=%u, global-thr=%u",
             beacon_stats.beacon_expiration_time,
             cfg->time_window,
             cfg->beacon_per_source_threshold,
             cfg->beacon_global_threshold);
}

void reload_beacon_detection_config(void)
{
    const AppConfig *cfg = get_config();
    beacon_stats.beacon_expiration_time = cfg->beacon_expiration_time;

    reconfigure_frequency_tracker(
        &beacon_stats.per_source_tracker,
        cfg->time_window,
        cfg->beacon_per_source_threshold);
    reconfigure_frequency_tracker(
        &beacon_stats.global_tracker,
        cfg->time_window,
        cfg->beacon_global_threshold);

    ESP_LOGI(TAG,
             "BeaconFlood reloaded: expire=%ums, window=%ums, "
             "per-src-thr=%u, global-thr=%u",
             beacon_stats.beacon_expiration_time,
             cfg->time_window,
             cfg->beacon_per_source_threshold,
             cfg->beacon_global_threshold);
}

// void deinit_beacon_detection(void)
// {
//     free_frequency_tracker(&beacon_stats.per_source_tracker);
//     free_frequency_tracker(&beacon_stats.global_tracker);
// }

void detect_beacon_flood(wifi_packet_t *pkt)
{
    if (pkt->subtype != 0x08) {
        return;
    }

    uint32_t now = esp_timer_get_time() / 1000;
    uint8_t bssid_key[BSSID_KEY_LEN];
    memcpy(bssid_key, pkt->src_mac, BSSID_KEY_LEN);
    update_frequency(&beacon_stats.per_source_tracker, bssid_key, now);
    uint8_t global_key[BSSID_KEY_LEN] = GLOBAL_KEY;
    update_frequency(&beacon_stats.global_tracker, global_key, now);

    bool per_src_flood = detect_high_frequency_once(
        &beacon_stats.per_source_tracker, bssid_key, now);
    bool global_flood = detect_high_frequency_once(
        &beacon_stats.global_tracker, global_key, now);

    if (per_src_flood || global_flood) {
        uint32_t cnt_src  = get_tracker_count(&beacon_stats.per_source_tracker, bssid_key);
        uint32_t cnt_glob = get_tracker_count(&beacon_stats.global_tracker,    global_key);

        char alert_msg[128];
        int len = snprintf(alert_msg, sizeof(alert_msg),
            "Beacon Flood: %s%s BSSID=%02X:%02X:%02X:%02X:%02X:%02X, "
            "cnt_src=%lu/%lu, cnt_glob=%lu/%lu in %lums",
            per_src_flood ? "[UnicaFuente]" : "",
            global_flood  ? "[Global]"      : "",
            bssid_key[0], bssid_key[1], bssid_key[2],
            bssid_key[3], bssid_key[4], bssid_key[5],
            cnt_src,
            beacon_stats.per_source_tracker.attack_threshold,
            cnt_glob,
            beacon_stats.global_tracker.attack_threshold,
            beacon_stats.per_source_tracker.time_window
        );
        if (len < 0 || (size_t)len >= sizeof(alert_msg)) {
            alert_msg[sizeof(alert_msg)-1] = '\0';
        }
        ESP_LOGW(TAG, "%s", alert_msg);
        build_attack_alert_payload(pkt, alert_msg);
    }
}
