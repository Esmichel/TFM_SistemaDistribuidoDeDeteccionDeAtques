#include "deauth_attack.h"
#include "tools/l3_processor.h"
#include "tools/centralized_config.h"
#include "detection_methods/frequency_analysis.h"
#include "esp_log.h"
#include <stdbool.h>
#include <string.h>

#define TAG "deauth_attack_detector"

static frequency_tracker_t deauth_freq_tracker;
static frequency_tracker_t disassoc_freq_tracker;
static int mass_deauth_threshold = 1;
static mac_history_t global_mac_history;

static uint32_t get_current_time_ms(void)
{
    return esp_timer_get_time() / 1000;
}

static bool is_deauth_packet(const wifi_packet_t *pkt)
{
    return pkt->type == 0x00 && pkt->subtype == DEAUTH_PACKET;
}

static bool is_disassoc_packet(const wifi_packet_t *pkt)
{
    return pkt->type == 0x00 && pkt->subtype == DISASOCIATION_PACKET;
}

static bool check_broadcast_deauth(const wifi_packet_t *pkt)
{
    return memcmp(pkt->dst_mac, BROADCAST_MAC, 6) == 0;
}

static bool check_directed_deauth(const mac_analysis_result_t *res)
{
    return (res->affected_targets == 1);
}

static bool check_mass_deauth(const mac_analysis_result_t *res)
{
    return (res->affected_targets > mass_deauth_threshold);
}

static void log_deauth_alert(const char *what,
                             const uint8_t mac[6],
                             frequency_tracker_t *tracker,
                             const uint8_t key[6],
                             const wifi_packet_t *pkt,
                             const char *attack_msg)
{

    uint32_t count = 0;
    for (uint32_t i = 0; i < tracker->num_entries; ++i)
    {
        if (memcmp(tracker->entries[i].mac, key, 6) == 0)
        {
            count = tracker->entries[i].count;
            break;
        }
    }

    ESP_LOGW(TAG, "%s", attack_msg);
    build_attack_alert_payload((wifi_packet_t *)pkt, (char *)attack_msg);
}
static void evaluate_attack(const wifi_packet_t *pkt,
                            frequency_tracker_t *tracker,
                            const char *label)
{
    uint32_t now = get_current_time_ms();

    update_frequency(tracker, pkt->src_mac, now);
    bool freq_alert = detect_high_frequency_once(tracker, pkt->src_mac, now);

    add_mac_to_history(&global_mac_history, pkt->src_mac, now);
    add_mac_to_history(&global_mac_history, pkt->dst_mac, now);

    mac_analysis_result_t mac_res = analyze_mac_activity(
        &global_mac_history,
        pkt->src_mac,
        pkt->dst_mac,
        now);

    char attack_type[32] = {0};
    if (mac_res.spoofing_detected)
        strncpy(attack_type, "MAC Spoofing", sizeof(attack_type) - 1);
    else if (check_broadcast_deauth(pkt))
        strncpy(attack_type, "Broadcast", sizeof(attack_type) - 1);
    else if (check_directed_deauth(&mac_res))
        strncpy(attack_type, "Directed", sizeof(attack_type) - 1);
    else if (check_mass_deauth(&mac_res))
        strncpy(attack_type, "Mass", sizeof(attack_type) - 1);

    if (mac_res.spoofing_detected || freq_alert)
    {
        uint8_t key[6];
        memcpy(key, pkt->src_mac, 6);

        char alert_msg[128];
        int len = snprintf(alert_msg, sizeof(alert_msg),
                           "%s Flood from %02X:%02X:%02X:%02X:%02X:%02X – count=%lu/%lu window=%lums",
                           label,
                           pkt->src_mac[0], pkt->src_mac[1], pkt->src_mac[2],
                           pkt->src_mac[3], pkt->src_mac[4], pkt->src_mac[5],
                           get_tracker_count(tracker, key),
                           tracker->attack_threshold,
                           tracker->time_window);
        if (len < 0 || (size_t)len >= sizeof(alert_msg))
        {
            alert_msg[sizeof(alert_msg) - 1] = '\0';
        }
        log_deauth_alert(label, pkt->src_mac, tracker, key, pkt, alert_msg);
    }
}

void check_for_deauth_attack(const wifi_packet_t *pkt)
{
    if (is_deauth_packet(pkt))
    {
        ESP_LOGI(TAG, "Detected DEAUTH packet");
        evaluate_attack(pkt, &deauth_freq_tracker, "Deauth");
    }
    else if (is_disassoc_packet(pkt))
    {
        ESP_LOGI(TAG, "Detected DISASSOC packet");
        evaluate_attack(pkt, &disassoc_freq_tracker, "Disassoc");
    }
}

void initialize_deauth_detection(void)
{
    const AppConfig *cfg = get_config();
    mass_deauth_threshold = cfg->mass_deauth_threshold;

    init_frequency_tracker(
        &deauth_freq_tracker,
        cfg->deauth_time_window,
        cfg->deauth_frequency_threshold);

    init_frequency_tracker(
        &disassoc_freq_tracker,
        cfg->deauth_time_window,
        cfg->deauth_frequency_threshold);

    ESP_LOGI(TAG, "Deauth detector initialized");
}

void reload_deauth_detection_config(void)
{
    const AppConfig *cfg = get_config();
    mass_deauth_threshold = cfg->mass_deauth_threshold;

    reconfigure_frequency_tracker(
        &deauth_freq_tracker,
        cfg->deauth_time_window,
        cfg->deauth_frequency_threshold);

    reconfigure_frequency_tracker(
        &disassoc_freq_tracker,
        cfg->deauth_time_window,
        cfg->deauth_frequency_threshold);

    ESP_LOGI(TAG, "Deauth config reloaded");
}
