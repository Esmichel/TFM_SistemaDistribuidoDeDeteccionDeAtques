
#include "deauth_attack.h"
#include "tools/l3_processor.h"
#include "tools/centralized_config.h"
#include "esp_log.h"
#include <string.h>

#define TAG "deauth_attack_detector"

typedef struct {
    mac_history_t     mac_history;
    attack_frequency_t frequency_data;
    uint32_t          last_update_time_ms;
    uint32_t          current_time_ms;
} deauth_detection_state_t;


static deauth_detection_state_t deauth_detection_state;
static frequency_tracker_t deauth_frequency_tracker;

static int mass_deauth_threshold = 0;

static uint32_t get_current_time_ms()
{
    return esp_timer_get_time() / 1000;
}

static void update_current_time()
{
    uint32_t new_time = get_current_time_ms();
    if (new_time - deauth_detection_state.last_update_time_ms >= 1000) {
        deauth_detection_state.current_time_ms = new_time;
        deauth_detection_state.last_update_time_ms = new_time;
    }
}

static bool is_deauth_attack_packet(const wifi_packet_t *packet)
{
    return (packet->type == 0x00 && packet->subtype == DEAUTH_PACKET);
}

static bool check_mass_deauth(const mac_analysis_result_t *mac_result)
{
    return (mac_result->affected_targets > mass_deauth_threshold);
}

static bool check_broadcast_deauth(const wifi_packet_t *packet)
{
    return (memcmp(packet->dst_mac, BROADCAST_MAC, 6) == 0);
}

static bool check_directed_deauth(const mac_analysis_result_t *mac_result)
{
    return (mac_result->affected_targets == 1);
}

void evaluate_deauth_attack(const wifi_packet_t *packet)
{
    uint32_t ssid_hash = hash_ssid((const char *)packet->src_mac);

    update_frequency(&deauth_frequency_tracker, &ssid_hash, deauth_detection_state.current_time_ms);
    add_mac_to_history(&deauth_detection_state.mac_history, packet->src_mac, deauth_detection_state.current_time_ms);
    add_mac_to_history(&deauth_detection_state.mac_history, packet->dst_mac, deauth_detection_state.current_time_ms);

    mac_analysis_result_t mac_result = analyze_mac_activity(
        &deauth_detection_state.mac_history,
        packet->src_mac,
        packet->dst_mac,
        deauth_detection_state.current_time_ms
    );

    char attack_type[50] = {0};
    bool directed = false, mass = false, broadcast = false;

    if (detect_attack_frequency(
            &deauth_detection_state.frequency_data,
            deauth_detection_state.current_time_ms,
            ATTACK_TYPE_DEAUTH))
    {
        // Factor 1: Ataque basado en frecuencia detectado
        // No cambia la salida directa, solo afecta a lógicas agregadas si amplías
    }

    if (mac_result.spoofing_detected) {
        strncpy(attack_type, "MAC Spoofing Detectado", sizeof(attack_type) - 1);
    }

    if (check_mass_deauth(&mac_result)) {
        strncpy(attack_type, "Deautenticación Masiva", sizeof(attack_type) - 1);
        mass = true;
    }
    else if (check_broadcast_deauth(packet)) {
        strncpy(attack_type, "Deautenticación Broadcast", sizeof(attack_type) - 1);
        broadcast = true;
    }
    else if (check_directed_deauth(&mac_result)) {
        strncpy(attack_type, "Deautenticación Dirigida", sizeof(attack_type) - 1);
        directed = true;
    }

    if (mass || broadcast || directed || mac_result.spoofing_detected) {
        ESP_LOGI(TAG, "\U0001F6A8 Posible ataque detectado: %s \U0001F6A8", attack_type);
        ESP_LOGW(TAG, "Deauth Attack Detected! Source MAC: %02X:%02X:%02X:%02X:%02X:%02X",
            packet->src_mac[0], packet->src_mac[1], packet->src_mac[2],
            packet->src_mac[3], packet->src_mac[4], packet->src_mac[5]);
    }
}

void check_for_deauth_attack(const wifi_packet_t *packet)
{
    if (!is_deauth_attack_packet(packet)) {
        return;
    }

    update_current_time();
    ESP_LOGI(TAG, "Paquete de deautenticación sospechoso detectado");

    evaluate_deauth_attack(packet);
}

void initialize_deauth_detection()
{
    const AppConfig *config = get_config();

    mass_deauth_threshold = config->mass_deauth_threshold;

    memset(&deauth_detection_state, 0, sizeof(deauth_detection_state));
    init_frequency_analysis(&deauth_detection_state.frequency_data);

    init_frequency_tracker(
        &deauth_frequency_tracker,
        config->deauth_time_window,
        config->deauth_frequency_threshold
    );

    ESP_LOGI(TAG, "Deauth attack detection initialized");
}
