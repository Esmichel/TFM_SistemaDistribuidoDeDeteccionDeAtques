#include "../detection_methods/mac_analysis.h"
#include "../detection_methods/frequency_analysis.h"
#include "../tools/hash_function.h"

#include "../sniffer_module.h"
#include "esp_mac.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_system.h"
#include "deauth_attack.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

typedef struct
{
    mac_history_t mac_history;
    attack_frequency_t frequency_data;
    unsigned long last_update_time;
    unsigned long current_time;
} deauth_detection_state_t;

static deauth_detection_state_t deauth_detection_state;

static frequency_tracker_t deauth_frequency_tracker;

static const char *TAG = "deauth_attack_detector";

void update_current_time()
{
    uint32_t new_time = esp_timer_get_time() / 1000;
    if (new_time - deauth_detection_state.last_update_time >= 1000)
    {
        deauth_detection_state.current_time = new_time;
        deauth_detection_state.last_update_time = new_time;
    }
}

bool is_deauth_attack_packet(const wifi_packet_t *packet)
{
    return (packet->type == 0x00 && packet->subtype == DEAUTH_PACKET);
}

bool check_mass_deauth(const wifi_packet_t *packet, mac_analysis_result_t *mac_result)
{
    return (mac_result->affected_targets > MASS_DEAUTH_THRESHOLD);
}

bool check_broadcast_deauth(const wifi_packet_t *packet)
{
    return (memcmp(packet->dst_mac, BROADCAST_MAC, 6) == 0);
}

bool check_directed_deauth(const wifi_packet_t *packet, mac_analysis_result_t *mac_result)
{
    return (mac_result->affected_targets == 1);
}

void evaluate_deauth_attack(const wifi_packet_t *packet)
{
    uint32_t ssid_hash = hash_ssid((char *)packet->src_mac);
    update_frequency(&deauth_frequency_tracker, &ssid_hash, deauth_detection_state.current_time);
    add_mac_to_history(&deauth_detection_state.mac_history, packet->src_mac, deauth_detection_state.current_time);
    add_mac_to_history(&deauth_detection_state.mac_history, packet->dst_mac, deauth_detection_state.current_time);

    
    mac_analysis_result_t mac_result = analyze_mac_activity(&deauth_detection_state.mac_history, packet->src_mac, packet->dst_mac, deauth_detection_state.current_time);

    char attack_type[50] = {0}; 
    int factors_met = 0;
    bool directed = false, mass = false, broadcast = false;

    if (detect_attack_frequency(&deauth_detection_state.frequency_data, deauth_detection_state.current_time, ATTACK_TYPE_DEAUTH))
    {
        factors_met++;
    }

    if (mac_result.spoofing_detected)
    {
        strcpy(attack_type, "MAC Spoofing Detectado");
    }

    if (check_mass_deauth(packet, &mac_result))
    {
        strcpy(attack_type, "Deautenticación Masiva");
        mass = true;
    }
    else if (check_broadcast_deauth(packet))
    {
        strcpy(attack_type, "Deautenticación Broadcast");
        broadcast = true;
    }
    else if (check_directed_deauth(packet, &mac_result))
    {
        strcpy(attack_type, "Deautenticación Dirigida");
        directed = true;
    }

    if (mass || broadcast || directed || mac_result.spoofing_detected)
    {
        ESP_LOGI(TAG, "\U0001F6A8 Posible ataque detectado: %s \U0001F6A8", attack_type);
        ESP_LOGW(TAG, "Deauth Attack Detected! Source: %02X:%02X:%02X:%02X:%02X:%02X",
            packet->src_mac[0], packet->src_mac[1], packet->src_mac[2],
            packet->src_mac[3], packet->src_mac[4], packet->src_mac[5]);
    }
}

void check_for_deauth_attack(const wifi_packet_t *packet)
{
    if (!is_deauth_attack_packet(packet))
        return;

    update_current_time();
    ESP_LOGI(TAG, "Paquete de deautenticación sospechoso detectado");

    evaluate_deauth_attack(packet);
}

void initialize_deauth_detection()
{
    memset(&deauth_detection_state.mac_history, 0, sizeof(mac_history_t));
    init_frequency_analysis(&deauth_detection_state.frequency_data);
    init_frequency_tracker(&deauth_frequency_tracker, 5000, 30);
}
