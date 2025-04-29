// centralized_config.h
#ifndef CENTRALIZED_CONFIG_H
#define CENTRALIZED_CONFIG_H

#include <stdbool.h>
#include <string.h>
#include "esp_log.h"
#include "nvs.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "cJSON.h"
#include "esp_system.h"

typedef enum {
    CONFIG_TYPE_INT,
    CONFIG_TYPE_LONG,
    CONFIG_TYPE_BOOL,
    CONFIG_TYPE_FLOAT
} ConfigType;

typedef struct {
    const char *key;      // Nombre en JSON/NVS
    ConfigType type;      // Tipo de dato
    void *addr;           // Puntero al campo en AppConfig
    const char *description; // Descripción del campo
    union {
        int default_int;
        long default_long;
        bool default_bool;
        float default_float;
    } def;
} ConfigItem;

// ¡OJO! Quita el 'static' de la definición en centralized_config.c
extern ConfigItem config_items[];
extern const size_t config_items_count;

// Main configuration structure
typedef struct {
    int mqtt_qos;
    int mqtt_retain;
    int attack_type_beacon_flood; // Attack identifier for the frequency analysis module in beacon_flood.c
    long beacon_expiration_time; // Expiration time for beacon flood detection in beacon_flood.c
    int mass_deauth_threshold; // Threshold for mass deauthentication in deauth_attack.c
    long deauth_time_window; // Time window for deauthentication detection in deauth_attack.c
    int deauth_frequency_threshold; // Frequency threshold for deauthentication detection in deauth_attack.c
    int ap_history_timeout_ms; // Timeout for AP history in evil_twin.c
    int ap_print_timeout_ms; // Timeout for AP history printing in evil_twin.c
    int flagging_start_delay_ms; // Delay before flagging starts in evil_twin.c
    int max_aps; // Maximum number of APs to track in evil_twin.c
    int evil_twin_signal_threshold; // Signal strength threshold for evil twin detection in evil_twin.c
    int evil_twin_ssid_threshold; // SSID threshold for evil twin detection in evil_twin.c
    int max_device_entries; // Maximum number of device entries for the MAC address module in mac_address_module.c
    int entry_ttl; // Entry time-to-live for the MAC address module in mac_address_module.c
    //int max_bins; // Maximum number of bins for frequency analysis in frequency_analysis.h
    //int max_variables; // Number of variables to analyze in frequency_analysis.h
    //int max_samples; // Maximum number of samples for standard deviation calculation in estandar_deviation.h
    int time_window; // Time window for frequency analysis in frequency_analysis.h
    int max_tracked_sources; // Maximum number of tracked sources for frequency analysis in frequency_analysis.h
    int mac_history_size; // Size of MAC history for MAC address module in mac_address_module.h
    int time_window_mac; // Time window for MAC address module in mac_address_module.h
    int time_window_frequency; // Time window for frequency analysis in frequency_analysis.h
    int time_window_mac_analysis; // Time window for MAC analysis in mac_analysis.h
    int spoofing_time_threshold; // Time threshold for MAC spoofing detection in mac_address_module.h
    int max_payload_len; // Maximum payload length for L7 processing in l7_processor.c
    int min_printable_seq; // Minimum sequence length for printable data in l7_processor.c
    float low_entropy_threshold; // Low entropy threshold for L7 processing in l7_processor.c
    int switch_interval; // Interval for switching channels in sniffer_module.c
    bool enable_channel_hopping; // Enable channel hopping in sniffer_module.c
    int deafult_channel; // Default channel for the ESP32 in tranparent_proxy.c
    int arp_request_timeout; // Timeout for ARP requests in arp_spoofing.c
    int scan_cycle_delay; // Delay for ARP scan cycle in arp_spoofing.c
    int max_arp_entires; // Maximum number of ARP entries for the ARP table in arp_spoofing.c (not used)
    int batch_size; // Batch size for processing data in sniffer_module.c
    int hop_interval_ms; // Interval for channel hopping in sniffer_module.c
    int filter_mode; // Sniffer filter mode for the sniffer module
} AppConfig;

#define MAX_ARP_ENTRIES 100 // Maximum number of ARP entries for the arp table in arp_spoofing.c (not used)
#define DEAUTH_PACKET 0x0C // Deauthentication packet type in deauth_attack.c
#define ATTACK_TYPE_COUNT  5 // Number of attack types for frequency analysis in frequency_analysis.h
#define BROADCAST_MAC ((uint8_t[]){0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) // Broadcast MAC address in mac_address_module.h
#define ETH_TYPE_IP 0x0800 // Ethernet type for IP packets

#define IP_PROTOCOL_TCP 6 // TCP protocol number in IP header used in l7_processor.c
#define WLAN_FC_TYPE(fc)    (((fc) & 0x000C) >> 2) // Frame Control Type in WLAN header used in l7_processor.c
#define WLAN_FC_SUBTYPE(fc) (((fc) & 0x00F0) >> 4) // Frame Control Subtype in WLAN header used in l7_processor.c
#define WLAN_FC_TODS(fc)    (((fc) & 0x0100) >> 8) // To DS in WLAN header used in l7_processor.c
#define WLAN_FC_FROMDS(fc)  (((fc) & 0x0200) >> 9) // From DS in WLAN header used in l7_processor.c
#define WIFI_FC_TYPE_MGMT  0 // Management frame type in WLAN header used in l7_processor.c
#define WIFI_FC_TYPE_CTRL  1 // Control frame type in WLAN header used in l7_processor.c
#define WIFI_FC_TYPE_DATA  2 // Data frame type in WLAN header used in l7_processor.c

#define MAC_ADDRESS_LENGTH 6 // Length of MAC address in bytes used in mac_address_module.h

// Dimensionses de arrays que deben de ser estaticos ya se vera si los hacemos por configuracion 
#define MAX_APS         60
#define MAX_VARIABLES   10  
#define MAX_BINS        10
#define MAC_HISTORY_SIZE 50
#define MAX_TRACKED_SOURCES 50
#define MAX_SAMPLES     50

typedef enum {
    STATE_NORMAL_ROTATION,    // El ciclo normal entre modo promiscuo/estación
    STATE_DEDICATED_LISTENING   // Modo de escucha dedicado (por ejemplo, ante Evil Twin)
} wifi_state_t;

typedef enum {
    FILTER_MODE_ALL,              // MGMT | CTRL | DATA
    FILTER_MODE_MGMT_ONLY,        // Solo tramas de gestión
    FILTER_MODE_DATA_ONLY,        // Solo tramas de datos
    FILTER_MODE_CTRL_ONLY,        // Solo tramas de control
    FILTER_MODE_NO_MGMT,          // Todo menos MGMT
    FILTER_MODE_BEACON_ONLY,      // Solo beacons (subtipo de MGMT, requiere parsear en callback)
    FILTER_MODE_STRICT_ALL        // MGMT | CTRL | DATA | MPDU | AMPDU
} SnifferFilterMode;

volatile extern wifi_state_t current_wifi_state; // Estado actual de Wi-Fi
volatile extern int actual_wifi_channel; // Canal wifi estatico por defecto
extern bool hoping_enabled; // Variable para habilitar/deshabilitar el cambio de canal

// Load configuration from non-volatile storage
void config_load();

// Save configuration to non-volatile storage
void config_save();

// Apply configuration values at runtime
void config_apply();

// Parse and apply configuration from JSON string
void config_update_from_json(const char *json, int len);

// Accessor for current config
AppConfig *get_config();

#endif // CENTRALIZED_CONFIG_H