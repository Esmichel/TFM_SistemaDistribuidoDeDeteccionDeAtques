#ifndef EVIL_TWIN_H
#define EVIL_TWIN_H

#include "esp_wifi.h"
#include "sniffer_module.h"

#define MAX_APS 50
#define EVIL_TWIN_SIGNAL_THRESHOLD -30  
#define EVIL_TWIN_SSID_THRESHOLD 3      

typedef struct {
    uint8_t mac[6];             
    char ssid[50];             
    int8_t signal_strength;    
    uint32_t timestamp;        
} detected_ap_t;

typedef struct {
    detected_ap_t aps[MAX_APS];
    int current_index;        
} ap_history_t;

void initialize_evil_twin();

void add_ap_to_history(ap_history_t *history, const uint8_t *mac, const char *ssid, int8_t signal_strength, uint32_t timestamp);


bool detect_evil_twin(ap_history_t *history, const uint8_t *mac, const char *ssid, int8_t signal_strength);

void analyze_evil_twin(const wifi_packet_t *wifi_pkt);

#endif 
