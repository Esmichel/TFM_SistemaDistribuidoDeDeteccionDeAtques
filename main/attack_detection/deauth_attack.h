#ifndef DEAUTH_ATTACK_H
#define DEAUTH_ATTACK_H


#include "deauth_attack.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "esp_mac.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_system.h"
#include "../sniffer_module.h"
#include "../detection_methods/mac_analysis.h"
#include "../detection_methods/frequency_analysis.h"
#include "../tools/hash_function.h"
#include "../../components/mqtt_communication/network_status.h"
#include "../tools/centralized_config.h"

//#define DEAUTH_PACKET 0x0C
//#define MASS_DEAUTH_THRESHOLD 10

void initialize_deauth_detection();
void clear_mac_history();
void check_for_deauth_attack(const wifi_packet_t *packet);

#endif
