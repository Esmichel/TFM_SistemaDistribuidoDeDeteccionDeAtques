#ifndef DEAUTH_ATTACK_H
#define DEAUTH_ATTACK_H

#include "../detection_methods/mac_analysis.h"
#include "../sniffer_module.h"  

#define DEAUTH_PACKET 0x0C
#define MASS_DEAUTH_THRESHOLD 10

void initialize_deauth_detection();
void clear_mac_history();
void check_for_deauth_attack(const wifi_packet_t *packet);

#endif
