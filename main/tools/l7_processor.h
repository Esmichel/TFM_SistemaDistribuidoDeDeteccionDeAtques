#ifndef L7_PROCESSOR_H
#define L7_PROCESSOR_H

#include <stdint.h>
#include "../sniffer_module.h"


void process_wifi_frame(const uint8_t *frame, uint16_t length, wifi_packet_t *wifi_pkt);
void process_ip_packet(const uint8_t *payload, uint16_t length, wifi_packet_t *wifi_pkt);
void process_tcp_packet(const uint8_t *payload, uint16_t length);
void process_layer_7_data(const uint8_t *payload, uint16_t length);


#define ETH_TYPE_IP 0x0800  
#define IP_PROTOCOL_TCP 0x06

#endif
