#ifndef ARP_SPOOFING_H
#define ARP_SPOOFING_H

#include <stdint.h>
#include <stdbool.h>
#include "detection_methods/frequency_analysis.h" // Include the header where frequency_tracker_t is defined
#include "../sniffer_module.h"

// Struct to store ARP entries (IP-MAC pair)

typedef struct
{
    uint32_t ip_address;
    uint8_t mac_address[6];
    int64_t last_change_time; // timestamp of last MAC update (us)
} arp_entry2_t;

// Function to initialize ARP detection
void arp_spoofing_init(void);

// Function to check for ARP spoofing (duplicate IP to MAC mapping)
bool check_arp_spoofing(uint32_t ip, uint8_t *mac);

// Function to process captured ARP packets
void process_arp_packet(wifi_packet_t *packet);

// Function to log detected ARP spoofing event
void log_arp_spoofing_event(uint32_t ip, uint8_t *mac, const char *reason, wifi_packet_t *pkt);
#endif // ARP_SPOOFING_H
