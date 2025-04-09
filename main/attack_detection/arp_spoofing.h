#ifndef ARP_SPOOFING_H
#define ARP_SPOOFING_H

#include <stdint.h>
#include <stdbool.h>

// Struct to store ARP entries (IP-MAC pair)
typedef struct {
    uint32_t ip_address;  // IP address in uint32_t format
    uint8_t mac_address[6];  // MAC address (6 bytes)
} arp_entry2_t;

// Function to initialize ARP detection
void arp_spoofing_init(void);

// Function to check for ARP spoofing (duplicate IP to MAC mapping)
bool check_arp_spoofing(uint32_t ip, uint8_t *mac);

// Function to process captured ARP packets
void process_arp_packet(uint8_t *packet, uint16_t length);

// Function to log detected ARP spoofing event
void log_arp_spoofing_event(uint32_t ip, uint8_t *mac);

#endif // ARP_SPOOFING_H
