#include "arp_spoofing.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "tools/centralized_config.h"

//#define MAX_ARP_ENTRIES 100

static const char *TAG = "evil_twin_detection";

arp_entry2_t arp_table[MAX_ARP_ENTRIES];
int arp_table_size = 0;

void arp_spoofing_init(void)
{
    memset(arp_table, 0, sizeof(arp_table));
    arp_table_size = 0;
    ESP_LOGI(TAG, "ARP Spoofing Detection Initialized\n");
}

bool check_arp_spoofing(uint32_t ip, uint8_t *mac)
{
    for (int i = 0; i < arp_table_size; i++)
    {
        if (arp_table[i].ip_address == ip)
        {
            if (memcmp(arp_table[i].mac_address, mac, 6) != 0)
            {
                return true;
            }
        }
    }
    return false;
}

void debug_log_packet(uint8_t *payload, uint16_t length)
{
    printf("Packet Length: %d bytes\n", length);
    printf("Packet Data: ");
    for (int i = 0; i < length; i++)
    {
        printf("%02X ", payload[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}

void process_arp_packet(uint8_t *payload, uint16_t length)
{
    int offset = (payload[0] & 0x80) ? 30 : 24;

    if (length < offset + 28)
    {
        printf("Packet too short for ARP, ignoring.\n");
        debug_log_packet(payload, length);
        return;
    }
    debug_log_packet(payload, length);
    if (payload[offset] == 0xAA && payload[offset + 1] == 0xAA)
    {
        uint16_t eth_type = ntohs(*(uint16_t *)(payload + offset + 6));

        if (eth_type == 0x0806)
        {
            uint8_t *arp_data = payload + offset + 8;

            uint16_t arp_operation = ntohs(*(uint16_t *)(arp_data + 6));

            if (arp_operation != 2)
            {
                return;
            }

            uint32_t sender_ip = *(uint32_t *)(arp_data + 14);
            uint8_t *sender_mac = arp_data + 8;               
            if (check_arp_spoofing(sender_ip, sender_mac))
            {
                log_arp_spoofing_event(sender_ip, sender_mac);
            }
            else
            {
                if (arp_table_size < MAX_ARP_ENTRIES)
                {
                    arp_table[arp_table_size].ip_address = sender_ip;
                    memcpy(arp_table[arp_table_size].mac_address, sender_mac, 6);
                    arp_table_size++;
                }
            }
        }
    }
}

void log_arp_spoofing_event(uint32_t ip, uint8_t *mac)
{
    printf("ARP Spoofing Detected!\n");
    printf("IP: %u.%u.%u.%u, MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           (unsigned int)((ip >> 24) & 0xFF), (unsigned int)((ip >> 16) & 0xFF), (unsigned int)((ip >> 8) & 0xFF), (unsigned int)(ip & 0xFF), 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
