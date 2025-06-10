#define _POSIX_C_SOURCE 200112L
#define _DEFAULT_SOURCE
#include "arp_spoofing.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "detection_methods/frequency_analysis.h"
#include "tools/centralized_config.h"
#include "esp_timer.h"
#include "../../components/mqtt_communication/network_status.h"

#define RAPID_CHANGE_US 500000 // Define a threshold for rapid MAC address changes (500ms)

// #define MAX_ARP_ENTRIES 100

arp_entry2_t arp_table[MAX_ARP_ENTRIES];
int arp_table_size = 0;

extern int arp_table_size;
static const char *TAG = "arp_logger";

#define ARP_LOG_INTERVAL_MS 10000

static void arp_table_logger_task(void *arg)
{
    char ip_str[INET_ADDRSTRLEN];

    while (1)
    {
        int count = arp_table_size;
        ESP_LOGW(TAG, "---- ARP Table (%d entries) ----", count);

        for (int i = 0; i < count; i++)
        {
            uint32_t ip = arp_table[i].ip_address;
            struct in_addr in;
            in.s_addr = ip;
            inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));

            uint8_t *mac = arp_table[i].mac_address;
            ESP_LOGW(TAG, " %2d: %s -> %02X:%02X:%02X:%02X:%02X:%02X",
                     i,
                     ip_str,
                     mac[0], mac[1], mac[2],
                     mac[3], mac[4], mac[5]);
        }

        vTaskDelay(pdMS_TO_TICKS(ARP_LOG_INTERVAL_MS));
    }
}

void start_arp_table_logger(void)
{
    xTaskCreate(
        arp_table_logger_task,
        "arp_logger",
        4 * 1024,
        NULL,
        tskIDLE_PRIORITY + 1,
        NULL);
}

void arp_spoofing_init(void)
{
    memset(arp_table, 0, sizeof(arp_table));
    arp_table_size = 0;
    // start_arp_table_logger();
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

void log_arp_spoofing_event(uint32_t ip, uint8_t *mac, const char *reason, wifi_packet_t *pkt)
{
    struct in_addr in;
    in.s_addr = ip;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));
    ESP_LOGE(TAG, "ARP Spoofing: %s | IP: %s, MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             reason, ip_str,
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    send_alert(pkt, "ARP Spoofing: %s | IP: %s, MAC: %02X:%02X:%02X:%02X:%02X:%02X",
               reason, ip_str,
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
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

void process_arp_packet(wifi_packet_t *pkt)
{

    if (pkt->payload_length < 28)
    {
        return;
    }

    // Parse ARP header
    uint16_t hw_type = ntohs(*(uint16_t *)(pkt->payload + 0));
    uint16_t proto_type = ntohs(*(uint16_t *)(pkt->payload + 2));
    uint8_t hw_size = *(pkt->payload + 4);
    uint8_t proto_size = *(pkt->payload + 5);
    uint16_t opcode = ntohs(*(uint16_t *)(pkt->payload + 6));
    uint8_t *sender_mac = pkt->payload + 8;
    uint32_t sender_ip = *(uint32_t *)(pkt->payload + 14);
    int64_t now_us = esp_timer_get_time();

    // Only consider ARP replies over Ethernet/IPv4
    if (hw_type != 1 || proto_type != 0x0800 || hw_size != 6 || proto_size != 4 || opcode != 2)
    {
        return;
    }

    // Search for existing IP entry
    for (int i = 0; i < arp_table_size; i++)
    {
        arp_entry2_t *e = &arp_table[i];
        if (e->ip_address == sender_ip)
        {
            // Detect rapid MAC change
            if (memcmp(e->mac_address, sender_mac, 6) != 0)
            {
                int64_t delta = now_us - e->last_change_time;
                if (delta < RAPID_CHANGE_US)
                {
                    log_arp_spoofing_event(sender_ip, sender_mac, "MAC changed too rapidly", pkt);
                }
                memcpy(e->mac_address, sender_mac, 6);
                e->last_change_time = now_us;
            }
            // Always log unsolicited ARP reply
            log_arp_spoofing_event(sender_ip, sender_mac, "Unsolicited ARP reply", pkt);
            build_arp_table_json_payload((arp_entry_t *)arp_table, arp_table_size, "passive");
            return;
        }
    }

    // New entry: add IP-MAC association
    if (arp_table_size < MAX_ARP_ENTRIES)
    {
        arp_entry2_t *e = &arp_table[arp_table_size++];
        e->ip_address = sender_ip;
        memcpy(e->mac_address, sender_mac, 6);
        e->last_change_time = now_us;
        // Log first unsolicited reply for new entry
        build_arp_table_json_payload((arp_entry_t *)arp_table, arp_table_size, "passive");
        log_arp_spoofing_event(sender_ip, sender_mac, "Unsolicited ARP reply", pkt);
    }
}