#include "arp_table.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "lwip/ip_addr.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/inet.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "centralized_config.h"
#include "../MQTT_Comunication/network_status.h"

#define TAG "ARP_SCAN"
// #define arp_request_timeout 1000
// #define scan_cycle_delay 5000
// #define MAX_ARP_ENTRIES 50
// #define batch_size 5

// loaded config values
int arp_request_timeout = 0;
int scan_cycle_delay = 0;
int max_arp_entries = 0;
int batch_size = 0;

static uint32_t last_scanned_ip = 0;
static arp_entry_t arp_table[MAX_ARP_ENTRIES];
static int arp_table_size = 0;
static bool arp_table_initialized = false;
static TaskHandle_t arp_scan_task_handle = NULL;

void print_mac(const uint8_t *mac)
{
    ESP_LOGI(TAG, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool mac_matches(const uint8_t *mac1, const uint8_t *mac2)
{
    return (memcmp(mac1, mac2, 6) == 0);
}

void update_arp_table(uint32_t ip, uint8_t *mac)
{
    for (int i = 0; i < arp_table_size; i++)
    {
        if (arp_table[i].ip == ip)
        {
            if (!mac_matches(arp_table[i].mac, mac))
            {
                struct ip4_addr ip_addr;
                ip_addr.addr = ip;
                ESP_LOGE(TAG, "⚠️ ARP Spoofing Detected! IP: " IPSTR " changed MAC", IP2STR(&ip_addr));
            }
            memcpy(arp_table[i].mac, mac, 6);
            return;
        }
    }
    if (arp_table_size >= MAX_ARP_ENTRIES)
    {
        ESP_LOGW(TAG, "ARP table full, overwriting oldest entry");
        memmove(&arp_table[0], &arp_table[1], sizeof(arp_entry_t) * (MAX_ARP_ENTRIES - 1));
        arp_table_size--;
    }
    arp_table[arp_table_size].ip = ip;
    memcpy(arp_table[arp_table_size].mac, mac, 6);
    arp_table_size++;

    struct ip4_addr ip_addr;
    ip_addr.addr = ip;
    ESP_LOGI(TAG, "Added ARP entry: IP " IPSTR " ↔ MAC ", IP2STR(&ip_addr));
    print_mac(mac);
}

void print_arp_table(void)
{
    ESP_LOGI(TAG, "Current ARP Table (%d entries):", arp_table_size);
    for (int i = 0; i < arp_table_size; i++)
    {
        struct ip4_addr ip_addr;
        ip_addr.addr = arp_table[i].ip;
        ESP_LOGI(TAG, "Entry %d: IP " IPSTR " ↔ MAC ", i, IP2STR(&ip_addr));
        print_mac(arp_table[i].mac);
    }
}

void process_arp_response(const uint8_t *buffer, uint16_t len)
{
    if (len < sizeof(struct etharp_hdr))
    {
        ESP_LOGE(TAG, "ARP packet too short");
        return;
    }
    struct etharp_hdr *arp = (struct etharp_hdr *)(buffer + 14);
    if (ntohs(arp->opcode) != ARP_REPLY)
    {
        return;
    }
    uint32_t sender_ip = ntohl(arp->sipaddr.addrw[0]);
    uint8_t *sender_mac = arp->shwaddr.addr;
    update_arp_table(sender_ip, sender_mac);
}

void send_arp_request(ip4_addr_t *target_ip)
{
    esp_netif_t *esp_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (esp_netif == NULL)
    {
        ESP_LOGE(TAG, "Network interface WIFI_STA_DEF not found");
        return;
    }
    struct netif *netif = esp_netif_get_netif_impl(esp_netif);
    if (netif == NULL)
    {
        ESP_LOGE(TAG, "Failed to retrieve netif structure");
        return;
    }
    err_t err = etharp_request(netif, target_ip);
    if (err == ERR_OK)
    {
        ESP_LOGI(TAG, "Sent ARP request for IP: " IPSTR, IP2STR(target_ip));
    }
    else
    {
        ESP_LOGE(TAG, "Failed to send ARP request, error code: %d", err);
    }
}

void arp_scan_task(void *pvParameter)
{
    esp_netif_t *esp_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (esp_netif == NULL)
    {
        ESP_LOGE(TAG, "WIFI_STA_DEF not found, aborting scan task");
        vTaskDelete(NULL);
        return;
    }
    struct netif *netif = esp_netif_get_netif_impl(esp_netif);
    if (netif == NULL)
    {
        ESP_LOGE(TAG, "Failed to get netif from esp_netif");
        vTaskDelete(NULL);
        return;
    }
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(esp_netif, &ip_info) != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to get IP info");
        vTaskDelete(NULL);
        return;
    }
    ip4_addr_t first_ip, last_ip;
    first_ip.addr = ip_info.ip.addr & ip_info.netmask.addr;
    last_ip.addr = first_ip.addr | (~ip_info.netmask.addr);
    ESP_LOGI(TAG, "Scanning IP range: " IPSTR " - " IPSTR, IP2STR(&first_ip), IP2STR(&last_ip));

    while (1)
    {
        ip4_addr_t current_ip;
        if (last_scanned_ip == 0 || last_scanned_ip >= ntohl(last_ip.addr))
        {
            current_ip = first_ip;
        }
        else
        {
            current_ip.addr = htonl(last_scanned_ip);
        }
        while (ntohl(current_ip.addr) < ntohl(last_ip.addr))
        {
            ip4_addr_t batch_ips[batch_size];
            int batch_count = 0;
            while (batch_count < batch_size && (ntohl(current_ip.addr) < ntohl(last_ip.addr)))
            {
                if (current_ip.addr != ip_info.ip.addr)
                {
                    batch_ips[batch_count] = current_ip;
                    send_arp_request(&current_ip);
                    batch_count++;
                }
                current_ip.addr = htonl(ntohl(current_ip.addr) + 1);
            }
            last_scanned_ip = ntohl(current_ip.addr);
            vTaskDelay(arp_request_timeout / portTICK_PERIOD_MS);
            for (int i = 0; i < batch_count; i++)
            {
                struct eth_addr *eth_ret = NULL;
                const ip4_addr_t *ipaddr_ret = NULL;
                if (etharp_find_addr(/*netif*/ NULL, &batch_ips[i], &eth_ret, &ipaddr_ret) != -1 /*== 0 && eth_ret != NULL*/)
                {
                    update_arp_table(batch_ips[i].addr, eth_ret->addr);
                }
            }
        }
        ESP_LOGI(TAG, "Completed scan cycle. ARP table size: %d", arp_table_size);
        print_arp_table();
        vTaskDelay(scan_cycle_delay / portTICK_PERIOD_MS);
        build_arp_table_json_payload(arp_table, arp_table_size);
    }
}

void arp_table_init(void)
{
    AppConfig *config = get_config();
    arp_request_timeout = config->arp_request_timeout;
    scan_cycle_delay = config->scan_cycle_delay;
    batch_size = config->batch_size;

    if (!arp_table_initialized)
    {
        memset(arp_table, 0, sizeof(arp_table));
        arp_table_size = 0;
        arp_table_initialized = true;
        ESP_LOGI(TAG, "ARP table initialized");
    }
    else
    {
        ESP_LOGI(TAG, "ARP table already initialized; preserving data");
    }
}

void arp_table_start(void)
{
    if (arp_scan_task_handle == NULL)
    {
        xTaskCreate(&arp_scan_task, "arp_scan_task", 8192, NULL, 5, &arp_scan_task_handle);
        ESP_LOGI(TAG, "ARP scanning started");
    }
    else
    {
        ESP_LOGW(TAG, "ARP scanning already running");
    }
}

void arp_table_stop(void)
{
    if (arp_scan_task_handle != NULL)
    {
        vTaskDelete(arp_scan_task_handle);
        arp_scan_task_handle = NULL;
        ESP_LOGI(TAG, "ARP scanning stopped");
    }
    else
    {
        ESP_LOGW(TAG, "No ARP scanning task to stop");
    }
}
