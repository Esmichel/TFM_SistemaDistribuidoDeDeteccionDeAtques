#include "mac_spoofing.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "MAC_SPOOF_DETECTOR";

static struct_mac_entry_t device_table[MAX_DEVICE_ENTRIES];
static int device_count = 0;

static void print_mac_ip_table(void)
{
    ESP_LOGI(TAG, "=== IP ↔ MAC Table (%d entries) ===", device_count);
    for (int i = 0; i < device_count; i++) {
        uint32_t ip = device_table[i].ip_addr;
        const uint8_t *mac = device_table[i].mac;
        ESP_LOGI(TAG, "IP: %d.%d.%d.%d  ↔  MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

void mac_spoof_detector_init(void)
{
    memset(device_table, 0, sizeof(device_table));
    device_count = 0;
    ESP_LOGI(TAG, "Detector de MAC spoofing inicializado.");
}

bool mac_spoof_detector_process(uint32_t ip, const uint8_t *mac)
{
    TickType_t now = xTaskGetTickCount();

    for (int i = 0; i < device_count; i++) {
        if (device_table[i].ip_addr == ip) {
            if ((now - device_table[i].timestamp) < ENTRY_TTL) {
                if (memcmp(device_table[i].mac, mac, 6) != 0) {
                    ESP_LOGW(TAG, "MAC spoofing detectado para IP: %d.%d.%d.%d. MAC previa: %02X:%02X:%02X:%02X:%02X:%02X, MAC nueva: %02X:%02X:%02X:%02X:%02X:%02X",
                        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                        device_table[i].mac[0], device_table[i].mac[1], device_table[i].mac[2],
                        device_table[i].mac[3], device_table[i].mac[4], device_table[i].mac[5],
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                    return true;
                }
                return false;
            } else {
                memcpy(device_table[i].mac, mac, 6);
                device_table[i].timestamp = now;
                ESP_LOGI(TAG, "Entrada actualizada para IP: %d.%d.%d.%d",
                    (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
                return false;
            }
        }
    }

    if (device_count < MAX_DEVICE_ENTRIES) {
        device_table[device_count].ip_addr = ip;
        memcpy(device_table[device_count].mac, mac, 6);
        device_table[device_count].timestamp = now;
        print_mac_ip_table();
        device_count++;
    } else {
        ESP_LOGE(TAG, "Tabla de dispositivos llena. No se pudo agregar IP: %d.%d.%d.%d",
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    }
    return false;
}
