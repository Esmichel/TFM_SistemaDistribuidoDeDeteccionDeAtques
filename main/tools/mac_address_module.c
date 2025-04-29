#include "mac_address_module.h"

#define TAG "MAC_ADDR_MODULE"
// #define MAC_ADDRESS_LENGTH 6

esp_err_t set_wifi_mac_address(wifi_interface_t interface, uint8_t *mac)
{
    esp_err_t ret = esp_wifi_set_mac(interface, mac);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set MAC address for interface %d: %d", interface, ret);
        return ret;
    }
    ESP_LOGI(TAG, "MAC address set successfully for interface %d", interface);
    return ESP_OK;
}

int string_to_mac(const char *mac_str, uint8_t *mac_bytes) {
    int values[MAC_ADDRESS_LENGTH];
    int i;

    if (strlen(mac_str) != 17) {
        return -1;
    }
     for (i = 0; i < MAC_ADDRESS_LENGTH; i++) {
        if (sscanf(mac_str + i * 3, "%2x", &values[i]) != 1) {
            return -1;
        }
    }
    for (i = 0; i < MAC_ADDRESS_LENGTH; i++) {
        mac_bytes[i] = (uint8_t)values[i];
    }
    return 0;
}

