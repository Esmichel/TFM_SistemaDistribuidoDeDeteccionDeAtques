#ifndef MAC_ADDRESS_MODULE_H
#define MAC_ADDRESS_MODULE_H

#include "esp_wifi.h"
#include "esp_err.h"

esp_err_t set_wifi_mac_address(wifi_interface_t interface, uint8_t *mac);

int string_to_mac(const char *mac_str, uint8_t *mac_bytes);

#endif
