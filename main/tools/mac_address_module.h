#ifndef MAC_ADDRESS_MODULE_H
#define MAC_ADDRESS_MODULE_H

#include "esp_wifi.h"
#include "esp_err.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_err.h"
#include "centralized_config.h"

esp_err_t set_wifi_mac_address(wifi_interface_t interface, uint8_t *mac);

int string_to_mac(const char *mac_str, uint8_t *mac_bytes);

#endif
