#ifndef MAC_SPOOFING_H
#define MAC_SPOOFING_H

#include <stdint.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

// #define MAX_DEVICE_ENTRIES 50
// #define ENTRY_TTL (600 * configTICK_RATE_HZ)

typedef struct mac_entry_t {
    uint32_t ip_addr;
    uint8_t mac[6];
    TickType_t timestamp; 
} struct_mac_entry_t;

void mac_spoof_detector_init(void);

bool mac_spoof_detector_process(uint32_t ip, const uint8_t *mac);

#ifdef __cplusplus
}
#endif

#endif
