#ifndef WIFI_STATION_H
#define WIFI_STATION_H

#include "esp_wifi.h"

void wifi_init_sta(bool connect_to_ap);
void event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
bool wait_for_wifi_connection();
void switch_wifi_mode(bool enable_sniffer);

#endif