#include <stdio.h>
#include <inttypes.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wifi_station.h" 
#include "attack_detection/deauth_attack.h" 
#include "attack_detection/evil_twin.h"
#include "attack_detection/arp_spoofing.h"
#include "attack_detection/beacon_flood.h"
#include "attack_detection/mac_spoofing.h"
#include "./tools/arp_table.h" 
#include "esp_netif.h"
#include "sniffer_module.h"    
#include "./MQTT_Comunication/requester.h" 
#include "esp_pm.h"
#include "tools/mac_address_module.h" 
#include "MQTT_Comunication/network_status.h"

static const char *TAG = "main";

typedef enum
{
    MODE_MANGEMENT_ONLY,
    MODE_PROMISCUOUS_EXTENDED,
    MODE_PROMISCUOUS_COMPLETE,
} sniffer_mode_t;

#define SWITCH_INTERVAL 10000 

typedef enum
{
    MODE_PROMISCUOUS,
    MODE_STATION
} operation_mode_t;

operation_mode_t current_mode = MODE_PROMISCUOUS;
sniffer_mode_t selected_mode = MODE_PROMISCUOUS;

void set_channel_6(void)
{
    ESP_ERROR_CHECK(esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE));
    ESP_LOGI(TAG, "Wi-Fi set to channel 1");
}

void switch_modes_task(void *pvParameter)
{
    ESP_LOGI(TAG, "Switching modes task started");
    while (1)
    {
        if (current_mode == MODE_PROMISCUOUS)
        {
            ESP_LOGI(TAG, "Switching to Station Mode for ARP Monitoring");

            wifi_sniffer_stop();
            esp_wifi_set_promiscuous(false);
            esp_wifi_stop();
            mqtt_app_stop(); 
            switch_wifi_mode(false);
            bool wifi_connected = wait_for_wifi_connection();
            if (wifi_connected)
            {
                arp_table_init();
                arp_table_start();
                mqtt_app_start();
                current_mode = MODE_STATION;
            }
            else
            {
                ESP_LOGW(TAG, "Failed to connect to Wi-Fi, returning to Promiscuous Mode.");
                switch_wifi_mode(true);
                wifi_sniffer_init(MODE_PROMISCUOUS);
                wifi_sniffer_start();
                current_mode = MODE_PROMISCUOUS;
            }
        }
        else
        {
            ESP_LOGI(TAG, "Switching to Promiscuous Mode for Attack Detection");

            esp_wifi_disconnect();
            esp_wifi_stop();
            arp_table_stop();
            mqtt_app_stop();
            switch_wifi_mode(true);
            wifi_sniffer_init(MODE_PROMISCUOUS);
            wifi_sniffer_start();
            current_mode = MODE_PROMISCUOUS;
        }
        vTaskDelay(SWITCH_INTERVAL / portTICK_PERIOD_MS);
    }
}

void select_mode_with_timeout()
{
    ESP_LOGI("Firmware Version", "ESP-IDF version: %s", esp_get_idf_version());
    printf("Selecciona el modo de funcionamiento:\n");
    printf("1. Modo Promiscuo (Capa 2)\n");
    printf("2. Modo Extendido (Capa 2)\n");
    printf("3. Modo Completo (Capa 2)\n");

    int mode = -1;
    TickType_t start_time = xTaskGetTickCount();

    while (mode == -1)
    {
        if ((xTaskGetTickCount() - start_time) / portTICK_PERIOD_MS >= 10000)
        {
            ESP_LOGW(TAG, "Tiempo de espera agotado. Seleccionando modo Promiscuo por defecto.");
            mode = 1;
        }
        if (scanf("%d", &mode) > 0)
        {
            break;
        }
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }

    if (mode == 1)
    {
        selected_mode = MODE_MANGEMENT_ONLY;
    }
    else if (mode == 2)
    {
        selected_mode = MODE_PROMISCUOUS_EXTENDED;
    }
    else if (mode == 3)
    {
        selected_mode = MODE_PROMISCUOUS_COMPLETE;
    }
    else
    {
        selected_mode = MODE_MANGEMENT_ONLY;
        ESP_LOGW(TAG, "Modo no válido, seleccionando Promiscuo por defecto.");
    }
}

void initialize_attack_detectors()
{
    initialize_deauth_detection();
    initialize_evil_twin();
    arp_spoofing_init();
    mac_spoof_detector_init();
    initialize_beacon_detection();
}

void set_power_mode()
{
    esp_pm_config_esp32_t pm_config = {
        .max_freq_mhz = 240,
        .min_freq_mhz = 80,
        .light_sleep_enable = false
    };

    if (esp_pm_configure(&pm_config) == ESP_OK)
    {
        printf("Power mode set: Max %d MHz, Min %d MHz\n", pm_config.max_freq_mhz, pm_config.min_freq_mhz);
    }
    else
    {
        printf("Failed to set power mode\n");
    }
}

void check_power_mode()
{
    esp_pm_config_esp32_t pm_config;
    esp_pm_get_configuration(&pm_config);

    if (pm_config.max_freq_mhz == 240)
    {
        ESP_LOGI(TAG, "ESP32 is running at MAX Performance mode (240 MHz)\n");
    }
    else if (pm_config.max_freq_mhz == 80)
    {
        ESP_LOGI(TAG, "ESP32 is running in Low Power mode (80 MHz)\n");
    }
    else
    {
        ESP_LOGI(TAG, "ESP32 is in another power mode: %d MHz\n", pm_config.max_freq_mhz);
    }
}

void app_main()
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_netif_init());
    esp_log_level_set("*", ESP_LOG_DEBUG);

    select_mode_with_timeout();
    wifi_init_sta(false);
    initialize_attack_detectors();
    // const char *mac_str = "48-51-B7-EF-FE-3E";
    // uint8_t mac[6];
    // string_to_mac(mac_str, mac);
    // set_wifi_mac_address(ESP_IF_WIFI_STA, mac);

    // esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
    // ESP_LOGI(TAG, "MAC address: %02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    if (selected_mode == MODE_MANGEMENT_ONLY)
    {
        ESP_LOGI(TAG, "Starting in Promiscuous Mode");
        wifi_sniffer_init(selected_mode);
        wifi_sniffer_start();
    }
    else if (selected_mode == MODE_PROMISCUOUS_EXTENDED)
    {
        ESP_LOGI(TAG, "Starting in Station Mode");
        switch_wifi_mode(false);
        bool wifi_connected = wait_for_wifi_connection();
        if (wifi_connected)
        {
            arp_table_init();
            arp_table_start();
            current_mode = MODE_STATION;
        }
    }
    else
    {
        ESP_LOGI(TAG, "Starting in Hybrid Mode");
        wifi_sniffer_init(selected_mode);
        wifi_sniffer_start();
        xTaskCreate(&switch_modes_task, "switch_modes_task", 8192, NULL, 5, NULL);
    }

    // set_channel_6();

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    if (current_mode == MODE_STATION)
    {
        mqtt_app_start();
    }
    esp_wifi_set_ps(WIFI_PS_NONE);
    //set_power_mode();
    //check_power_mode();
}
