#include <stdio.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_err.h"
#include "esp_system.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "nvs_flash.h"

static const char *TAG = "wifi_station";

#define WIFI_SSID "TP-Link_A64E"
#define WIFI_PASSWORD ""
#define WIFI_CONNECT_TIMEOUT 5000

static bool wifi_connected = false;
static bool is_sniffer_mode = true; 

SemaphoreHandle_t wifi_semaphore;

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        ESP_LOGI(TAG, "Wi-Fi Station started, attempting to connect");
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED)
    {
        ESP_LOGI(TAG, "Wi-Fi connected successfully");
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        ESP_LOGE(TAG, "Wi-Fi disconnected, retrying...");
        esp_wifi_connect();
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));

        wifi_connected = true;
        xSemaphoreGive(wifi_semaphore);
    }
}

void switch_wifi_mode(bool enable_sniffer)
{
    if (enable_sniffer == is_sniffer_mode)
    {
        ESP_LOGW(TAG, "Already in the requested mode, no changes made.");
        return;
    }

    if (enable_sniffer)
    {
        ESP_LOGI(TAG, "Switching to Sniffer Mode...");

        esp_wifi_disconnect();
        esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler);
        esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler);
        esp_wifi_set_promiscuous(true);
        ESP_LOGI(TAG, "Promiscuous mode enabled.");

        is_sniffer_mode = true;
    }
    else
    {
        ESP_LOGI(TAG, "Switching to Station Mode...");

        esp_wifi_set_promiscuous(false);
        esp_wifi_set_mode(WIFI_MODE_STA);
        esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL);
        esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL);
        wifi_config_t wifi_config = {
            .sta = {
                .ssid = WIFI_SSID,
                .password = WIFI_PASSWORD,
            },
        };
        esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
        esp_wifi_start();
        esp_wifi_connect();
        is_sniffer_mode = false;
    }
}

void wifi_init_sta(bool connect_to_ap)
{

    wifi_semaphore = xSemaphoreCreateBinary();
    ESP_ERROR_CHECK(esp_wifi_init(&(wifi_init_config_t)WIFI_INIT_CONFIG_DEFAULT()));
    esp_netif_create_default_wifi_sta();
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    if (connect_to_ap)
    {
        ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));
        ESP_LOGI(TAG, "Connecting to Wi-Fi AP: %s", WIFI_SSID);

        wifi_config_t wifi_config = {
            .sta = {
                .ssid = WIFI_SSID,
                .password = WIFI_PASSWORD,
            },
        };
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
        ESP_ERROR_CHECK(esp_wifi_start());
    }
    else
    {
        ESP_LOGI(TAG, "Wi-Fi promiscuous mode enabled.");
        ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
        esp_wifi_set_promiscuous_filter(NULL);
    }
}

bool wait_for_wifi_connection()
{
    ESP_LOGI(TAG, "Waiting for Wi-Fi connection...");

    if (xSemaphoreTake(wifi_semaphore, pdMS_TO_TICKS(WIFI_CONNECT_TIMEOUT)))
    {
        ESP_LOGI(TAG, "Wi-Fi connection established!");
        return true;
    }
    else
    {
        ESP_LOGW(TAG, "Wi-Fi connection timeout. Switching to promiscuous mode.");
        return false;
    }
}

/*bool wait_for_wifi_connection()
{
    ESP_LOGI(TAG, "Waiting for Wi-Fi connection...");

    wifi_connected = false;                            // Reset before waiting
    uint32_t start_time = esp_timer_get_time() / 1000; // Convert to milliseconds

    while (!wifi_connected)
    {
        uint32_t elapsed_time = (esp_timer_get_time() / 1000) - start_time;

        if (elapsed_time >= WIFI_CONNECT_TIMEOUT)
        {
            ESP_LOGW(TAG, "Wi-Fi connection timeout. Switching to promiscuous mode.");
            break;
        }

        vTaskDelay(100 / portTICK_PERIOD_MS); // Prevents busy-waiting
    }

    if (wifi_connected)
    {
        ESP_LOGI(TAG, "Wi-Fi connection established!");
    }
    else
    {
        ESP_LOGI(TAG, "Wi-Fi connection failed, returning to Promiscuous Mode.");
    }
    return wifi_connected;
}*/
