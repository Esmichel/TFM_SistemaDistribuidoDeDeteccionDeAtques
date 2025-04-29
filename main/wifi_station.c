#include "wifi_station.h"
#include "sniffer_module.h"

static const char *TAG = "wifi_station";

#define WIFI_SSID "TP-Link_A64E"
#define WIFI_PASSWORD ""
#define WIFI_CONNECT_TIMEOUT 5000

#define SSID_NAME "HiddenESP32"
#define STA_SSID ""
#define STA_PASSWORD ""
#define CHANNEL 1

static bool wifi_connected = false;
static bool is_sniffer_mode = true;

SemaphoreHandle_t wifi_semaphore;
SemaphoreHandle_t wifi_mode_mutex;
static esp_timer_handle_t spoofing_timer;

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
    if (xSemaphoreTake(wifi_mode_mutex, pdMS_TO_TICKS(1000)))
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
        xSemaphoreGive(wifi_mode_mutex);
    }
    else
    {
        ESP_LOGW(TAG, "Timeout while waiting for Wi-Fi mode mutex.");
    }
}

void wifi_init_sta(bool connect_to_ap)
{
    wifi_semaphore = xSemaphoreCreateBinary();
    wifi_mode_mutex = xSemaphoreCreateMutex();

    ESP_ERROR_CHECK(esp_wifi_init(&(wifi_init_config_t)WIFI_INIT_CONFIG_DEFAULT()));
    esp_netif_create_default_wifi_sta();
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));

    if (connect_to_ap)
    {
        ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));

        wifi_config_t wifi_config = {
            .sta = {
                .ssid = WIFI_SSID,
                .password = WIFI_PASSWORD,
            },
        };
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    }
    ESP_ERROR_CHECK(esp_wifi_start());
    if (!connect_to_ap)
    {
        ESP_LOGI(TAG, "Wi-Fi promiscuous mode enabled.");
        ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
        // wifi_promiscuous_filter_t filt;
        // filt.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL; // todo tipo de tramas

        // ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt));
    }
    else
    {
        ESP_LOGI(TAG, "Connecting to Wi-Fi AP: %s", WIFI_SSID);
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

void start_dedicated_listening_mode(const wifi_packet_t *evil_pkt)
{
    if (xSemaphoreTake(wifi_mode_mutex, pdMS_TO_TICKS(2000)) == pdFALSE)
    {
        ESP_LOGE(TAG, "Could not enter Dedicated Listening Mode: mutex timeout.");
        return;
    }
    hoping_enabled = false;

    ESP_LOGW(TAG, "Starting Dedicated Listening Mode for Evil Twin (channel %d)", evil_pkt->channel);

    ESP_ERROR_CHECK(esp_wifi_stop());
    wifi_sniffer_stop();
    wifi_sniffer_init(1);
    actual_wifi_channel = evil_pkt->channel;
    wifi_sniffer_start();
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));

    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "Wi‑Fi driver restarted");

    // ESP_ERROR_CHECK(esp_wifi_set_channel(evil_pkt->channel, WIFI_SECOND_CHAN_NONE));
    ESP_LOGI(TAG, "Wi‑Fi channel locked to %d", evil_pkt->channel);

    if (spoofing_timer == NULL)
    {
        const esp_timer_create_args_t timer_args = {
            .callback = &revert_to_normal_mode,
            .name = "spoofing_timeout"};
        esp_timer_create(&timer_args, &spoofing_timer);
    }
    esp_timer_start_once(spoofing_timer, 120000 * 1000ULL);

    current_wifi_state = STATE_DEDICATED_LISTENING;
    xSemaphoreGive(wifi_mode_mutex);
}

void revert_to_normal_mode(void *arg)
{
    if (current_wifi_state == STATE_DEDICATED_LISTENING)
    {
        ESP_LOGI(TAG, "Reverting to Normal Mode.");

        uint8_t factory_mac[6];
        esp_err_t err = esp_efuse_mac_get_default(factory_mac);
        hoping_enabled = true;
        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to read base MAC: %s", esp_err_to_name(err));
            return;
        }
        ESP_LOGI(TAG, "Factory MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                 factory_mac[0], factory_mac[1], factory_mac[2],
                 factory_mac[3], factory_mac[4], factory_mac[5]);

        uint8_t ap_mac[6];
        memcpy(ap_mac, factory_mac, 6);
        ap_mac[5] += 1; // now this is factory + 1

        esp_wifi_disconnect();
        esp_wifi_stop();
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
        ESP_ERROR_CHECK(esp_wifi_set_mac(ESP_IF_WIFI_AP, ap_mac));
        ESP_ERROR_CHECK(esp_wifi_set_mac(ESP_IF_WIFI_STA, factory_mac));
        // Restaura el estado global
        current_wifi_state = STATE_NORMAL_ROTATION;
        ESP_LOGI(TAG, "Normal mode restored.");
    }
    else
    {
        ESP_LOGW(TAG, "Not in Dedicated Listening Mode, no action taken.");
    }
}
