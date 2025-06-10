#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/select.h>
#include <stdbool.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wifi_station.h"
#include "./attack_detection/deauth_attack.h"
#include "./attack_detection/evil_twin.h"
#include "./attack_detection/arp_spoofing.h"
#include "./attack_detection/beacon_flood.h"
#include "./attack_detection/mac_spoofing.h"
#include "./tools/arp_table.h"
#include "esp_netif.h"
#include "sniffer_module.h"
#include "../components/mqtt_communication/requester.h"
#include "esp_pm.h"
#include "tools/mac_address_module.h"
#include "../components/mqtt_communication/network_status.h"
#include "./tools/centralized_config.h"
#include "./tools/l3_processor.h"
#include "./tools/l7_processor.h"
#include "./attack_detection/traffic_analyzer.h"
#include "./detection_methods/frequency_analysis.h"
#include "./Calculation/estandard_deviation.h"
#include "./tools/hash_function.h"
#include "./Calculation/entropy.h"
#include "./tools/centralized_config.h"
#include "driver/gpio.h"
#include "esp_heap_trace.h"
#include "esp_heap_caps.h"
#include "esp_netif.h"

// loaded config values
int switch_interval = 0;
static const char *TAG = "main";
static const char *HEAP_TAG = "HEAP_MON";

#define STACK_SIZE_SWITCH_TASK 8192
#define STACK_SIZE_INPUT_TASK 2048
#define PRIORITY_SWITCH_TASK 5
#define PRIORITY_INPUT_TASK 10
typedef enum
{
    MODE_MANGEMENT_ONLY,
    MODE_PROMISCUOUS_EXTENDED,
    MODE_PROMISCUOUS_COMPLETE,
} sniffer_mode_t;

typedef enum
{
    MODE_PROMISCUOUS,
    MODE_STATION
} operation_mode_t;

operation_mode_t current_mode = MODE_PROMISCUOUS;
sniffer_mode_t selected_mode = MODE_PROMISCUOUS;
volatile wifi_state_t current_wifi_state = STATE_NORMAL_ROTATION;
AppConfig *config_main = NULL;
heap_trace_record_t heap_trace_records[];

void switch_modes_task(void *pvParameter)
{
    ESP_LOGI(TAG, "Switching modes task started");

    while (1)
    {
        // heap_trace_init_standalone(heap_trace_records, HEAP_TRACE_NUM_RECORDS);
        // heap_trace_start(HEAP_TRACE_LEAKS);

        // size_t free_total = heap_caps_get_free_size(MALLOC_CAP_8BIT);
        // size_t min_ever = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
        // size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);

        // ESP_LOGE(HEAP_TAG,
        //          "Heap total libre: %u B   MinFreeEver: %u B   LargestFreeBlock: %u B",
        //          (unsigned)free_total,
        //          (unsigned)min_ever,
        //          (unsigned)largest_block);

        if (current_wifi_state == STATE_DEDICATED_LISTENING)
        {
            ESP_LOGW(TAG, "Dedicated Listening Mode active — staying in promiscuous mode");

            vTaskDelay(pdMS_TO_TICKS(10000));
            continue;
        }

        if (current_mode == MODE_PROMISCUOUS)
        {
            ESP_LOGI(TAG, "Switching to Station Mode for ARP Monitoring");

            mqtt_app_stop();
            ESP_LOGE(TAG, "punto de congelacion 1");
            wifi_sniffer_stop();
            ESP_LOGE(TAG, "punto de congelacion 2");
            esp_wifi_disconnect();
            ESP_LOGE(TAG, "punto de congelacion 3");
            esp_wifi_set_promiscuous(false);
            ESP_LOGE(TAG, "punto de congelacion 4");
            esp_wifi_stop();
            ESP_LOGE(TAG, "punto de congelacion 5");
            switch_wifi_mode(false);
            ESP_LOGE(TAG, "punto de congelacion 6");
            bool wifi_connected = wait_for_wifi_connection();
            ESP_LOGE(TAG, "punto de congelacion 7");
            if (wifi_connected)
            {
                arp_table_init();
                ESP_LOGE(TAG, "punto de congelacion 8");
                arp_table_start();
                ESP_LOGE(TAG, "punto de congelacion 9");
                mqtt_app_start();

                current_mode = MODE_STATION;
            }
            else
            {
                ESP_LOGW(TAG, "Failed to connect to Wi-Fi, returning to Promiscuous Mode.");

                switch_wifi_mode(true);
                ESP_LOGE(TAG, "punto de congelacion 10");
                wifi_sniffer_init(MODE_PROMISCUOUS);
                ESP_LOGE(TAG, "punto de congelacion 11");
                wifi_sniffer_start();
                current_mode = MODE_PROMISCUOUS;
            }
        }
        else
        {
            ESP_LOGI(TAG, "Switching to Promiscuous Mode for Attack Detection");

            arp_table_stop();
            ESP_LOGE(TAG, "punto de congelacion 12");
            mqtt_app_stop();
            ESP_LOGE(TAG, "punto de congelacion 13");
            esp_wifi_disconnect();
            ESP_LOGE(TAG, "punto de congelacion 14");
            esp_wifi_stop();
            ESP_LOGE(TAG, "punto de congelacion 15");
            switch_wifi_mode(true);
            ESP_LOGE(TAG, "punto de congelacion 16");
            wifi_sniffer_init(MODE_PROMISCUOUS);
            ESP_LOGE(TAG, "punto de congelacion 17");
            wifi_sniffer_start();

            current_mode = MODE_PROMISCUOUS;
        }

        // ESP_LOGI(HEAP_TAG, "*** Dumping heap trace for leaks (this cycle) ***");
        // heap_trace_stop(); // Stop collecting records
        // heap_trace_dump(); // Print the collected records to UART

        vTaskDelay(switch_interval / portTICK_PERIOD_MS);
    }
}
QueueHandle_t input_queue;
static void input_task(void *pvParameter)
{
    char c;
    while (1)
    {
        if (xQueueReceive(input_queue, &c, portMAX_DELAY))
        {
            if (c == '1')
                selected_mode = MODE_MANGEMENT_ONLY;
            else if (c == '2')
                selected_mode = MODE_PROMISCUOUS_EXTENDED;
            else if (c == '3')
                selected_mode = MODE_PROMISCUOUS_COMPLETE;
        }
    }
}

void select_mode_with_timeout()
{
    ESP_LOGI(TAG, "ESP-IDF version: %s", esp_get_idf_version());
    printf("Selecciona el modo de funcionamiento:\n"
           "1. Modo Promiscuo (Capa 2)\n"
           "2. Modo Extendido (Capa 2)\n"
           "3. Modo Completo (Capa 2)\n"
           "(esperando 3 segundos...)\n");

    int timeout = 6000 / portTICK_PERIOD_MS; // 3 segundos de timeout
    char mode_input = 0;

    // Crear una cola para la entrada
    input_queue = xQueueCreate(1, sizeof(char));

    // Crear la tarea de lectura
    xTaskCreate(input_task, "input_task", STACK_SIZE_INPUT_TASK, NULL, PRIORITY_INPUT_TASK, NULL);

    // Esperar la entrada durante el timeout
    if (xQueueReceive(input_queue, &mode_input, timeout))
    {
        // Entrada recibida antes del timeout
        ESP_LOGI(TAG, "Modo seleccionado por el usuario: %c", mode_input);
    }
    else
    {
        // Timeout alcanzado
        ESP_LOGW(TAG, "Tiempo de espera agotado. Seleccionando modo Híbrido por defecto.");
        mode_input = '3'; // Modo por defecto
    }

    // Asignar el modo seleccionado
    switch (mode_input)
    {
    case '1':
        selected_mode = MODE_MANGEMENT_ONLY;
        break;
    case '2':
        selected_mode = MODE_PROMISCUOUS_EXTENDED;
        break;
    case '3':
    default:
        selected_mode = MODE_PROMISCUOUS_COMPLETE;
        break;
    }

    ESP_LOGI(TAG, "Modo seleccionado: %d", selected_mode);
}

void initialize_attack_detectors()
{
    initialize_deauth_detection();
    initialize_evil_twin();
    attack_detector_init();
    l7_processor_init();
    initialize_beacon_detection();
    // init_frequency_tracker();
    init_mac_analysis();
    arp_table_init();
    arp_spoofing_init();
    mac_spoof_detector_init();
}

void set_power_mode()
{
    esp_pm_config_t pm_config = {
        .max_freq_mhz = 240,
        .min_freq_mhz = 80,
        .light_sleep_enable = false};

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
    esp_pm_config_t pm_config;
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

static void idle_blinker(void *p)
{
    gpio_set_direction(GPIO_NUM_2, GPIO_MODE_OUTPUT);
    while (true)
    {
        gpio_set_level(GPIO_NUM_2, 1);
        vTaskDelay(pdMS_TO_TICKS(100));
        gpio_set_level(GPIO_NUM_2, 0);
        vTaskDelay(pdMS_TO_TICKS(900));
    }
}

void app_main()
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_log_level_set("*", ESP_LOG_ERROR);
    config_load();
    config_main = get_config();
    switch_interval = config_main->switch_interval;
    ESP_LOGI(TAG, "Switch interval: %d ms", switch_interval);

    select_mode_with_timeout();
    wifi_init_sta(false);
    initialize_attack_detectors();

    // heap_trace_init_standalone(heap_trace_records, HEAP_TRACE_NUM_RECORDS);
    // heap_trace_start(HEAP_TRACE_LEAKS);

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
        xTaskCreate(&switch_modes_task, "switch_modes_task", STACK_SIZE_SWITCH_TASK, NULL, PRIORITY_SWITCH_TASK, NULL);
    }

    if (current_mode == MODE_STATION)
    {
        mqtt_app_start();
    }

    esp_wifi_set_ps(WIFI_PS_NONE);
    xTaskCreate(idle_blinker, "blinker", 1024, NULL, 0, NULL);
}

void main_update_config(void)
{
    if (switch_interval != config_main->switch_interval)
    {
        switch_interval = config_main->switch_interval;
        ESP_LOGI(TAG, "switch_interval updated: %d ms", switch_interval);
    }
}
