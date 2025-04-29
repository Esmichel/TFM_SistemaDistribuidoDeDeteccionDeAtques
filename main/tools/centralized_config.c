#include "centralized_config.h"
#include "../sniffer_module.h"

#define TAG "CONFIG"

// Default values (from your requirements)
#define DEFAULT_MQTT_QOS 1
#define DEFAULT_MQTT_RETAIN 1
#define DEFAULT_ATTACK_TYPE_BEACON_FLOOD 4
#define DEFAULT_BEACON_EXPIRATION_TIME 60000
#define DEFAULT_MASS_DEAUTH_THRESHOLD 10
#define DEFAULT_AP_HISTORY_TIMEOUT_MS 20000
#define DEFAULT_AP_PRINT_TIMEOUT_MS 20000000
#define DEFAULT_FLAGGING_START_DELAY_MS 60000
#define DEFAULT_MAX_APS 60
#define DEFAULT_EVIL_TWIN_SIGNAL_THRESHOLD -30
#define DEFAULT_EVIL_TWIN_SSID_THRESHOLD 3
#define DEFAULT_MAX_DEVICE_ENTRIES 50
#define DEFAULT_ENTRY_TTL 60000
#define DEFAULT_TIME_WINDOW 5000
#define DEFAULT_TIME_WINDOW_FREQUENCY 5000
#define DEFAULT_TIME_WINDOW_MAC_ANALYSIS 5000
#define DEFAULT_MAX_TRACKED_SOURCES 50
#define DEFAULT_MAC_HISTORY_SIZE 50
#define DEFAULT_TIME_WINDOW_MAC 5000
#define DEFAULT_SPOOFING_TIME_THRESHOLD 1000
#define DEFAULT_MAX_PAYLOAD_LEN 1023
#define DEFAULT_MIN_PRINTABLE_SEQ 10
#define DEFAULT_LOW_ENTROPY_THRESHOLD 3.5f
#define DEFAULT_SWITCH_INTERVAL 10000
#define DEFAULT_ENABLE_CHANNEL_HOPPING true
#define DEFAULT_CHANNEL 6
#define DEFAULT_DEAUTH_FREQ_THRESHOLD 30

#define ARP_REQUEST_TIMEOUT 1000
#define SCAN_CYCLE_DELAY 5000
#define MAX_ARP_ENTRIES 50
#define BATCH_SIZE 5
#define CHANNEL_HOP_PERIOD_MS 50
#define SNIFFER_FILTER_MODE 6

// Global configuration instance
static AppConfig config;

// Getter for configuration
AppConfig *get_config(void)
{
    return &config;
}

//-----------------------------------------------------------------
// Configuration item abstraction
// typedef enum {
//     CONFIG_TYPE_INT,
//     CONFIG_TYPE_LONG,
//     CONFIG_TYPE_BOOL,
//     CONFIG_TYPE_FLOAT
//     // Extend with CONFIG_TYPE_STRING as needed
// } ConfigType;

// typedef struct {
//     const char *key;      // Key name for NVS and JSON
//     ConfigType type;      // Data type
//     void *addr;           // Pointer to the configuration field
//     union {
//         int default_int;
//         long default_long;
//         bool default_bool;
//         float default_float;
//     } def;
// } ConfigItem;

// Lookup table for all runtime-configurable items
ConfigItem config_items[] = {
    {"mqtt_qos", CONFIG_TYPE_INT, &config.mqtt_qos, "Nivel de QoS para los mensajes MQTT (0, 1 o 2)", .def.default_int = DEFAULT_MQTT_QOS},
    {"mqtt_retain", CONFIG_TYPE_INT, &config.mqtt_retain, "Indica si los mensajes MQTT deben enviarse con la marca retain", .def.default_int = DEFAULT_MQTT_RETAIN},
    {"atk_beacon", CONFIG_TYPE_INT, &config.attack_type_beacon_flood, "Tipo de ataque utilizado en el análisis de inundación de beacons", .def.default_int = DEFAULT_ATTACK_TYPE_BEACON_FLOOD},
    {"beacon_exp", CONFIG_TYPE_LONG, &config.beacon_expiration_time, "Tiempo de expiración de un beacon detectado para marcarlo como inactivo (milisegundos)", .def.default_long = DEFAULT_BEACON_EXPIRATION_TIME},
    {"mass_deauth", CONFIG_TYPE_INT, &config.mass_deauth_threshold, "Umbral de desconexiones masivas para activar la detección de ataque deauth (número de eventos)", .def.default_int = DEFAULT_MASS_DEAUTH_THRESHOLD},
    {"ap_hist_to", CONFIG_TYPE_INT, &config.ap_history_timeout_ms, "Tiempo de expiración para entradas en el historial de APs (milisegundos)", .def.default_int = DEFAULT_AP_HISTORY_TIMEOUT_MS},
    {"ap_print_to", CONFIG_TYPE_INT, &config.ap_print_timeout_ms, "Intervalo para imprimir el historial de APs detectados (milisegundos)", .def.default_int = DEFAULT_AP_PRINT_TIMEOUT_MS},
    {"flag_delay", CONFIG_TYPE_INT, &config.flagging_start_delay_ms, "Retardo antes de empezar a marcar APs como sospechosos (milisegundos)", .def.default_int = DEFAULT_FLAGGING_START_DELAY_MS},
    {"max_aps", CONFIG_TYPE_INT, &config.max_aps, "Número máximo de puntos de acceso (APs) que se pueden rastrear simultáneamente", .def.default_int = DEFAULT_MAX_APS},
    {"evil_sig", CONFIG_TYPE_INT, &config.evil_twin_signal_threshold, "Umbral de potencia de señal para identificar posibles Evil Twin (dBm)", .def.default_int = DEFAULT_EVIL_TWIN_SIGNAL_THRESHOLD},
    {"evil_ssid", CONFIG_TYPE_INT, &config.evil_twin_ssid_threshold, "Número de SSIDs similares requeridos para sospechar de un Evil Twin", .def.default_int = DEFAULT_EVIL_TWIN_SSID_THRESHOLD},
    {"max_dev", CONFIG_TYPE_INT, &config.max_device_entries, "Número máximo de dispositivos a rastrear en la base de datos de direcciones MAC", .def.default_int = DEFAULT_MAX_DEVICE_ENTRIES},
    {"entry_ttl", CONFIG_TYPE_INT, &config.entry_ttl, "Tiempo de vida para una entrada de dispositivo en la tabla MAC (segundos)", .def.default_int = DEFAULT_ENTRY_TTL},
    {"time_win", CONFIG_TYPE_INT, &config.time_window, "Ventana de tiempo para el análisis de frecuencia de tráfico (segundos)", .def.default_int = DEFAULT_TIME_WINDOW},
    {"time_win_freq", CONFIG_TYPE_INT, &config.time_window_frequency, "Ventana de tiempo usada en análisis de frecuencia de tráfico (segundos)", .def.default_int = DEFAULT_TIME_WINDOW_FREQUENCY},
    {"time_win_mac_ana", CONFIG_TYPE_INT, &config.time_window_mac_analysis, "Ventana de tiempo específica para análisis de direcciones MAC (segundos)", .def.default_int = DEFAULT_TIME_WINDOW_MAC_ANALYSIS},
    {"max_trk_src", CONFIG_TYPE_INT, &config.max_tracked_sources, "Número máximo de fuentes rastreadas en análisis de frecuencia", .def.default_int = DEFAULT_MAX_TRACKED_SOURCES},
    {"mac_hist_size", CONFIG_TYPE_INT, &config.mac_history_size, "Tamaño del historial de direcciones MAC almacenadas", .def.default_int = DEFAULT_MAC_HISTORY_SIZE},
    {"time_win_mac", CONFIG_TYPE_INT, &config.time_window_mac, "Ventana de tiempo para el rastreo y análisis de cambios en direcciones MAC (segundos)", .def.default_int = DEFAULT_TIME_WINDOW_MAC},
    {"spoof_thresh", CONFIG_TYPE_INT, &config.spoofing_time_threshold, "Tiempo mínimo entre cambios de MAC para considerar spoofing (milisegundos)", .def.default_int = DEFAULT_SPOOFING_TIME_THRESHOLD},
    {"max_payload", CONFIG_TYPE_INT, &config.max_payload_len, "Longitud máxima del payload para su análisis en capa 7 (bytes)", .def.default_int = DEFAULT_MAX_PAYLOAD_LEN},
    {"min_print_seq", CONFIG_TYPE_INT, &config.min_printable_seq, "Longitud mínima de datos imprimibles para ser analizados (caracteres consecutivos)", .def.default_int = DEFAULT_MIN_PRINTABLE_SEQ},
    {"low_entropy", CONFIG_TYPE_FLOAT, &config.low_entropy_threshold, "Umbral de entropía baja para detectar patrones sospechosos en datos (0.0 - 1.0)", .def.default_float = DEFAULT_LOW_ENTROPY_THRESHOLD},
    {"switch_intv", CONFIG_TYPE_INT, &config.switch_interval, "Intervalo de cambio entre canales WiFi (milisegundos)", .def.default_int = DEFAULT_SWITCH_INTERVAL},
    {"chan_hop", CONFIG_TYPE_BOOL, &config.enable_channel_hopping, "Habilita el cambio automático de canal (booleano)", .def.default_bool = DEFAULT_ENABLE_CHANNEL_HOPPING},
    {"def_chan", CONFIG_TYPE_INT, &config.deafult_channel, "Canal WiFi por defecto al iniciar la captura (1-13)", .def.default_int = DEFAULT_CHANNEL},
    {"arp_req_timeout", CONFIG_TYPE_INT, &config.arp_request_timeout, "Tiempo máximo de espera para respuestas ARP (milisegundos)", .def.default_int = ARP_REQUEST_TIMEOUT},
    {"scan_cycle", CONFIG_TYPE_INT, &config.scan_cycle_delay, "Intervalo entre ciclos de escaneo de ARP (milisegundos)", .def.default_int = SCAN_CYCLE_DELAY},
    {"batch_size", CONFIG_TYPE_INT, &config.batch_size, "Tamaño del lote para procesamiento de datos o envío por MQTT (número de elementos)", .def.default_int = BATCH_SIZE},
    {"chan_hop_period", CONFIG_TYPE_INT, &config.hop_interval_ms, "Período de cambio de canal para el sniffer (milisegundos)", .def.default_int = CHANNEL_HOP_PERIOD_MS},
    {"sniffer_filter_mode", CONFIG_TYPE_INT, &config.filter_mode, "Modo de filtro para el sniffer (0: todo, 1: solo gestión, 2: solo datos, 3: solo control)", .def.default_int = SNIFFER_FILTER_MODE},
    {"deauth_time_window", CONFIG_TYPE_INT, &config.deauth_time_window, "Ventana de tiempo para detección de desconexiones (milisegundos)", .def.default_int = DEFAULT_TIME_WINDOW},
    {"deauth_freq_threshold", CONFIG_TYPE_INT, &config.deauth_frequency_threshold, "Umbral de frecuencia para detección de desconexiones (número de eventos)", .def.default_int = DEFAULT_DEAUTH_FREQ_THRESHOLD}

};

const size_t config_items_count = sizeof(config_items) / sizeof(ConfigItem);

//-----------------------------------------------------------------
// Set all configuration items to their defaults using the lookup table.
static void config_set_defaults_from_table(void)
{
    for (size_t i = 0; i < config_items_count; i++)
    {
        switch (config_items[i].type)
        {
        case CONFIG_TYPE_INT:
            *((int *)config_items[i].addr) = config_items[i].def.default_int;
            break;
        case CONFIG_TYPE_LONG:
            *((long *)config_items[i].addr) = config_items[i].def.default_long;
            break;
        case CONFIG_TYPE_BOOL:
            *((bool *)config_items[i].addr) = config_items[i].def.default_bool;
            break;
        case CONFIG_TYPE_FLOAT:
            *((float *)config_items[i].addr) = config_items[i].def.default_float;
            break;
        default:
            break;
        }
    }
}

void config_log_values(void)
{
    ESP_LOGW(TAG, "Applying configuration:");
    for (size_t i = 0; i < config_items_count; i++)
    {
        switch (config_items[i].type)
        {
        case CONFIG_TYPE_INT:
            ESP_LOGW(TAG, "  %s: %d", config_items[i].key, *((int *)config_items[i].addr));
            break;
        case CONFIG_TYPE_LONG:
            ESP_LOGW(TAG, "  %s: %ld", config_items[i].key, *((long *)config_items[i].addr));
            break;
        case CONFIG_TYPE_BOOL:
            ESP_LOGW(TAG, "  %s: %d", config_items[i].key, *((bool *)config_items[i].addr));
            break;
        case CONFIG_TYPE_FLOAT:
            ESP_LOGW(TAG, "  %s: %f", config_items[i].key, *((float *)config_items[i].addr));
            break;
        default:
            break;
        }
    }
}

// Loads configuration from NVS; if none found, loads defaults from the lookup table.
void config_load(void)
{
    nvs_handle_t nvs;
    esp_err_t err = 1; // nvs_open("config_ns", NVS_READONLY, &nvs);
    if (err == ESP_OK)
    {
        for (size_t i = 0; i < config_items_count; i++)
        {
            switch (config_items[i].type)
            {
            case CONFIG_TYPE_INT:
            {
                int32_t value = 0;
                if (nvs_get_i32(nvs, config_items[i].key, &value) == ESP_OK)
                {
                    *((int *)config_items[i].addr) = value;
                }
                else
                {
                    *((int *)config_items[i].addr) = config_items[i].def.default_int;
                }
                break;
            }
            case CONFIG_TYPE_LONG:
            {
                int32_t value = 0;
                if (nvs_get_i32(nvs, config_items[i].key, &value) == ESP_OK)
                {
                    *((long *)config_items[i].addr) = (long)value;
                }
                else
                {
                    *((long *)config_items[i].addr) = config_items[i].def.default_long;
                }
                break;
            }
            case CONFIG_TYPE_BOOL:
            {
                int32_t value = 0;
                if (nvs_get_i32(nvs, config_items[i].key, &value) == ESP_OK)
                {
                    *((bool *)config_items[i].addr) = (value != 0);
                }
                else
                {
                    *((bool *)config_items[i].addr) = config_items[i].def.default_bool;
                }
                break;
            }
            case CONFIG_TYPE_FLOAT:
            {
                // Store float as int (multiplied by 1000) to preserve precision
                int32_t value = 0;
                if (nvs_get_i32(nvs, config_items[i].key, &value) == ESP_OK)
                {
                    *((float *)config_items[i].addr) = (float)value / 1000.0f;
                }
                else
                {
                    *((float *)config_items[i].addr) = config_items[i].def.default_float;
                }
                break;
            }
            default:
                break;
            }
        }
        nvs_close(nvs);
    }
    else
    {
        ESP_LOGW(TAG, "No stored config found; loading defaults");
        config_set_defaults_from_table();
        config_save();
    }
    config_log_values();
}

// Saves the configuration values from the lookup table to NVS.
void config_save(void)
{
    nvs_handle_t nvs;
    if (nvs_open("config_ns", NVS_READWRITE, &nvs) == ESP_OK)
    {
        for (size_t i = 0; i < config_items_count; i++)
        {
            switch (config_items[i].type)
            {
            case CONFIG_TYPE_INT:
                nvs_set_i32(nvs, config_items[i].key, *((int *)config_items[i].addr));
                break;
            case CONFIG_TYPE_LONG:
                nvs_set_i32(nvs, config_items[i].key, *((long *)config_items[i].addr));
                break;
            case CONFIG_TYPE_BOOL:
                nvs_set_i32(nvs, config_items[i].key, *((bool *)config_items[i].addr) ? 1 : 0);
                break;
            case CONFIG_TYPE_FLOAT:
            {
                // Store float as int (multiplied by 1000)
                int32_t fval = (int32_t)(*((float *)config_items[i].addr) * 1000.0f);
                nvs_set_i32(nvs, config_items[i].key, fval);
                break;
            }
            default:
                break;
            }
        }
        nvs_commit(nvs);
        nvs_close(nvs);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to open NVS for saving config");
    }
}

void config_apply(void)
{
    config_log_values();
    sniffer_update_config();
    // TODO: Call each module's update function (e.g., sniffer_update_settings(&config); mqtt_client_set_qos(config.mqtt_qos); etc.)
}

void config_update_from_json(const char *json, int len)
{
    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!root)
    {
        ESP_LOGE(TAG, "Failed to parse JSON config");
        return;
    }

    cJSON *config_params = cJSON_GetObjectItem(root, "config_params");
    if (!cJSON_IsArray(config_params))
    {
        ESP_LOGE(TAG, "Config params missing or invalid");
        cJSON_Delete(root);
        return;
    }

    cJSON *param = NULL;
    cJSON_ArrayForEach(param, config_params)
    {
        cJSON *name = cJSON_GetObjectItem(param, "name");
        cJSON *value = cJSON_GetObjectItem(param, "value");

        if (!cJSON_IsString(name) || !value)
            continue;

        for (size_t i = 0; i < config_items_count; i++)
        {
            if (strcmp(config_items[i].key, name->valuestring) == 0)
            {
                ESP_LOGI(TAG, "Updating config for %s", config_items[i].key);
                switch (config_items[i].type)
                {
                case CONFIG_TYPE_INT:
                    if (cJSON_IsNumber(value)){
                        *((int *)config_items[i].addr) = value->valueint;
                        ESP_LOGI(TAG, "Updated %s to %d", config_items[i].key, *((int *)config_items[i].addr));
                    }
                    break;
                case CONFIG_TYPE_LONG:
                    if (cJSON_IsNumber(value))
                        *((long *)config_items[i].addr) = (long)value->valuedouble;
                    break;
                case CONFIG_TYPE_BOOL:
                    if (cJSON_IsBool(value)) {
                        *((bool *)config_items[i].addr) = cJSON_IsTrue(value);
                        ESP_LOGI(TAG, "Updated %s to %d", config_items[i].key, *((bool *)config_items[i].addr));
                    }
                    break;
                case CONFIG_TYPE_FLOAT:
                    if (cJSON_IsNumber(value))
                        *((float *)config_items[i].addr) = (float)value->valuedouble;
                    break;
                default:
                    break;
                }
                break;
            }
        }
    }

    cJSON_Delete(root);

    config_apply();
    config_save();
}
