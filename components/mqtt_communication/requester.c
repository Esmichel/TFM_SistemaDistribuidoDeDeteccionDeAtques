#include "requester.h"
#include <time.h>
#include "mqtt_fragment_buffer.h"
#include <stdbool.h>
#include "esp_tls.h"
#include "mbedtls/ssl.h"
#include "esp_heap_trace.h"
#include "esp_heap_caps.h"

extern const uint8_t ca_crt_start[] asm("_binary_ca_crt_start");
extern const uint8_t ca_crt_end[] asm("_binary_ca_crt_end");

extern const uint8_t client_crt_start[] asm("_binary_client_crt_start");
extern const uint8_t client_crt_end[] asm("_binary_client_crt_end");

extern const uint8_t client_key_start[] asm("_binary_client_key_start");
extern const uint8_t client_key_end[] asm("_binary_client_key_end");

static mqtt_fragment_buffer_t frag_buf;
esp_mqtt_client_handle_t client = NULL;
#define LOG_TAG "MQTT_APP"
static const char *HEAP_TAG = "HEAP_MON";
static const char *HEAP_TRACE_MON_TAG = "HEAP_MON";

static bool heartbeat_task_started = false;
static TaskHandle_t heartbeat_task_handle = NULL;

static bool telemetry_task_started = false;
static TaskHandle_t telemetry_task_handle = NULL;

static bool heap_monitor_task_started = false;
static TaskHandle_t heap_monitor_task_handle = NULL;

// #define mqtt_qos 1
// #define mqtt_retain 1
// loaded config values
int mqtt_qos = 0;
int mqtt_retain = 0;

extern SemaphoreHandle_t wifi_semaphore;
typedef struct
{
    char *topic;
    char *payload;
    int qos;
    int retain;
} mqtt_message_t;

#define OFFLINE_QUEUE_SIZE 10
static QueueHandle_t offlineQueue = NULL;

static esp_mqtt_client_config_t mqtt_cfg = {
    .broker.address.uri = "mqtts://rabbit.local",
    .credentials = {
        .username = "admin",
        .authentication = {
            .password = "admin",
            .certificate = (const char *)client_crt_start,
            .key = (const char *)client_key_start,
            .key_len = 0, // Will be set dynamically
        },
        .client_id = "test",
    },
    .broker.verification.certificate = (const char *)ca_crt_start,
    .session = {
        .keepalive = 120,
        .disable_clean_session = true,
    },
};

char device_id[20];
void generate_unique_id()
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    sprintf(device_id, "%02X%02X%02X%02X%02X%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void send_response(const char *correlation_id, const char *content)
{
    char topic[64];
    snprintf(topic, sizeof(topic), RESPONSE_TOPIC_FORMAT, device_id);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "device_id", device_id);
    cJSON_AddStringToObject(root, "correlation_id", correlation_id);
    cJSON_AddStringToObject(root, "content", content);

    char *json_str = cJSON_PrintUnformatted(root);
    send_mqtt_message(topic, json_str);
    free(json_str);
    cJSON_Delete(root);
}

void handle_incoming_config(cJSON *json)
{
    cJSON *target = cJSON_GetObjectItem(json, "device_id");
    if (cJSON_IsString(target))
    {
        if (strcmp(target->valuestring, device_id) != 0)
        {
            ESP_LOGI(LOG_TAG, "Config not intended for this device. Ignoring.");
            return;
        }
    }

    char *json_str = cJSON_PrintUnformatted(json);
    if (!json_str)
    {
        ESP_LOGE(LOG_TAG, "Failed to serialize JSON for config update");
        return;
    }

    config_update_from_json(json_str, strlen(json_str));
    free(json_str);

    ESP_LOGI(LOG_TAG, "Updated configuration from MQTT");
}

void send_heartbeat(void)
{

    char topic[64];
    snprintf(topic, sizeof(topic), "%s/%s", DISCOVERY_TOPIC, device_id);

    char payload[128];
    snprintf(payload, sizeof(payload),
             "{\"device_id\":\"%s\", \"status\":\"online\"}",
             device_id);

    esp_mqtt_client_publish(client, topic, payload, 0, mqtt_qos, mqtt_retain);

    ESP_LOGI(LOG_TAG, "Heartbeat enviado a '%s'", topic);
}

void heartbeat_task(void *param)
{
    while (true)
    {
        send_heartbeat();
        vTaskDelay(20000 / portTICK_PERIOD_MS);
    }
}

void telemetry_task(void *param)
{
    while (true)
    {
        build_monitoring_payload();
        vTaskDelay(50000 / portTICK_PERIOD_MS);
    }
}

void buffer_message(const char *formatted_topic, const char *payload, int qos, int retain)
{
    mqtt_message_t msg = {0};
    msg.topic = strdup(formatted_topic);
    msg.payload = payload ? strdup(payload) : NULL;
    msg.qos = qos;
    msg.retain = retain;
    if (offlineQueue != NULL)
    {
        if (xQueueSend(offlineQueue, &msg, 0) != pdPASS)
        {
            ESP_LOGI(LOG_TAG, "Offline message buffer full, message dropped");
            free(msg.topic);
            if (msg.payload)
                free(msg.payload);
            return;
        }
        else
        {
            ESP_LOGI(LOG_TAG, "Message buffered for offline transmission");
        }
    }
}

void flush_offline_messages()
{
    ESP_LOGW(LOG_TAG, "Free heap size: %d bytes\n", esp_get_free_heap_size());

    mqtt_message_t msg;
    while (uxQueueMessagesWaiting(offlineQueue) > 0)
    {
        if (xQueueReceive(offlineQueue, &msg, 0) == pdTRUE)
        {
            ESP_LOGI(LOG_TAG, "Flushing message: topic=%s, payload=%s", msg.topic, msg.payload);
            esp_mqtt_client_publish(client, msg.topic, msg.payload, 0, msg.qos, msg.retain);
            free(msg.topic);
            free(msg.payload);
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }
}

void send_mqtt_message(const char *topic, const char *payload)
{
    char formatted_topic[128];
    if (strstr(topic, "%s") != NULL)
    {
        snprintf(formatted_topic, sizeof(formatted_topic), topic, device_id);
    }
    else
    {
        strncpy(formatted_topic, topic, sizeof(formatted_topic) - 1);
        formatted_topic[sizeof(formatted_topic) - 1] = '\0';
    }

    if (xSemaphoreTake(wifi_semaphore, 0))
    {
        ESP_LOGI(LOG_TAG, "Wi-Fi connected! Sending message on topic: %s", formatted_topic);
        int msg_id = esp_mqtt_client_publish(client, formatted_topic, payload, 0, mqtt_qos, 0);
        ESP_LOGI(LOG_TAG, "Message sent with ID: %d", msg_id);
        xSemaphoreGive(wifi_semaphore);
    }
    else
    {
        ESP_LOGI(LOG_TAG, "Wi-Fi not connected! Buffering message.");
        buffer_message(formatted_topic, payload, mqtt_qos, 0);
    }
}

static void add_config_item(cJSON *array, ConfigItem *item)
{
    cJSON *param = cJSON_CreateObject();
    cJSON_AddStringToObject(param, "name", item->key);
    cJSON_AddStringToObject(param, "description", item->description);

    const char *type_str = "";
    switch (item->type)
    {
    case CONFIG_TYPE_INT:
        type_str = "int";
        break;
    case CONFIG_TYPE_LONG:
        type_str = "long";
        break;
    case CONFIG_TYPE_BOOL:
        type_str = "bool";
        break;
    case CONFIG_TYPE_FLOAT:
        type_str = "float";
        break;
    }
    cJSON_AddStringToObject(param, "type", type_str);

    switch (item->type)
    {
    case CONFIG_TYPE_INT:
        cJSON_AddNumberToObject(param, "defaultValue", *((int *)item->addr));
        break;
    case CONFIG_TYPE_LONG:
        cJSON_AddNumberToObject(param, "defaultValue", *((long *)item->addr));
        break;
    case CONFIG_TYPE_BOOL:
        cJSON_AddBoolToObject(param, "defaultValue", *((bool *)item->addr));
        break;
    case CONFIG_TYPE_FLOAT:
        cJSON_AddNumberToObject(param, "defaultValue", *((float *)item->addr));
        break;
    }

    cJSON_AddItemToArray(array, param);
}

void send_config_summary(const char *response_topic)
{
    ESP_LOGI(LOG_TAG, "Building config summary…");
    ESP_LOGI(LOG_TAG, "Topic to publish: %s", response_topic);

    // root object
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "deviceId", device_id);
    cJSON_AddStringToObject(root, "type", "config_params");

    // payload array
    cJSON *payload = cJSON_CreateArray();
    for (size_t i = 0; i < config_items_count; ++i)
    {
        add_config_item(payload, &config_items[i]);
    }
    cJSON_AddItemToObject(root, "payload", payload);

    // serialize & publish
    char *json_str = cJSON_PrintUnformatted(root);
    if (json_str)
    {
        int msg_id = esp_mqtt_client_publish(client,
                                             response_topic,
                                             json_str,
                                             0,
                                             /*mqtt_qos*/ 0,
                                             /*mqtt_retain*/ 0);
        ESP_LOGI(LOG_TAG, "Published config summary, msg_id=%d", msg_id);
        free(json_str);
    }
    cJSON_Delete(root);
}

void handle_incoming_whitelist(cJSON *json)
{
    cJSON *array = NULL;

    // Caso 1: el JSON entrante es un array
    if (cJSON_IsArray(json))
    {
        array = json;
    }
    // Caso 2: el JSON entrante es un objeto que contiene "payload": [ ... ]
    else
    {
        cJSON *payload = cJSON_GetObjectItem(json, "payload");
        if (cJSON_IsArray(payload))
        {
            array = payload;
        }
    }

    if (array == NULL)
    {
        ESP_LOGE(LOG_TAG, "Invalid whitelist format, expected array or {\"payload\":[...]}");
        return;
    }

    // Vaciamos la lista previa
    whitelist_clear();

    // Recorremos cada elemento del array
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, array)
    {
        if (!cJSON_IsObject(item))
        {
            continue;
        }

        cJSON *ssid_obj = cJSON_GetObjectItem(item, "ssid");
        cJSON *mac_obj = cJSON_GetObjectItem(item, "mac");

        if (cJSON_IsString(ssid_obj) && cJSON_IsString(mac_obj))
        {
            const char *ssid = ssid_obj->valuestring;
            const char *mac = mac_obj->valuestring;

            whitelist_add(mac, ssid);
            ESP_LOGE(LOG_TAG, "Added to whitelist: SSID=%s  MAC=%s", ssid, mac);
        }
    }

    ESP_LOGI(LOG_TAG, "Whitelist actualizada desde MQTT");
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    switch (event_id)
    {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGW(LOG_TAG, "Connected to broker");
        esp_mqtt_client_subscribe(client, REQUEST_TOPIC, mqtt_qos);
        {
            char device_topic[64];
            snprintf(device_topic, sizeof(device_topic), "rabbitmq/queue/%s", device_id);
            ESP_LOGW(LOG_TAG, "Subscribing to device topic: %s", device_topic);
            esp_mqtt_client_subscribe(client, device_topic, mqtt_qos);
            snprintf(device_topic, sizeof(device_topic), "sistema/configuracion/%s", device_id);
            esp_mqtt_client_subscribe(client, device_topic, mqtt_qos);
            esp_mqtt_client_subscribe(client, "sistema/whitelist", mqtt_qos);
        }
        send_heartbeat();
        if (!heartbeat_task_started)
        {
            xTaskCreate(heartbeat_task, "heartbeat_task", 4096, NULL, 5, &heartbeat_task_handle);
            heartbeat_task_started = true;
        }
        if (!telemetry_task_started)
        {
            xTaskCreate(telemetry_task, "telemetry_task", 4096, NULL, 5, &telemetry_task_handle);
            telemetry_task_started = true;
        }
        // if (xTaskCreate(offline_flush_task, "off_flush", 4096, NULL, 3, NULL) != pdPASS)
        // {
        //     ESP_LOGW(LOG_TAG, "Failed to create offline_flush_task");
        // }
        flush_offline_messages();
        ESP_LOGW(LOG_TAG, "Ended reconnection process, flushing offline messages if any");
        break;

    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(LOG_TAG, "MQTT client disconnected");
        break;

    case MQTT_EVENT_DATA:
    {
        if (event->current_data_offset == 0)
        {

            if (!mqtt_fragment_buffer_init(&frag_buf, event->total_data_len))
            {
                ESP_LOGE(LOG_TAG, "Failed to alloc frag buffer of %u bytes", event->total_data_len);
                break; // abort data handling
            }
        }

        mqtt_fragment_buffer_add(&frag_buf, event->data, event->data_len, event->current_data_offset);

        if (mqtt_fragment_buffer_is_complete(&frag_buf))
        {
            const char *full_msg = mqtt_fragment_buffer_get(&frag_buf);
            char topic[event->topic_len + 1];
            strncpy(topic, event->topic, event->topic_len);
            topic[event->topic_len] = '\0';

            ESP_LOGW(LOG_TAG, "Topic: %s", topic);
            ESP_LOGW(LOG_TAG, "Message: %s", full_msg);

            cJSON *json = cJSON_Parse(full_msg);
            if (json == NULL)
            {
                ESP_LOGE(LOG_TAG, "Failed to parse JSON");
                break;
            }
            mqtt_fragment_buffer_free(&frag_buf);

            cJSON *correlation_id = cJSON_GetObjectItem(json, "correlation_id");
            if (cJSON_IsString(correlation_id))
            {
                send_response(correlation_id->valuestring, "Ack");
            }

            cJSON *type = cJSON_GetObjectItem(json, "type");
            if (strcmp(topic, "sistema/whitelist") == 0)
            {
                handle_incoming_whitelist(json);
                cJSON_Delete(json);
                break;
            }
            cJSON *resp_topic = cJSON_GetObjectItem(json, "response_topic");
            if (cJSON_IsString(type) &&
                strcmp(type->valuestring, "get_config") == 0 &&
                cJSON_IsString(resp_topic))
            {
                send_config_summary(resp_topic->valuestring);
                cJSON_Delete(json);
                break;
            }

            handle_incoming_config(json);

            if (cJSON_IsString(resp_topic))
            {
                char response_topic[64];
                snprintf(response_topic, sizeof(response_topic),
                         RESPONSE_TOPIC_FORMAT,
                         resp_topic->valuestring);

                ESP_LOGI(LOG_TAG, "Publishing response to: %s", response_topic);
                esp_mqtt_client_publish(client,
                                        response_topic,
                                        "Response from device",
                                        0,
                                        mqtt_qos,
                                        mqtt_retain);
            }

            cJSON_Delete(json);
        }
        break;
    }

    case MQTT_EVENT_ERROR:
        ESP_LOGE(LOG_TAG, "MQTT_EVENT_ERROR");

        if (!event->error_handle)
        {
            ESP_LOGE(LOG_TAG, "  No error_handle info available");
            break;
        }

        if (event->error_handle->error_type == MQTT_ERROR_TYPE_ESP_TLS)
        {
            // 1) Códigos de error ESP-TLS y mbedTLS
            ESP_LOGE(LOG_TAG, "  TLS error       --> 0x%04x",
                     event->error_handle->esp_tls_last_esp_err);
            ESP_LOGE(LOG_TAG, "  ESP-TLS error   --> 0x%04x",
                     event->error_handle->esp_tls_last_esp_err);

            // 2) Verification flags de mbedTLS
            uint32_t flags = event->error_handle->esp_tls_cert_verify_flags;
            ESP_LOGE(LOG_TAG, "  verify flags    --> 0x%08x", flags);
            if (flags & MBEDTLS_X509_BADCERT_EXPIRED)
            {
                ESP_LOGE(LOG_TAG, "    Certificate has expired");
            }
            if (flags & MBEDTLS_X509_BADCERT_FUTURE)
            {
                ESP_LOGE(LOG_TAG, "    Certificate not yet valid");
            }
            if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
            {
                ESP_LOGE(LOG_TAG, "    CA not trusted");
            }
            if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)
            {
                ESP_LOGE(LOG_TAG, "    Hostname mismatch");
            }
        }
        else if (event->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED)
        {
            ESP_LOGE(LOG_TAG, "  Connection refused, ack=%d",
                     event->error_handle->connect_return_code);
        }
        else
        {
            ESP_LOGE(LOG_TAG, "  Transport error type %d",
                     event->error_handle->error_type);
        }
        break;

    default:
        ESP_LOGI(LOG_TAG, "Unhandled event ID: %d", event_id);
        break;
    }
}

void mqtt_app_start()
{
    AppConfig *config = get_config();
    mqtt_qos = config->mqtt_qos;
    mqtt_retain = config->mqtt_retain;
    if (offlineQueue == NULL)
    {
        offlineQueue = xQueueCreate(OFFLINE_QUEUE_SIZE, sizeof(mqtt_message_t));
        // BaseType_t res = xTaskCreate(
        //     heap_monitor_task,
        //     "heap_monitor_task",
        //     4096,
        //     NULL,
        //     tskIDLE_PRIORITY + 1,
        //     NULL);
        // if (res != pdPASS)
        // {
        //     ESP_LOGE(HEAP_TAG, "Error al crear heap_monitor_task");
        // }
    }
    generate_unique_id();
    ESP_LOGI(LOG_TAG, "Device ID: %s", device_id);

    // --- Debugging Certificate and Key Lengths ---
    ESP_LOGI(LOG_TAG, "CA Certificate Start Address: %p", ca_crt_start);
    ESP_LOGI(LOG_TAG, "CA Certificate End Address: %p", ca_crt_end);
    ESP_LOGI(LOG_TAG, "CA Certificate Length: %d bytes", (int)(ca_crt_end - ca_crt_start));

    ESP_LOGI(LOG_TAG, "Client Certificate Start Address: %p", client_crt_start);
    ESP_LOGI(LOG_TAG, "Client Certificate End Address: %p", client_crt_end);
    ESP_LOGI(LOG_TAG, "Client Certificate Length: %d bytes", (int)(client_crt_end - client_crt_start));

    ESP_LOGI(LOG_TAG, "Client Key Start Address: %p", client_key_start);
    ESP_LOGI(LOG_TAG, "Client Key End Address: %p", client_key_end);
    ESP_LOGI(LOG_TAG, "Client Key Length (calculated): %d bytes", (int)(client_key_end - client_key_start));
    mqtt_cfg.credentials.authentication.key_len = client_key_end - client_key_start;
    // --- End Debugging ---

    mqtt_cfg.broker.verification.certificate = (const char *)ca_crt_start;
    mqtt_cfg.broker.verification.certificate_len = ca_crt_end - ca_crt_start; // Asegúrate de incluir esto
    mqtt_cfg.credentials.client_id = device_id;

    client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);
}
void mqtt_app_stop()
{
    if (heartbeat_task_started && heartbeat_task_handle != NULL)
    {
        ESP_LOGW(LOG_TAG, "Stopping heartbeat task...");
        vTaskDelete(heartbeat_task_handle);
        heartbeat_task_handle = NULL;
        heartbeat_task_started = false;
        ESP_LOGW(LOG_TAG, "Heartbeat task stopped.");
    }

    // Stop the heap monitor task first
    if (heap_monitor_task_started && heap_monitor_task_handle != NULL)
    {
        ESP_LOGW(HEAP_TRACE_MON_TAG, "Stopping heap monitor task...");
        vTaskDelete(heap_monitor_task_handle);
        heap_monitor_task_handle = NULL;
        heap_monitor_task_started = false;
        ESP_LOGW(HEAP_TRACE_MON_TAG, "Heap monitor task stopped.");
    }

    if (telemetry_task_started && telemetry_task_handle != NULL)
    {
        ESP_LOGW(LOG_TAG, "Stopping telemetry task...");
        vTaskDelete(telemetry_task_handle);
        telemetry_task_handle = NULL;
        telemetry_task_started = false;
        ESP_LOGW(LOG_TAG, "Telemetry task stopped.");
    }

    if (client != NULL)
    {
        ESP_LOGW(LOG_TAG, "Stopping MQTT client...");
        esp_mqtt_client_stop(client);
        vTaskDelay(10 / portTICK_PERIOD_MS);
        mqtt_fragment_buffer_free(&frag_buf);
        esp_mqtt_client_destroy(client);
        client = NULL;
        ESP_LOGW(LOG_TAG, "MQTT client stopped and destroyed");
    }
}

void device_a_publish_request()
{
    char payload[128];
    snprintf(payload, sizeof(payload), "{\"requester\":\"deviceA_queue\",\"data\":\"some_request_data\"}");
    send_mqtt_message(REQUEST_TOPIC, payload);
}

// #define HEAP_TRACE_REC_MAX   400
// static heap_trace_record_t s_trace_records[HEAP_TRACE_REC_MAX];
// static const int max_depth = CONFIG_HEAP_TRACING_STACK_DEPTH;

/**
 * Datos auxiliares para llevar contador de ciclos consecutivos de cada malloc “sin free”.
 */
// typedef struct {
//     void     *address;
//     size_t    size;
//     int       consecutive_count;
//     void    *alloced_by[CONFIG_HEAP_TRACING_STACK_DEPTH];
// } LeakInfo;

// static LeakInfo s_leaks[HEAP_TRACE_REC_MAX];
// static int     s_leaks_count = 0;
// static LeakInfo new_leaks[HEAP_TRACE_REC_MAX];
// static int     new_leaks_count = 0;

// static int find_leak_index(void *addr)
// {
//     for (int i = 0; i < s_leaks_count; i++) {
//         if (s_leaks[i].address == addr) {
//             return i;
//         }
//     }
//     return -1;
// }

// static void reset_leaks_tracking(void)
// {
//     s_leaks_count = 0;
// }

// /**
//  * Muestra solo los bloques que lleven N ciclos consecutivos sin free.
//  */
// static void heap_monitor_task(void *pvParameters)
// {
//     esp_err_t err;

//     // 1) Inicializar tracing en modo standalone
//     err = heap_trace_init_standalone(s_trace_records, HEAP_TRACE_REC_MAX);
//     if (err == ESP_ERR_NOT_SUPPORTED) {
//         ESP_LOGE(HEAP_TAG, "Heap tracing NO habilitado en menuconfig.");
//         vTaskDelete(NULL);
//         return;
//     } else if (err == ESP_ERR_INVALID_STATE) {
//         // Ya estaba inicializado: seguimos adelante.
//     } else if (err != ESP_OK) {
//         ESP_LOGE(HEAP_TAG, "heap_trace_init_standalone() falló: %s", esp_err_to_name(err));
//         vTaskDelete(NULL);
//         return;
//     }

//     // 2) Detener cualquier tracing anterior antes de arrancar
//     heap_trace_stop();

//     // 3) Iniciar tracing de malloc/free
//     err = heap_trace_start(HEAP_TRACE_ALL);
//     if (err == ESP_ERR_INVALID_STATE) {
//         // Ya estaba activo: reiniciamos
//         heap_trace_stop();
//         err = heap_trace_start(HEAP_TRACE_ALL);
//     }
//     if (err != ESP_OK) {
//         ESP_LOGE(HEAP_TAG, "heap_trace_start() falló: %s", esp_err_to_name(err));
//         vTaskDelete(NULL);
//         return;
//     }

//     const TickType_t INTERVAL_TICKS = pdMS_TO_TICKS(30000); // 30 segundos
//     reset_leaks_tracking();

//     while (true) {
//         // 4) Esperamos el intervalo
//         vTaskDelay(INTERVAL_TICKS);

//         // 5) Parar tracing para leer registros
//         err = heap_trace_stop();
//         if (err == ESP_ERR_INVALID_STATE) {
//             ESP_LOGW(HEAP_TAG, "heap_trace_stop(): no había tracing activo.");
//         } else if (err != ESP_OK) {
//             ESP_LOGW(HEAP_TAG, "heap_trace_stop() falló: %s", esp_err_to_name(err));
//             heap_trace_start(HEAP_TRACE_ALL);
//             continue;
//         }

//         // 6) Construir new_leaks[] con mallocs aún no liberados
//         new_leaks_count = 0;
//         for (size_t idx = 0; idx < HEAP_TRACE_REC_MAX; idx++) {
//             heap_trace_record_t rec;
//             if (heap_trace_get(idx, &rec) != ESP_OK) {
//                 break; // Ya no hay más registros
//             }
//             if (!rec.freed && rec.address != NULL) {
//                 new_leaks[new_leaks_count].address = rec.address;
//                 new_leaks[new_leaks_count].size = rec.size;
//                 new_leaks[new_leaks_count].consecutive_count = 1;
//                 memcpy(new_leaks[new_leaks_count].alloced_by,
//                        rec.alloced_by,
//                        sizeof(void *) * max_depth);
//                 new_leaks_count++;
//             }
//         }

//         // 7) Comparar new_leaks con s_leaks para actualizar consecutive_count
//         for (int i = 0; i < new_leaks_count; i++) {
//             int prev_idx = find_leak_index(new_leaks[i].address);
//             if (prev_idx >= 0) {
//                 new_leaks[i].consecutive_count = s_leaks[prev_idx].consecutive_count + 1;
//             }
//             // Si no se encontró, el contador ya quedó en 1
//         }

//         // 8) Copiar new_leaks → s_leaks para el siguiente ciclo
//         memcpy(s_leaks, new_leaks, sizeof(LeakInfo) * new_leaks_count);
//         s_leaks_count = new_leaks_count;

//         // 9) Mostrar SOLO direcciones con consecutive_count >= UMBRAL
//         const int UMBRAL = 10;
//         bool any_candidate = false;
//         for (int i = 0; i < s_leaks_count; i++) {
//             if (s_leaks[i].consecutive_count >= UMBRAL) {
//                 if (!any_candidate) {
//                     ESP_LOGE(HEAP_TAG, "=== FUGAS DETECTADAS (persistencia >= %d ciclos) ===", UMBRAL);
//                     any_candidate = true;
//                 }
//                 ESP_LOGE(HEAP_TAG, "- Dirección: %p  | Tamaño: %u bytes  | Ciclos: %d",
//                          s_leaks[i].address,
//                          (unsigned int)s_leaks[i].size,
//                          s_leaks[i].consecutive_count);
//                 // Imprimimos únicamente el stack de malloc para ese bloque
//                 for (int d = 0; d < 1; d++) {
//                     if (s_leaks[i].alloced_by[d] == NULL) {
//                         break;
//                     }
//                     ESP_LOGE(HEAP_TAG, "    ALLOC[%d] = %p", d, s_leaks[i].alloced_by[d]);
//                 }
//             }
//         }
//         if (any_candidate) {
//             ESP_LOGE(HEAP_TAG, "=== FIN DE FUGAS ===");
//         }

//         // 10) Reiniciar tracing para el próximo ciclo
//         err = heap_trace_start(HEAP_TRACE_ALL);
//         if (err == ESP_ERR_INVALID_STATE) {
//             heap_trace_stop();
//             err = heap_trace_start(HEAP_TRACE_ALL);
//         }
//         if (err != ESP_OK) {
//             ESP_LOGW(HEAP_TAG, "heap_trace_start() tras dump falló: %s", esp_err_to_name(err));
//         }
//     }

//     vTaskDelete(NULL);
// }