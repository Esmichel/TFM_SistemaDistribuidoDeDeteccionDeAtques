#include "requester.h"
#include <time.h>
#include "mqtt_fragment_buffer.h"
#include <stdbool.h>

static mqtt_fragment_buffer_t frag_buf;

esp_mqtt_client_handle_t client = NULL;
#define LOG_TAG "MQTT_APP"
// #define mqtt_qos 1
// #define mqtt_retain 1
static bool heartbeat_task_started = false;
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
    .broker.address.uri = BROKER_URI,
    .credentials = {
        .username = "admin",
        .authentication.password = "admin"},
    .session.keepalive = 60,
    .session.disable_clean_session = true,
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

void buffer_message(const char *formatted_topic, const char *payload, int qos, int retain)
{
    mqtt_message_t msg;
    msg.topic = strdup(formatted_topic);
    if (payload != NULL)
        msg.payload = strdup(payload);
    msg.qos = qos;
    msg.retain = retain;
    if (offlineQueue != NULL)
    {
        if (xQueueSend(offlineQueue, &msg, 0) != pdPASS)
        {
            ESP_LOGW(LOG_TAG, "Offline message buffer full, message dropped");
            free(msg.topic);
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
        int msg_id = esp_mqtt_client_publish(client, formatted_topic, payload, 0, mqtt_qos, mqtt_retain);
        ESP_LOGI(LOG_TAG, "Message sent with ID: %d", msg_id);
        xSemaphoreGive(wifi_semaphore);
    }
    else
    {
        ESP_LOGW(LOG_TAG, "Wi-Fi not connected! Buffering message.");
        buffer_message(formatted_topic, payload, mqtt_qos, mqtt_retain);
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
                                             /*mqtt_qos*/0,
                                             /*mqtt_retain*/0);
        ESP_LOGI(LOG_TAG, "Published config summary, msg_id=%d", msg_id);
        free(json_str);
    }
    cJSON_Delete(root);
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    switch (event_id)
    {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(LOG_TAG, "Connected to broker");
        esp_mqtt_client_subscribe(client, REQUEST_TOPIC, mqtt_qos);
        {
            char device_topic[64];
            snprintf(device_topic, sizeof(device_topic), "rabbitmq/queue/%s", device_id);
            ESP_LOGI(LOG_TAG, "Subscribing to device topic: %s", device_topic);
            esp_mqtt_client_subscribe(client, device_topic, mqtt_qos);
            esp_mqtt_client_subscribe(client, "sistema/configuracion/#", mqtt_qos);
        }
        send_heartbeat();
        if (!heartbeat_task_started)
        {
            xTaskCreate(heartbeat_task, "heartbeat_task", 4096, NULL, 5, NULL);
            heartbeat_task_started = true;
        }
        flush_offline_messages();
        break;

    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(LOG_TAG, "MQTT client disconnected");
        break;

    case MQTT_EVENT_DATA:
    {
        if (event->current_data_offset == 0)
        {
            mqtt_fragment_buffer_free(&frag_buf);
            mqtt_fragment_buffer_init(&frag_buf, event->total_data_len);
        }

        mqtt_fragment_buffer_add(&frag_buf, event->data, event->data_len, event->current_data_offset);

        if (mqtt_fragment_buffer_is_complete(&frag_buf))
        {
            const char *full_msg = mqtt_fragment_buffer_get(&frag_buf);

            char topic[event->topic_len + 1];
            strncpy(topic, event->topic, event->topic_len);
            topic[event->topic_len] = '\0';

            ESP_LOGI(LOG_TAG, "Topic: %s", topic);
            ESP_LOGI(LOG_TAG, "Message: %s", full_msg);

            cJSON *json = cJSON_Parse(full_msg);
            if (json == NULL)
            {
                ESP_LOGE(LOG_TAG, "Failed to parse JSON");
                break;
            }

            cJSON *correlation_id = cJSON_GetObjectItem(json, "correlation_id");
            if (cJSON_IsString(correlation_id))
            {
                send_response(correlation_id->valuestring, "Ack");
            }

            cJSON *type = cJSON_GetObjectItem(json, "type");
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
        ESP_LOGE(LOG_TAG, "MQTT Error occurred");
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
    }
    generate_unique_id();
    ESP_LOGI(LOG_TAG, "Device ID: %s", device_id);
    client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);
}
void mqtt_app_stop()
{
    if (client != NULL)
    {
        ESP_LOGI(LOG_TAG, "Stopping MQTT client...");
        esp_mqtt_client_stop(client);
        vTaskDelay(10 / portTICK_PERIOD_MS);
        esp_mqtt_client_destroy(client);
        client = NULL;
        ESP_LOGI(LOG_TAG, "MQTT client stopped and destroyed");
    }
}

void device_a_publish_request()
{
    char payload[128];
    snprintf(payload, sizeof(payload), "{\"requester\":\"deviceA_queue\",\"data\":\"some_request_data\"}");
    send_mqtt_message(REQUEST_TOPIC, payload);
}
