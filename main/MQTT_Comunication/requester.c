#include "requester.h"
#include "mqtt_client.h"
#include "esp_log.h"
#include "string.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "cJSON.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_wifi.h"

static const char *TAG = "MQTT_APP";
esp_mqtt_client_handle_t client = NULL;

#define LOG_TAG "MQTT_APP"
#define MQTT_QOS 1
#define MQTT_RETAIN 1

extern SemaphoreHandle_t wifi_semaphore;
typedef struct {
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
        .authentication.password = "admin"
    },
   // .session.keepalive = 60,
   // .session.disable_clean_session = true,
};

char device_id[20];
void generate_unique_id()
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    sprintf(device_id, "%02X%02X%02X%02X%02X%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

#define NVS_NAMESPACE "storage"
#define NVS_KEY_ANNOUNCED "announced"
bool is_announced = false;

esp_err_t check_device_announcement()
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    if (ret != ESP_OK)
    {
        ESP_LOGE(LOG_TAG, "Failed to init NVS");
        return ret;
    }
    nvs_handle_t handle;
    ret = nvs_open(NVS_NAMESPACE, NVS_READONLY, &handle);
    if (ret == ESP_OK)
    {
        uint8_t flag = 0;
        ret = nvs_get_u8(handle, NVS_KEY_ANNOUNCED, &flag);
        if (ret == ESP_OK)
        {
            is_announced = (flag == 1);
        }
        nvs_close(handle);
    }
    return ESP_OK;
}

esp_err_t set_device_announced()
{
    nvs_handle_t handle;
    esp_err_t ret = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (ret != ESP_OK)
    {
        return ret;
    }
    ret = nvs_set_u8(handle, NVS_KEY_ANNOUNCED, 1);
    if (ret == ESP_OK)
    {
        nvs_commit(handle);
        is_announced = true;
    }
    nvs_close(handle);
    return ret;
}

void announce_device()
{
    if (!is_announced)
    {
        ESP_LOGI(LOG_TAG, "Announcing device: %s", device_id);
        esp_mqtt_client_publish(client, DISCOVERY_TOPIC, device_id, 0, MQTT_QOS, MQTT_RETAIN);
        set_device_announced();
    }
    else
    {
        ESP_LOGI(LOG_TAG, "Device already announced");
    }
}

void buffer_message(const char *formatted_topic, const char *payload, int qos, int retain)
{
    mqtt_message_t msg;
    msg.topic = strdup(formatted_topic);
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
    ESP_LOGW(LOG_TAG,"Free heap size: %d bytes\n", esp_get_free_heap_size());
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
        ESP_LOGI(TAG, "Wi-Fi connected! Sending message on topic: %s", formatted_topic);
        int msg_id = esp_mqtt_client_publish(client, formatted_topic, payload, 0, MQTT_QOS, MQTT_RETAIN);
        ESP_LOGI(TAG, "Message sent with ID: %d", msg_id);
        xSemaphoreGive(wifi_semaphore);
    }
    else
    {
        ESP_LOGW(TAG, "Wi-Fi not connected! Buffering message.");
        buffer_message(formatted_topic, payload, MQTT_QOS, MQTT_RETAIN);
    }
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    switch (event_id)
    {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(LOG_TAG, "Connected to broker");
        esp_mqtt_client_subscribe(client, REQUEST_TOPIC, MQTT_QOS);
        {
            char device_topic[64];
            snprintf(device_topic, sizeof(device_topic), "rabbitmq/queue/%s", device_id);
            ESP_LOGI(LOG_TAG, "Subscribing to device topic: %s", device_topic);
            esp_mqtt_client_subscribe(client, device_topic, MQTT_QOS);
        }
        check_device_announcement();
        announce_device();
        flush_offline_messages();
        break;

    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(LOG_TAG, "MQTT client disconnected");
        break;

    case MQTT_EVENT_DATA:
    {
        ESP_LOGI(LOG_TAG, "Received MQTT data");
        char topic[event->topic_len + 1];
        strncpy(topic, event->topic, event->topic_len);
        topic[event->topic_len] = '\0';
        char data[event->data_len + 1];
        strncpy(data, event->data, event->data_len);
        data[event->data_len] = '\0';
        ESP_LOGI(LOG_TAG, "Topic: %s", topic);
        ESP_LOGI(LOG_TAG, "Message: %s", data);

        cJSON *json = cJSON_Parse(data);
        if (json == NULL)
        {
            ESP_LOGE(LOG_TAG, "Failed to parse JSON");
            break;
        }
        cJSON *response_topic_json = cJSON_GetObjectItem(json, "response_topic");
        if (!cJSON_IsString(response_topic_json))
        {
            ESP_LOGE(LOG_TAG, "Invalid response_topic in JSON");
            cJSON_Delete(json);
            break;
        }
        char response_topic[64];
        snprintf(response_topic, sizeof(response_topic), RESPONSE_TOPIC_FORMAT, response_topic_json->valuestring);
        ESP_LOGI(LOG_TAG, "Publishing response to: %s", response_topic);
        esp_mqtt_client_publish(client, response_topic, "Response from device", 0, MQTT_QOS, MQTT_RETAIN);
        cJSON_Delete(json);
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
    if (offlineQueue == NULL) {
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
        vTaskDelay(100 / portTICK_PERIOD_MS);
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
