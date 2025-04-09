#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "network_status.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_event.h"
#include "cJSON.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "requester.h"
#include "../tools/base64encoding.h"
#include "mbedtls/base64.h"
#include "../tools/hash_function.h"
#include "../tools/arp_table.h"

#define MAX_PACKET_SIZE 2048
#define MAX_MAC_ADDRESS_LEN 18
#define MQTT_TOPIC "wifi/status"
#define LOG_TAG "network_status"
static const char *TAG = "network_status";

char *mac_to_string(uint8_t *mac)
{
    char *str = (char *)malloc(MAX_MAC_ADDRESS_LEN);
    if (str)
    {
        snprintf(str, MAX_MAC_ADDRESS_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    return str;
}

char *generate_sender_id(uint8_t *mac)
{
    char *mac_str = mac_to_string(mac);
    if (mac_str == NULL)
    {
        return NULL;
    }

    uint32_t timestamp = esp_timer_get_time();

    char *sender_id = (char *)malloc(64);
    if (sender_id)
    {
        snprintf(sender_id, 64, "%s-%lu", mac_str, timestamp);
    }

    free(mac_str);
    return sender_id;
}
uint32_t generate_packet_hash(wifi_packet_t *wifi_pkt)
{
    char data_to_hash[1024];
    snprintf(data_to_hash, sizeof(data_to_hash), "%s-%lu-%s-%d-%s",
             (char *)wifi_pkt->src_mac, wifi_pkt->timestamp, wifi_pkt->protocol,
             wifi_pkt->signal_strength, wifi_pkt->payload);

    return hash_ssid(data_to_hash);
}

const char *get_frame_type(uint8_t frame_type)
{
    switch (frame_type)
    {
    case 0:
        return "management";
    case 1:
        return "control";
    case 2:
        return "data";
    default:
        return "unknown";
    }
}

const char *get_frame_subtype(uint8_t frame_type, uint8_t subtype)
{
    if (frame_type == 0)
    {
        const char *subtypes[] = {
            "association_request", "association_response", "reassociation_request",
            "reassociation_response", "probe_request", "probe_response", "reserved",
            "beacon", "reserved", "disassociation", "authentication", "deauthentication",
            "action", "action_no_ack", "reserved"};
        return (subtype < sizeof(subtypes) / sizeof(subtypes[0])) ? subtypes[subtype] : "reserved";
    }
    else if (frame_type == 1)
    {
        const char *subtypes[] = {
            "reserved", "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
            "reserved", "block_ack_request", "block_ack", "ps_poll", "rts", "cts", "ack",
            "cf_end", "cf_end_ack"};
        return (subtype < sizeof(subtypes) / sizeof(subtypes[0])) ? subtypes[subtype] : "reserved";
    }
    else if (frame_type == 2)
    {
        const char *subtypes[] = {
            "data", "reserved", "reserved", "reserved", "null_data", "reserved", "reserved",
            "reserved", "qos_data", "reserved", "reserved", "reserved", "qos_null", "reserved"};
        return (subtype < sizeof(subtypes) / sizeof(subtypes[0])) ? subtypes[subtype] : "reserved";
    }
    return "unknown";
}

void send_wifi_packet_json(wifi_packet_t *wifi_pkt)
{

    cJSON *root = cJSON_CreateObject();
    if (!root)
    {
        ESP_LOGE(TAG, "Failed to create JSON object");
        return;
    }

    char *sender_id = generate_sender_id(wifi_pkt->src_mac);
    if (sender_id != NULL)
    {
        cJSON_AddStringToObject(root, "sender_id", sender_id);
        free(sender_id);
    }

    cJSON_AddStringToObject(root, "packet_id", wifi_pkt->packet_id);
    cJSON_AddNumberToObject(root, "timestamp", wifi_pkt->timestamp);

    const char *frame_type_str = get_frame_type(wifi_pkt->type);
    const char *frame_subtype_str = get_frame_subtype(wifi_pkt->type, wifi_pkt->subtype);
    cJSON_AddStringToObject(root, "frame_type", frame_type_str);
    cJSON_AddStringToObject(root, "frame_subtype", frame_subtype_str);

    char *src_mac_str = mac_to_string(wifi_pkt->src_mac);
    char *dst_mac_str = mac_to_string(wifi_pkt->dst_mac);
    cJSON_AddStringToObject(root, "src_mac", src_mac_str ? src_mac_str : "unknown");
    cJSON_AddStringToObject(root, "dst_mac", dst_mac_str ? dst_mac_str : "unknown");
    free(src_mac_str);
    free(dst_mac_str);

    cJSON_AddNumberToObject(root, "signal_strength", wifi_pkt->signal_strength);
    cJSON_AddNumberToObject(root, "channel", wifi_pkt->channel);

    cJSON_AddStringToObject(root, "protocol", wifi_pkt->protocol);
    cJSON_AddNumberToObject(root, "src_port", wifi_pkt->src_port);
    cJSON_AddNumberToObject(root, "dst_port", wifi_pkt->dst_port);

    cJSON_AddBoolToObject(root, "is_broadcast", wifi_pkt->is_broadcast);

    cJSON_AddNumberToObject(root, "ssid_length", wifi_pkt->ssid_length);
    cJSON_AddStringToObject(root, "ssid", (wifi_pkt->ssid_length > 0) ? (char *)wifi_pkt->ssid : "null");

    uint32_t packet_hash = generate_packet_hash(wifi_pkt);
    cJSON_AddNumberToObject(root, "packet_hash", packet_hash);

    cJSON *payload = cJSON_CreateObject();
    cJSON_AddNumberToObject(payload, "length", wifi_pkt->payload_length);

    size_t base64_size = ((wifi_pkt->payload_length + 2) / 3) * 4 + 1;
    char *encoded_payload = malloc(base64_size);
    if (encoded_payload == NULL)
    {
        ESP_LOGE(TAG, "Failed to allocate memory for base64 payload");
        cJSON_Delete(root);
        return;
    }
    size_t olen = 0;
    int ret = mbedtls_base64_encode((unsigned char *)encoded_payload,
                                    base64_size,
                                    &olen,
                                    wifi_pkt->payload,
                                    wifi_pkt->payload_length);
    if (ret != 0)
    {
        ESP_LOGE(TAG, "Base64 encoding failed, error: %d", ret);
        encoded_payload[0] = '\0';
    }
    else
    {
        if (olen < base64_size)
            encoded_payload[olen] = '\0';
        else
            encoded_payload[base64_size - 1] = '\0';
    }
    cJSON_AddStringToObject(payload, "payload_data", encoded_payload);
    free(encoded_payload);

    cJSON_AddItemToObject(root, "payload", payload);

    char *json_string = cJSON_PrintUnformatted(root);
    send_mqtt_message(MONITORING_TOPIC, json_string);

    cJSON_Delete(root);
    free(json_string);
}

#include "cJSON.h"
#include <time.h>

void build_arp_table_json_payload(arp_entry_t *arp_table, int arp_table_size)
{
    cJSON *root = cJSON_CreateObject();

    time_t now = time(NULL);
    struct tm *t = gmtime(&now);
    char iso_timestamp[30];
    strftime(iso_timestamp, sizeof(iso_timestamp), "%Y-%m-%dT%H:%M:%SZ", t);
    cJSON_AddStringToObject(root, "timestamp", iso_timestamp);

    cJSON *entries = cJSON_CreateArray();
    for (int i = 0; i < arp_table_size; i++)
    {
        cJSON *entry = cJSON_CreateObject();

        uint8_t *ip_bytes = (uint8_t *)&arp_table[i].ip;
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                 ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 arp_table[i].mac[0], arp_table[i].mac[1], arp_table[i].mac[2],
                 arp_table[i].mac[3], arp_table[i].mac[4], arp_table[i].mac[5]);

        cJSON_AddStringToObject(entry, "ip", ip_str);
        cJSON_AddStringToObject(entry, "mac", mac_str);

        cJSON_AddItemToArray(entries, entry);
    }

    cJSON_AddItemToObject(root, "entries", entries);

    char *json_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    send_mqtt_message(ARP_TOPIC, json_string);
    free(json_string);
}
