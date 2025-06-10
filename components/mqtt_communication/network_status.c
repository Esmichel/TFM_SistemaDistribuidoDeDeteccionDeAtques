#include "network_status.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include "cJSON.h"
#include <time.h>
#include <esp_system.h>
#include <esp_chip_info.h>
#include "esp_cpu.h"
#include "soc/rtc.h"
#include "esp_private/rtc_clk.h"

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
const char *get_layer2_protocol_name(uint16_t proto)
{
    switch (proto)
    {
    case 0x0800:
        return "IPv4";
    case 0x86DD:
        return "IPv6";
    case 0x0806:
        return "ARP";
    case 0x888E:
        return "EAPOL";
    case 0x8100:
        return "VLAN";
    default:
        return "Unknown";
    }
}

// Añadir arriba, junto con get_layer2_protocol_name()
const char *get_layer3_protocol_name(uint8_t proto)
{
    switch (proto)
    {
    case 1:
        return "ICMP";
    case 2:
        return "IGMP";
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    case 41:
        return "IPv6";
    case 89:
        return "OSPF";
    default:
        return "Unknown";
    }
}

const char *get_tcp_flags_description(uint8_t flags)
{
    static char desc[64];
    desc[0] = '\0';

    if (flags & 0x01)
        strcat(desc, "FIN ");
    if (flags & 0x02)
        strcat(desc, "SYN ");
    if (flags & 0x04)
        strcat(desc, "RST ");
    if (flags & 0x08)
        strcat(desc, "PSH ");
    if (flags & 0x10)
        strcat(desc, "ACK ");
    if (flags & 0x20)
        strcat(desc, "URG ");
    if (flags & 0x40)
        strcat(desc, "ECE ");
    if (flags & 0x80)
        strcat(desc, "CWR ");

    if (desc[0] == '\0')
        return "None";
    else
    {
        size_t len = strlen(desc);
        if (len > 0 && desc[len - 1] == ' ')
            desc[len - 1] = '\0';
        return desc;
    }
}

char *generate_sender_id(uint8_t *mac)
{
    if (mac == NULL)
        return NULL;

    char mac_str[13];
    snprintf(mac_str, sizeof(mac_str),
             "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);

    char *sender_id = (char *)malloc(32);
    if (!sender_id)
        return NULL;

    snprintf(sender_id, 32, "esp32_%s", mac_str);

    return sender_id;
}
uint32_t generate_packet_hash(wifi_packet_t *wifi_pkt)
{
    char data_to_hash[1024];

    snprintf(data_to_hash, sizeof(data_to_hash), "%s-%lu-%d-%s",
             (char *)wifi_pkt->src_mac, wifi_pkt->timestamp,
             wifi_pkt->signal_strength, wifi_pkt->payload);

    return hash_ssid(data_to_hash);
}

uint32_t generate_alert_hash(wifi_packet_t *wifi_pkt, char *attack)
{
    char data_to_hash[1024];
    snprintf(data_to_hash, sizeof(data_to_hash), "%s-%lu-%d-%s",
             (char *)wifi_pkt->src_mac, wifi_pkt->timestamp,
             wifi_pkt->signal_strength, attack);

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
        static const char *mgmt_subtypes[16] = {
            "association_request",
            "association_response",
            "reassociation_request",
            "reassociation_response",
            "probe_request",
            "probe_response",
            "timing_advertisement",
            "reserved",
            "beacon",
            "atim",
            "disassociation",
            "authentication",
            "deauthentication",
            "action",
            "action_no_ack",
            "reserved"};
        return mgmt_subtypes[subtype];
    }
    else if (frame_type == 1)
    {
        static const char *ctrl_subtypes[16] = {
            "reserved",
            "reserved",
            "trigger",
            "block_ack_request",
            "block_ack",
            "ps_poll",
            "rts",
            "cts",
            "ack",
            "cf_end",
            "cf_end_ack",
            "null_func",
            "qos_null",
            "reserved",
            "reserved",
            "reserved"};
        return ctrl_subtypes[subtype];
    }
    else if (frame_type == 2)
    {
        static const char *data_subtypes[16] = {
            "data",
            "data_cf_ack",
            "data_cf_poll",
            "data_cf_ack_poll",
            "null_data",
            "cf_ack",
            "cf_poll",
            "cf_ack_cf_poll",
            "qos_data",
            "qos_data_cf_ack",
            "qos_data_cf_poll",
            "qos_data_cf_ack_poll",
            "qos_null",
            "reserved",
            "reserved",
            "reserved"};
        return data_subtypes[subtype];
    }
    return "unknown";
}

void debug_heap(const char *label)
{
    multi_heap_info_t info;
    heap_caps_get_info(&info, MALLOC_CAP_DEFAULT);
    ESP_LOGW(TAG, "[%s] Heap - Free: %d, Min Free: %d, Largest Free: %d, Allocated Blocks: %d",
             label, info.total_free_bytes, info.minimum_free_bytes, info.largest_free_block, info.allocated_blocks);
}

void send_alert(const wifi_packet_t *pkt, const char *fmt, ...)
{
    char buf[128];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    ESP_LOGW(TAG, "%s", buf);
    build_attack_alert_payload((wifi_packet_t *)pkt, buf);
}

void send_wifi_packet_json(wifi_packet_t *wifi_pkt)
{
    debug_heap("BEFORE send_wifi_packet_json");
    static char json_buffer[1024]; // Ajusta tamaño según lo que quieras enviar
    cJSON *root = cJSON_CreateObject();
    if (!root)
    {
        ESP_LOGE(TAG, "Failed to create JSON root");
        return;
    }

    uint8_t mac[6];
    esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);

    char sender_id[32];
    snprintf(sender_id, sizeof(sender_id), "esp32_%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    cJSON_AddStringToObject(root, "sender_id", sender_id);

    cJSON_AddStringToObject(root, "packet_id", wifi_pkt->packet_id);
    cJSON_AddNumberToObject(root, "timestamp", wifi_pkt->timestamp);
    cJSON_AddStringToObject(root, "frame_type", get_frame_type(wifi_pkt->type));
    cJSON_AddStringToObject(root, "frame_subtype", get_frame_subtype(wifi_pkt->type, wifi_pkt->subtype));

    char src_mac[18], dst_mac[18];
    snprintf(src_mac, sizeof(src_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             wifi_pkt->src_mac[0], wifi_pkt->src_mac[1], wifi_pkt->src_mac[2],
             wifi_pkt->src_mac[3], wifi_pkt->src_mac[4], wifi_pkt->src_mac[5]);

    snprintf(dst_mac, sizeof(dst_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             wifi_pkt->dst_mac[0], wifi_pkt->dst_mac[1], wifi_pkt->dst_mac[2],
             wifi_pkt->dst_mac[3], wifi_pkt->dst_mac[4], wifi_pkt->dst_mac[5]);

    cJSON_AddStringToObject(root, "src_mac", src_mac);
    cJSON_AddStringToObject(root, "dst_mac", dst_mac);
    cJSON_AddNumberToObject(root, "signal_strength", wifi_pkt->signal_strength);
    cJSON_AddNumberToObject(root, "channel", wifi_pkt->channel);
    cJSON_AddStringToObject(root, "layer3_protocol", get_layer3_protocol_name(wifi_pkt->protocol));

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr_in = {.s_addr = wifi_pkt->src_addr};
    struct in_addr dst_addr_in = {.s_addr = wifi_pkt->dst_addr};

    inet_ntop(AF_INET, &src_addr_in, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst_addr_in, dst_ip, sizeof(dst_ip));

    cJSON_AddStringToObject(root, "src_addr", src_ip);
    cJSON_AddStringToObject(root, "dst_addr", dst_ip);
    cJSON_AddNumberToObject(root, "src_port", ntohs(wifi_pkt->src_port));
    cJSON_AddNumberToObject(root, "dst_port", ntohs(wifi_pkt->dst_port));
    cJSON_AddNumberToObject(root, "ttl", wifi_pkt->ttl);
    cJSON_AddStringToObject(root, "flags_description", get_tcp_flags_description(wifi_pkt->flags));
    cJSON_AddBoolToObject(root, "is_broadcast", wifi_pkt->is_broadcast);
    cJSON_AddNumberToObject(root, "ssid_length", wifi_pkt->ssid_length);
    cJSON_AddStringToObject(root, "ssid", (const char *)wifi_pkt->ssid);
    cJSON_AddNumberToObject(root, "packet_hash", generate_packet_hash(wifi_pkt));

    cJSON *payload = cJSON_CreateObject();
    cJSON_AddNumberToObject(payload, "length", wifi_pkt->payload_length);
    cJSON_AddStringToObject(payload, "payload_data", "not provided");
    cJSON_AddItemToObject(root, "payload", payload);

    // Usar cJSON_PrintPreallocated para evitar malloc()
    bool ok = cJSON_PrintPreallocated(root, json_buffer, sizeof(json_buffer), false);
    if (ok)
    {
        send_mqtt_message(MONITORING_TOPIC, json_buffer);
    }
    else
    {
        ESP_LOGE(TAG, "JSON serialization failed (buffer too small?)");
    }

    cJSON_Delete(root); // Libera solo los nodos de cJSON, no el buffer externo
    debug_heap("AFTER send_wifi_packet_json");
}

// static const char *TAG = "MONITOR";

// Estructura para obtener información detallada del heap
static void get_heap_info_json(cJSON *parent)
{
    multi_heap_info_t info_total = {0};
    heap_caps_get_info(&info_total, MALLOC_CAP_8BIT); // Incluye SRAM interna + DMA

    // Datos globales del heap
    cJSON_AddNumberToObject(parent, "total_free_bytes", info_total.total_free_bytes);
    cJSON_AddNumberToObject(parent, "total_free_blocks", info_total.free_blocks);
    cJSON_AddNumberToObject(parent, "total_largest_block", info_total.largest_free_block);
    cJSON_AddNumberToObject(parent, "heap_min_free", info_total.minimum_free_bytes);
    cJSON_AddNumberToObject(parent, "heap_allocated_blocks", info_total.allocated_blocks);

    // Fragmentación aproximada: 1 - (módulo)
    if (info_total.total_free_bytes > 0)
    {
        float frag = 1.0f - ((float)info_total.largest_free_block / (float)info_total.total_free_bytes);
        cJSON_AddNumberToObject(parent, "heap_fragmentation", (int)(frag * 100)); // porcentaje
    }
    else
    {
        cJSON_AddNumberToObject(parent, "heap_fragmentation", 0);
    }

    // Heap en SRAM interna únicamente (MALLOC_CAP_INTERNAL)
    multi_heap_info_t info_internal = {0};
    heap_caps_get_info(&info_internal, MALLOC_CAP_INTERNAL);
    cJSON_AddNumberToObject(parent, "int_free_bytes", info_internal.total_free_bytes);
    cJSON_AddNumberToObject(parent, "int_free_blocks", info_internal.free_blocks);
    cJSON_AddNumberToObject(parent, "int_largest_block", info_internal.largest_free_block);
}

void build_monitoring_payload()
{
    debug_heap("BEFORE send_monitoring_packet_json");

    static char json_buffer[2048];

    cJSON *root = cJSON_CreateObject();
    if (!root)
    {
        ESP_LOGE(TAG, "Failed to create monitoring JSON object");
        return;
    }

    // --- 1. TIMESTAMP (ISO 8601) ---
    time_t now = time(NULL);
    struct tm *t = gmtime(&now);
    char iso_timestamp[30];
    strftime(iso_timestamp, sizeof(iso_timestamp), "%Y-%m-%dT%H:%M:%SZ", t);
    cJSON_AddStringToObject(root, "timestamp", iso_timestamp);

    // --- 2. SENDER_ID (MAC address) ---
    uint8_t mac[6];
    if (esp_wifi_get_mac(ESP_IF_WIFI_STA, mac) == ESP_OK)
    {
        char sender_id[32];
        snprintf(sender_id, sizeof(sender_id),
                 "esp32_%02X%02X%02X%02X%02X%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        cJSON_AddStringToObject(root, "sender_id", sender_id);
    }
    else
    {
        cJSON_AddStringToObject(root, "sender_id", "unknown_mac");
    }

    // --- 3. HEAP STATUS DETALLADO (dinámico, útil) ---
    get_heap_info_json(root);

    // --- 4. UPTIME (en segundos) ---
    int64_t uptime_us = esp_timer_get_time();
    cJSON_AddNumberToObject(root, "uptime_sec", uptime_us / 1000000);

    // --- 5. FREERTOS TASK STATS (dinámico, útil) ---
    UBaseType_t task_count = uxTaskGetNumberOfTasks();
    cJSON_AddNumberToObject(root, "freertos_task_count", task_count);

    UBaseType_t stack_min_free = uxTaskGetStackHighWaterMark(NULL);
    cJSON_AddNumberToObject(root, "stack_min_free_current_task", stack_min_free);

    // --- 6. WIFI CONNECTION INFO (dinámico, útil) ---
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK)
    {
        cJSON_AddStringToObject(root, "connected_ssid", (const char *)ap_info.ssid);

        char ap_mac[18];
        snprintf(ap_mac, sizeof(ap_mac),
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 ap_info.bssid[0], ap_info.bssid[1],
                 ap_info.bssid[2], ap_info.bssid[3],
                 ap_info.bssid[4], ap_info.bssid[5]);
        cJSON_AddStringToObject(root, "ap_mac", ap_mac);

        cJSON_AddNumberToObject(root, "rssi", ap_info.rssi);
        cJSON_AddNumberToObject(root, "wifi_channel", ap_info.primary);
        cJSON_AddStringToObject(root, "auth_mode",
                                (ap_info.authmode == WIFI_AUTH_OPEN) ? "OPEN" : (ap_info.authmode == WIFI_AUTH_WEP)        ? "WEP"
                                                                            : (ap_info.authmode == WIFI_AUTH_WPA_PSK)      ? "WPA_PSK"
                                                                            : (ap_info.authmode == WIFI_AUTH_WPA2_PSK)     ? "WPA2_PSK"
                                                                            : (ap_info.authmode == WIFI_AUTH_WPA_WPA2_PSK) ? "WPA_WPA2_PSK"
                                                                                                                           : "UNKNOWN");
    }
    else
    {
        cJSON_AddStringToObject(root, "connected_ssid", "N/A");
        cJSON_AddStringToObject(root, "ap_mac", "N/A");
        cJSON_AddNumberToObject(root, "rssi", 0);
        cJSON_AddNumberToObject(root, "wifi_channel", 0);
        cJSON_AddStringToObject(root, "auth_mode", "N/A");
    }

    // --- 7. IP ADDRESS INFO (dinámico, útil) ---
    esp_netif_ip_info_t ip_info;
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK)
    {
        char ip_str[16], gw_str[16], nm_str[16];
        inet_ntoa_r(ip_info.ip, ip_str, sizeof(ip_str));
        inet_ntoa_r(ip_info.gw, gw_str, sizeof(gw_str));
        inet_ntoa_r(ip_info.netmask, nm_str, sizeof(nm_str));
        cJSON_AddStringToObject(root, "ip_addr", ip_str);
        cJSON_AddStringToObject(root, "gateway", gw_str);
        cJSON_AddStringToObject(root, "netmask", nm_str);
    }
    else
    {
        cJSON_AddStringToObject(root, "ip_addr", "0.0.0.0");
        cJSON_AddStringToObject(root, "gateway", "0.0.0.0");
        cJSON_AddStringToObject(root, "netmask", "0.0.0.0");
    }

    // --- 8. SERIALIZACIÓN Y ENVÍO ---
    bool ok = cJSON_PrintPreallocated(root, json_buffer, sizeof(json_buffer), false);
    if (ok)
    {
        send_mqtt_message(ESP32_MONITORING_TOPIC, json_buffer);
    }
    else
    {
        ESP_LOGE(TAG, "Failed to serialize JSON with static buffer");
    }

    cJSON_Delete(root);
    debug_heap("AFTER send_monitoring_packet_json");
}

void build_arp_table_json_payload(arp_entry_t *arp_table, int arp_table_size, char *type)
{
    debug_heap("BEFORE send_arp_table_json");
    cJSON *root = cJSON_CreateObject();

    time_t now = time(NULL);
    struct tm *t = gmtime(&now);
    char iso_timestamp[30];
    strftime(iso_timestamp, sizeof(iso_timestamp), "%Y-%m-%dT%H:%M:%SZ", t);
    cJSON_AddStringToObject(root, "timestamp", iso_timestamp);

    uint8_t mac[6];
    esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
    char *sender_id = generate_sender_id(mac);
    if (sender_id != NULL)
    {
        cJSON_AddStringToObject(root, "sender_id", sender_id);
        free(sender_id);
    }

    cJSON_AddStringToObject(root, "type", type);
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
    debug_heap("AFTER send_arp_table_json");
}

void build_attack_alert_payload(wifi_packet_t *wifi_pkt, char *attack)
{
    debug_heap("BEFORE send_wifi_alert_json");
    cJSON *root = cJSON_CreateObject();
    time_t now = time(NULL);
    struct tm *t = gmtime(&now);
    char iso_timestamp[30];
    strftime(iso_timestamp, sizeof(iso_timestamp), "%Y-%m-%dT%H:%M:%SZ", t);
    cJSON_AddStringToObject(root, "timestamp", iso_timestamp);

    uint8_t mac[6];
    esp_wifi_get_mac(ESP_IF_WIFI_STA, mac);
    char *sender_id = generate_sender_id(mac);
    if (sender_id != NULL)
    {
        cJSON_AddStringToObject(root, "sender_id", sender_id);
        free(sender_id);
    }

    uint32_t alert_hash = generate_alert_hash(wifi_pkt, attack);
    cJSON_AddNumberToObject(root, "alert_hash", alert_hash);

    char *src_mac_str = mac_to_string(wifi_pkt->src_mac);
    char *dst_mac_str = mac_to_string(wifi_pkt->dst_mac);
    cJSON_AddStringToObject(root, "src_mac", src_mac_str ? src_mac_str : "unknown");
    cJSON_AddStringToObject(root, "dst_mac", dst_mac_str ? dst_mac_str : "unknown");
    free(src_mac_str);
    free(dst_mac_str);

    cJSON_AddNumberToObject(root, "signal_strength", wifi_pkt->signal_strength);
    cJSON_AddStringToObject(root, "attack_type", attack);
    cJSON_AddStringToObject(root, "ssid", (const char *)wifi_pkt->ssid);

    char *json_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    send_mqtt_message(ALERT_TOPIC, json_string);
    free(json_string);
    debug_heap("AFTER send_wifi_attack_json");
}
