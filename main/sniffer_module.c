#include "sniffer_module.h"

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <arpa/inet.h>
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "./attack_detection/deauth_attack.h"
#include "./attack_detection/evil_twin.h"
#include "./attack_detection/arp_spoofing.h"
#include "./attack_detection/beacon_flood.h"
#include "./MQTT_Comunication/network_status.h"
#include "./tools/l3_processor.h"
#include "./tools/l7_processor.h"
#include "./tools/centralized_config.h"

#define ETH_TYPE_ARP 0x0806
#define MAX_CHANNELS 13
#define HOP_INTERVAL_MS 50
#define MAC_BROADCAST_BYTE 0xFF
#define WIFI_FRAME_CONTROL_MGMT_MASK 0x80
#define WIFI_FC_TYPE_MASK 0x000C
#define WIFI_FC_SUBTYPE_MASK 0x00F0
#define MAC_ADDR_LEN 6
#define WIFI_MGMT_HEADER_OFFSET 30
#define WIFI_OTHER_HEADER_OFFSET 24
#define IEEE_TAG_SSID_NUMBER 0
#define IEEE_TAG_LEN_OFFSET 1
#define IEEE_MGMT_TAGGED_PARAMS_OFFSET 36
#define SNIFFER_SLOW_CB_THRESHOLD_US 1000
#define ARP_SIG_BYTE 0xAA
#define CHANNEL_HOP_PERIOD_MS (HOP_INTERVAL_MS * 3000)
#define SSID_NO_TAG_STR "<No SSID>"
#define SSID_HIDDEN_STR "<Hidden>"


static const char *TAG = "wifi_promiscuous";

// loaded config values
bool hoping_enabled = false;
// pending config values
//  default channel
//  hop interval
//  sniffer filter mode

sniffer_filter_t selected_filter = FILTER_MANAGEMENT_ONLY;
esp_timer_handle_t channel_hop_timer;
static uint8_t channels[MAX_CHANNELS] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
volatile int actual_wifi_channel = 0;
static int current_channel = 0;
AppConfig *config = NULL;

wifi_promiscuous_filter_t get_filter_from_mode(SnifferFilterMode mode)
{
    wifi_promiscuous_filter_t filt = {0};

    switch (mode)
    {
    case FILTER_MODE_ALL:
        filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                           WIFI_PROMIS_FILTER_MASK_CTRL |
                           WIFI_PROMIS_FILTER_MASK_DATA;
        break;
    case FILTER_MODE_MGMT_ONLY:
        filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
        break;
    case FILTER_MODE_DATA_ONLY:
        filt.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
        break;
    case FILTER_MODE_CTRL_ONLY:
        filt.filter_mask = WIFI_PROMIS_FILTER_MASK_CTRL;
        break;
    case FILTER_MODE_NO_MGMT:
        filt.filter_mask = WIFI_PROMIS_FILTER_MASK_CTRL |
                           WIFI_PROMIS_FILTER_MASK_DATA;
        break;
    case FILTER_MODE_STRICT_ALL:
        filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                           WIFI_PROMIS_FILTER_MASK_CTRL |
                           WIFI_PROMIS_FILTER_MASK_DATA |
                           WIFI_PROMIS_FILTER_MASK_DATA_MPDU |
                           WIFI_PROMIS_FILTER_MASK_DATA_AMPDU;
        break;
    case FILTER_MODE_BEACON_ONLY:
        // No se puede filtrar solo beacons por máscara,
        // esto se implementa en el callback con verificación adicional
        filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
        break;
    }

    return filt;
}

void hop_channel()
{
    current_channel++;
    if (current_channel >= MAX_CHANNELS)
    {
        current_channel = 0;
    }
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_channel(channels[current_channel], WIFI_SECOND_CHAN_NONE);
    wifi_promiscuous_filter_t filter = get_filter_from_mode(config->filter_mode);
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    esp_wifi_set_promiscuous(true);
    ESP_LOGD(TAG, "Channel hopped to: %d", channels[current_channel]);
}

void channel_hop_timer_cb(void *arg)
{
    if (hoping_enabled)
    {
        hop_channel();
    }
    else if (current_channel != actual_wifi_channel)
    {
        current_channel = actual_wifi_channel;
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_channel(actual_wifi_channel, WIFI_SECOND_CHAN_NONE);
        wifi_promiscuous_filter_t filter = get_filter_from_mode(config->filter_mode);
        ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
        esp_wifi_set_promiscuous(true);
        ESP_LOGD(TAG, "Channel set to: %d", actual_wifi_channel);
    }
}

void init_channel_hop_timer()
{
    esp_timer_create_args_t timer_args = {
        .callback = channel_hop_timer_cb,
        .name = "channel_hop_timer"};

    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &channel_hop_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(channel_hop_timer, CHANNEL_HOP_PERIOD_MS));
}

void debug_arp_packet(uint8_t *data, int len)
{
    ESP_LOGI(TAG, "Dumping ARP Packet (%d bytes):", len);
    for (int i = 0; i < len; i++)
    {
        if (i % 16 == 0)
        {
            ESP_LOGI(TAG, "");
        }
        ESP_LOGI(TAG, "%02X ", data[i]);
    }
    ESP_LOGI(TAG, "\n");
}
void detect_arp_packet(wifi_promiscuous_pkt_t *pkt)
{

    uint8_t *payload = pkt->payload;
    int offset = (payload[0] & WIFI_FRAME_CONTROL_MGMT_MASK) ? WIFI_MGMT_HEADER_OFFSET : WIFI_OTHER_HEADER_OFFSET;
    if (payload[offset] != ARP_SIG_BYTE || payload[offset + 1] != ARP_SIG_BYTE)
    {
        return;
    }

    uint16_t eth_type = ntohs(*(uint16_t *)(payload + offset + MAC_ADDR_LEN));
    if (eth_type != ETH_TYPE_ARP)
    {
        return;
    }
    uint8_t *arp_data = payload + offset + 8;

    // debug_arp_packet(arp_data, pkt->rx_ctrl.sig_len - offset - 8);

    uint16_t arp_operation = ntohs(*(uint16_t *)(arp_data + 6));
    if (arp_operation == 2)
        ESP_LOGI(TAG, "%02X", arp_operation);
    if (arp_operation == 2)
    {
        uint8_t *sender_mac = arp_data + 8;
        // uint32_t sender_ip = ntohl(*(uint32_t *)(arp_data + 14));
        // uint8_t *target_mac = arp_data + 18;
        uint32_t target_ip = ntohl(*(uint32_t *)(arp_data + 24));

        ESP_LOGI(TAG, "ARP Response detected! %02X:%02X:%02X:%02X:%02X:%02X is at IP %u.%u.%u.%u",
                 sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5],
                 (target_ip >> 24) & MAC_BROADCAST_BYTE, (target_ip >> 16) & MAC_BROADCAST_BYTE, (target_ip >> 8) & MAC_BROADCAST_BYTE, target_ip & MAC_BROADCAST_BYTE);

        process_arp_packet(arp_data, pkt->rx_ctrl.sig_len - offset - 8);
    }
}

wifi_packet_t create_wifi_packet(wifi_promiscuous_pkt_t *pkt, wifi_promiscuous_pkt_type_t type)
{
    wifi_packet_t wifi_pkt;
    uint8_t *payload = pkt->payload;

    uint16_t frame_control = payload[0] | (payload[1] << 8);
    wifi_pkt.type = (frame_control & WIFI_FC_TYPE_MASK) >> 2;
    wifi_pkt.subtype = (frame_control & WIFI_FC_SUBTYPE_MASK) >> 4;
    memcpy(wifi_pkt.dst_mac, payload + 4, MAC_ADDR_LEN);
    memcpy(wifi_pkt.src_mac, payload + 10, MAC_ADDR_LEN);

    wifi_pkt.timestamp = pkt->rx_ctrl.timestamp;
    wifi_pkt.signal_strength = pkt->rx_ctrl.rssi;

    uint8_t *tagged_params;
    uint8_t ssid_length = 0;
    uint8_t *ssid_data = NULL;
    bool ssid_tag_found = false;

    if (wifi_pkt.subtype == 0x08 || wifi_pkt.subtype == 0x05) // Beacon or Probe Response
    {
        tagged_params = payload + IEEE_MGMT_TAGGED_PARAMS_OFFSET;
    }
    else
    {
        tagged_params = payload + 24;
    }

    int index = 0;
    int tagged_len = pkt->rx_ctrl.sig_len - (tagged_params - payload);

    while (index + 2 <= tagged_len)
    {
        uint8_t tag_number = tagged_params[index];
        uint8_t tag_len = tagged_params[index + IEEE_TAG_LEN_OFFSET];

        if (index + 2 + tag_len > tagged_len)
        {
            break;
        }

        if (tag_number == IEEE_TAG_SSID_NUMBER)
        {
            ssid_tag_found = true;
            if (tag_len > sizeof(wifi_pkt.ssid) - 1)  // <-- proteger contra desbordo
                tag_len = sizeof(wifi_pkt.ssid) - 1;
            ssid_length = tag_len;
            ssid_data = &tagged_params[index + 2];
            break;
        }

        index += 2 + tag_len;
    }

    memset(wifi_pkt.ssid, 0, sizeof(wifi_pkt.ssid));

    if (!ssid_tag_found)
    {
        strncpy((char *)wifi_pkt.ssid, SSID_NO_TAG_STR, sizeof(wifi_pkt.ssid) - 1);
    }
    else if (ssid_length == 0)
    {
        strncpy((char *)wifi_pkt.ssid, SSID_HIDDEN_STR, sizeof(wifi_pkt.ssid) - 1);
    }
    else
    {
        memcpy(wifi_pkt.ssid, ssid_data, ssid_length);
        wifi_pkt.ssid[ssid_length] = '\0';

        for (int i = 0; i < ssid_length; ++i)
        {
            if (wifi_pkt.ssid[i] < 32 || wifi_pkt.ssid[i] > 126)
                wifi_pkt.ssid[i] = '.';
        }
    }

    snprintf(wifi_pkt.packet_id, sizeof(wifi_pkt.packet_id), "%lld", esp_timer_get_time());
    wifi_pkt.channel = pkt->rx_ctrl.channel;
    wifi_pkt.is_broadcast = (wifi_pkt.dst_mac[0] == MAC_BROADCAST_BYTE) && (wifi_pkt.dst_mac[1] == MAC_BROADCAST_BYTE) &&
                            (wifi_pkt.dst_mac[2] == MAC_BROADCAST_BYTE) && (wifi_pkt.dst_mac[3] == MAC_BROADCAST_BYTE) &&
                            (wifi_pkt.dst_mac[4] == MAC_BROADCAST_BYTE) && (wifi_pkt.dst_mac[5] == MAC_BROADCAST_BYTE);

    snprintf(wifi_pkt.protocol, sizeof(wifi_pkt.protocol), "Unknown");
    // wifi_pkt.src_port = 0;
    // wifi_pkt.dst_port = 0;
    // wifi_pkt.payload = pkt->payload;
    // wifi_pkt.payload_length = pkt->rx_ctrl.sig_len;

    return wifi_pkt;
}


static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;

    int64_t start_time = esp_timer_get_time();

    if (pkt->rx_ctrl.sig_len < sizeof(wifi_mac_hdr_t))
    {
        ESP_LOGW(TAG, "Packet too short, ignoring");
        return;
    }

    wifi_packet_t wifi_pkt = create_wifi_packet(pkt, type);

    if (type == WIFI_PKT_MGMT)
    {
        // check_for_deauth_attack(&wifi_pkt);
        // analyze_evil_twin(&wifi_pkt);
        // detect_beacon_flood(&wifi_pkt);
    }
    else if (type == WIFI_PKT_CTRL)
    {
        ESP_LOGI(TAG, "Received Control packet");
    }
    else if (type == WIFI_PKT_DATA)
    {
        process_wifi_frame(pkt->payload, pkt->rx_ctrl.sig_len, &wifi_pkt);
        //detect_arp_packet(pkt);
    }
    send_wifi_packet_json(&wifi_pkt);
    int64_t end_time = esp_timer_get_time();
    int64_t duration = end_time - start_time;
    if (duration > SNIFFER_SLOW_CB_THRESHOLD_US)
    {
        ESP_LOGW("SNIFFER", "Slow callback: %lld us", duration);
    }
    return;
}

void wifi_sniffer_init(sniffer_filter_t filter)
{
    ESP_LOGI(TAG, "Sniffer filter: %d", filter);
    config = get_config();
    actual_wifi_channel = config->deafult_channel;
    if (config->enable_channel_hopping)
    {
        hoping_enabled = true;
        ESP_LOGI(TAG, "Channel hopping enabled");
    }
    else
    {
        hoping_enabled = false;
        ESP_LOGI(TAG, "Channel hopping disabled");
        esp_wifi_set_channel(config->deafult_channel, WIFI_SECOND_CHAN_NONE);
    }
    selected_filter = filter;
    init_channel_hop_timer();
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_cb));
}

void wifi_sniffer_start(void)
{
    ESP_LOGI(TAG, "Starting Wi-Fi sniffer...");
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_channel(actual_wifi_channel, WIFI_SECOND_CHAN_NONE);
    wifi_promiscuous_filter_t filter = get_filter_from_mode(config->filter_mode);
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    esp_wifi_set_promiscuous(true);
}

void print_heap_info()
{
    multi_heap_info_t info;
    heap_caps_get_info(&info, MALLOC_CAP_DEFAULT);
    ESP_LOGI("MEMORY", "Free heap: %d, Largest free block: %d", info.total_free_bytes, info.largest_free_block);
}

void wifi_sniffer_stop(void)
{
    ESP_LOGI(TAG, "Stopping Wi-Fi sniffer...");
    ESP_ERROR_CHECK(esp_timer_stop(channel_hop_timer));
    ESP_LOGI(TAG, "Hopping stopped");
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(NULL));
    ESP_LOGI(TAG, "Wi-Fi sniffer stopped.");
    print_heap_info();
}

void sniffer_update_config()
{
    AppConfig *config = get_config();
    static bool last_hopping_enabled = false;
    static int last_hop_interval_ms = -1;

    if (!config->enable_channel_hopping)
    {
        ESP_LOGI(TAG, "Updating default channel to %d", config->deafult_channel);
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_channel(config->deafult_channel, WIFI_SECOND_CHAN_NONE);
        wifi_promiscuous_filter_t filter = get_filter_from_mode(config->filter_mode);
        ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
        esp_wifi_set_promiscuous(true);
    }

    // Comprobar si hay que actualizar hopping (enable o intervalo)
    bool hopping_config_changed =
        (last_hopping_enabled != config->enable_channel_hopping) ||
        (last_hop_interval_ms != config->hop_interval_ms);

    if (hopping_config_changed)
    {
        last_hopping_enabled = config->enable_channel_hopping;
        last_hop_interval_ms = config->hop_interval_ms;

        if (last_hopping_enabled)
        {
            ESP_LOGI(TAG, "Channel hopping enabled, interval: %d ms", last_hop_interval_ms);
    //         ESP_ERROR_CHECK(esp_timer_stop(channel_hop_timer)); // por si estaba activo con otro intervalo
    //         ESP_ERROR_CHECK(esp_timer_start_periodic(channel_hop_timer, last_hop_interval_ms * 1000));
        }
        else
        {
            ESP_LOGI(TAG, "Channel hopping disabled");
    //         ESP_ERROR_CHECK(esp_timer_stop(channel_hop_timer));
        }

        hoping_enabled = last_hopping_enabled;
    }

    // Filtro de captura
    esp_wifi_set_promiscuous(false);
    wifi_promiscuous_filter_t filter = get_filter_from_mode(config->filter_mode);
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    esp_wifi_set_promiscuous(true);
    //ESP_LOGI(TAG, "Sniffer filter mode updated to: %s", config->filter_mode);
}
