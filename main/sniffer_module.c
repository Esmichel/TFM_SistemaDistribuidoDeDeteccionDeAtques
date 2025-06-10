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
#include "../components/mqtt_communication/network_status.h"
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
#define WIFI_FC_PROTECTED_BIT (1 << 14)

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

static void debug_payload_hex(const uint8_t *data, size_t length)
{
    ESP_LOGI(TAG, "--- Payload dump (%u bytes) ---", length);
    ESP_LOG_BUFFER_HEXDUMP(TAG, data, length, ESP_LOG_INFO);
}
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
    ESP_LOGW(TAG, "Dumping ARP Packet (%d bytes):", len);
    for (int i = 0; i < len; i++)
    {
        if (i % 16 == 0)
        {
            ESP_LOGW(TAG, "");
        }
        ESP_LOGW(TAG, "%02X ", data[i]);
    }
    ESP_LOGW(TAG, "\n");
}
void detect_arp_packet(const wifi_packet_t *wpkt)
{
    if (wpkt->discarded)
        return;
    if (wpkt->l2protocol != ETH_TYPE_ARP)
        return;
    if (wpkt->payload_length < 8)
        return;
    uint16_t oper = ntohs(*(uint16_t *)(wpkt->payload + 6));

    if (oper != 2)
        return;
    ESP_LOGW(TAG, "Detected ARP response");
    process_arp_packet((wifi_packet_t *)wpkt);
}

wifi_packet_t create_wifi_packet(wifi_promiscuous_pkt_t *pkt, wifi_promiscuous_pkt_type_t type)
{
    uint8_t *payload = pkt->payload;
    size_t raw_len = pkt->rx_ctrl.sig_len;
    wifi_packet_t wifi_pkt = {0};
    memset(wifi_pkt.ssid, 0, sizeof(wifi_pkt.ssid));

    wifi_pkt.payload = payload;
    wifi_pkt.payload_length = raw_len;

    uint16_t fc = payload[0] | (payload[1] << 8);
    wifi_pkt.discarded = false;
    wifi_pkt.type = (fc & WIFI_FC_TYPE_MASK) >> 2;
    wifi_pkt.subtype = (fc & WIFI_FC_SUBTYPE_MASK) >> 4;
    bool toDS = (fc & BIT(8)) != 0;
    bool fromDS = (fc & BIT(9)) != 0;
    bool is_encrypted = (fc & WIFI_FC_PROTECTED_BIT) != 0;

    if (is_encrypted ||
        (type == WIFI_FC_TYPE_DATA &&
         (wifi_pkt.subtype == 0x4 || wifi_pkt.subtype == 0xC ||
          wifi_pkt.subtype == 0xE || wifi_pkt.subtype == 0xF)))
    {
        wifi_pkt.discarded = true;
        return wifi_pkt;
    }

    uint8_t *addr1 = payload + 4;
    uint8_t *addr2 = payload + 10;
    memcpy(wifi_pkt.dst_mac, addr1, 6);
    memcpy(wifi_pkt.src_mac, addr2, 6);

    wifi_pkt.timestamp = pkt->rx_ctrl.timestamp;
    wifi_pkt.signal_strength = pkt->rx_ctrl.rssi;

    uint8_t *tagged_params;
    if (raw_len > IEEE_MGMT_TAGGED_PARAMS_OFFSET &&
        (wifi_pkt.subtype == 0x08 || wifi_pkt.subtype == 0x05))
    {
        tagged_params = payload + IEEE_MGMT_TAGGED_PARAMS_OFFSET;
    }
    else if (raw_len > 24)
    {
        tagged_params = payload + 24;
    }
    else
    {
        tagged_params = NULL;
    }

    int tagged_len = 0;
    if (tagged_params)
    {
        tagged_len = (int)(raw_len - (tagged_params - payload));
        if (tagged_len < 0)
            tagged_len = 0;
    }

    wifi_pkt.ie = tagged_params;
    wifi_pkt.ie_len = (uint16_t)tagged_len;

    bool ssid_found = false;
    uint8_t ssid_len = 0;
    uint8_t *ssid_data = NULL;

    if (tagged_len >= 2)
    {
        int index = 0;
        while (index + 1 < tagged_len)
        {
            uint8_t tag_num = tagged_params[index];
            uint8_t orig_len = tagged_params[index + IEEE_TAG_LEN_OFFSET];
            if (index + 2 + orig_len > tagged_len)
                break;
            if (tag_num == IEEE_TAG_SSID_NUMBER)
            {
                ssid_found = true;
                ssid_len = (orig_len > sizeof(wifi_pkt.ssid) - 1)
                               ? sizeof(wifi_pkt.ssid) - 1
                               : orig_len;
                ssid_data = &tagged_params[index + 2];
                break;
            }
            index += 2 + orig_len;
        }
    }

    if (!ssid_found)
    {
        strncpy((char *)wifi_pkt.ssid, SSID_NO_TAG_STR, sizeof(wifi_pkt.ssid) - 1);
        wifi_pkt.ssid[sizeof(wifi_pkt.ssid) - 1] = '\0';
    }
    else if (ssid_len == 0)
    {
        strncpy((char *)wifi_pkt.ssid, SSID_HIDDEN_STR, sizeof(wifi_pkt.ssid) - 1);
        wifi_pkt.ssid[sizeof(wifi_pkt.ssid) - 1] = '\0';
    }
    else
    {
        memcpy(wifi_pkt.ssid, ssid_data, ssid_len);
        wifi_pkt.ssid[ssid_len] = '\0';
        for (int i = 0; i < ssid_len; ++i)
        {
            if (wifi_pkt.ssid[i] < 32 || wifi_pkt.ssid[i] > 126)
                wifi_pkt.ssid[i] = '.';
        }
    }

    snprintf(wifi_pkt.packet_id, sizeof(wifi_pkt.packet_id),
             "%llu", (unsigned long long)esp_timer_get_time());

    wifi_pkt.channel = pkt->rx_ctrl.channel;
    wifi_pkt.is_broadcast =
        (wifi_pkt.dst_mac[0] == MAC_BROADCAST_BYTE &&
         wifi_pkt.dst_mac[1] == MAC_BROADCAST_BYTE &&
         wifi_pkt.dst_mac[2] == MAC_BROADCAST_BYTE &&
         wifi_pkt.dst_mac[3] == MAC_BROADCAST_BYTE &&
         wifi_pkt.dst_mac[4] == MAC_BROADCAST_BYTE &&
         wifi_pkt.dst_mac[5] == MAC_BROADCAST_BYTE);

    size_t hdr_len = 24 + ((toDS && fromDS) ? 6 : 0) + ((wifi_pkt.subtype & 0x08) ? 2 : 0);
    if (raw_len >= hdr_len + 8)
    {
        uint8_t *llc = payload + hdr_len;
        if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03)
        {
            uint16_t eth = (llc[6] << 8) | llc[7];
            wifi_pkt.l2protocol = eth;
            wifi_pkt.payload = llc + 8;
            wifi_pkt.payload_length = raw_len - (hdr_len + 8);
        }
    }

    wifi_pkt.protocol = 0;
    wifi_pkt.src_port = 0;
    wifi_pkt.dst_port = 0;
    wifi_pkt.src_addr = 0;
    wifi_pkt.dst_addr = 0;
    wifi_pkt.ttl = 0;
    wifi_pkt.flags = 0;

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
    if (wifi_pkt.discarded)
        return;

    if (type == WIFI_PKT_MGMT)
    {
        check_for_deauth_attack(&wifi_pkt);
        analyze_evil_twin(&wifi_pkt);
        detect_beacon_flood(&wifi_pkt);
    }
    else if (type == WIFI_PKT_CTRL)
    {
        ESP_LOGI(TAG, "Received Control packet");
    }
    else if (type == WIFI_PKT_DATA)
    {
        process_wifi_frame(pkt->payload, pkt->rx_ctrl.sig_len, &wifi_pkt);
        detect_arp_packet(&wifi_pkt);
    }
    send_wifi_packet_json(&wifi_pkt);
    int64_t end_time = esp_timer_get_time();
    int64_t duration = end_time - start_time;
    if (duration > SNIFFER_SLOW_CB_THRESHOLD_US)
    {
        ESP_LOGI("SNIFFER", "Slow callback: %lld us", duration);
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
    // ESP_LOGI(TAG, "Sniffer filter mode updated to: %s", config->filter_mode);
}
