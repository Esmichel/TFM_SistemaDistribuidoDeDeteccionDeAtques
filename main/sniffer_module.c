#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <arpa/inet.h>
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "sniffer_module.h"
#include "attack_detection/deauth_attack.h"
#include "attack_detection/evil_twin.h"
#include "attack_detection/arp_spoofing.h" 
#include "attack_detection/beacon_flood.h" 
#include "MQTT_Comunication/network_status.h"
#include "tools/l3_processor.h"
#include "tools/l7_processor.h"

#define ETH_TYPE_ARP 0x0806 
#define MAX_CHANNELS 13     
#define HOP_INTERVAL_MS 50  
static const char *TAG = "wifi_promiscuous";

sniffer_filter_t selected_filter = FILTER_MANAGEMENT_ONLY;
esp_timer_handle_t channel_hop_timer;

static uint8_t channels[MAX_CHANNELS] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

static int current_channel = 0;

void hop_channel()
{
    current_channel++;
    if (current_channel >= MAX_CHANNELS)
    {
        current_channel = 0;
    }
    esp_wifi_set_channel(channels[current_channel], WIFI_SECOND_CHAN_NONE);
    ESP_LOGD(TAG, "Channel hopped to: %d", channels[current_channel]);
}

void channel_hop_timer_cb(void *arg)
{
    hop_channel(); 
}

void init_channel_hop_timer()
{
    esp_timer_create_args_t timer_args = {
        .callback = channel_hop_timer_cb,
        .name = "channel_hop_timer"};

    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &channel_hop_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(channel_hop_timer, HOP_INTERVAL_MS * 1000));
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
    int offset = (payload[0] & 0x80) ? 30 : 24;     
    if (payload[offset] != 0xAA || payload[offset + 1] != 0xAA)
    {
        return; 
    }

    uint16_t eth_type = ntohs(*(uint16_t *)(payload + offset + 6));
    if (eth_type != 0x0806)
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
        uint32_t sender_ip = ntohl(*(uint32_t *)(arp_data + 14));
        uint8_t *target_mac = arp_data + 18;                     
        uint32_t target_ip = ntohl(*(uint32_t *)(arp_data + 24));

        ESP_LOGI(TAG, "ARP Response detected! %02X:%02X:%02X:%02X:%02X:%02X is at IP %u.%u.%u.%u",
                 sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5],
                 (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF, (target_ip >> 8) & 0xFF, target_ip & 0xFF);

        process_arp_packet(arp_data, pkt->rx_ctrl.sig_len - offset - 8);
    }
}

wifi_packet_t create_wifi_packet(wifi_promiscuous_pkt_t *pkt, wifi_promiscuous_pkt_type_t type)
{
    wifi_packet_t wifi_pkt;
    uint8_t *payload = pkt->payload;

    uint16_t frame_control = payload[0] | (payload[1] << 8);
    wifi_pkt.type = (frame_control & 0x000C) >> 2;    
    wifi_pkt.subtype = (frame_control & 0x00F0) >> 4; 
    memcpy(wifi_pkt.dst_mac, payload + 4, 6);
    memcpy(wifi_pkt.src_mac, payload + 10, 6);

    // wifi_pkt.timestamp = esp_timer_get_time();
    // ESP_LOGI(TAG, "Timestamp: %lld", wifi_pkt.timestamp);
    wifi_pkt.timestamp = pkt->rx_ctrl.timestamp;

    wifi_pkt.signal_strength = pkt->rx_ctrl.rssi;

    uint8_t *tagged_params;
    uint8_t ssid_length = 0;
    uint8_t *ssid_data = NULL;

    if (wifi_pkt.subtype == 0x08 || wifi_pkt.subtype == 0x05)
    {
        tagged_params = payload + 36; 
    }
    else
    {
        tagged_params = payload + 24; 
    }

    int index = 0;
    while (index + 1 < pkt->rx_ctrl.sig_len - (tagged_params - payload))
    {
        uint8_t tag_number = tagged_params[index];
        uint8_t tag_len = tagged_params[index + 1];

        if (index + 2 + tag_len > pkt->rx_ctrl.sig_len - (tagged_params - payload))
        {
            // ESP_LOGW(TAG, "Tag length exceeds packet length, stopping");
            break;
        }
        if (tag_number == 0)
        {
            if (tag_len > 32)
                tag_len = 32;
            ssid_length = tag_len;
            ssid_data = &tagged_params[index + 2];
            break;
        }
        index += 2 + tag_len;
    }

    memset(wifi_pkt.ssid, 0, sizeof(wifi_pkt.ssid));
    if (ssid_data && ssid_length > 0)
    {
        memcpy(wifi_pkt.ssid, ssid_data, ssid_length);
        wifi_pkt.ssid[ssid_length] = '\0';
        for (int i = 0; i < ssid_length; ++i)
        {
            if (wifi_pkt.ssid[i] < 32 || wifi_pkt.ssid[i] > 126)
                wifi_pkt.ssid[i] = '.';
        }
    }
    else
    {
        strncpy((char *)wifi_pkt.ssid, "<Hidden>", sizeof(wifi_pkt.ssid));
    }

    snprintf(wifi_pkt.packet_id, sizeof(wifi_pkt.packet_id), "%lld", esp_timer_get_time());
    wifi_pkt.channel = pkt->rx_ctrl.channel;
    wifi_pkt.is_broadcast = (wifi_pkt.dst_mac[0] == 0xFF) && (wifi_pkt.dst_mac[1] == 0xFF) &&
                            (wifi_pkt.dst_mac[2] == 0xFF) && (wifi_pkt.dst_mac[3] == 0xFF) &&
                            (wifi_pkt.dst_mac[4] == 0xFF) && (wifi_pkt.dst_mac[5] == 0xFF);

    snprintf(wifi_pkt.protocol, sizeof(wifi_pkt.protocol), "Unknown");
    wifi_pkt.src_port = 0;
    wifi_pkt.dst_port = 0;

    wifi_pkt.payload = pkt->payload;
    wifi_pkt.payload_length = pkt->rx_ctrl.sig_len;

    return wifi_pkt;
}

void extract_header_data(wifi_promiscuous_pkt_t *pkt, wifi_promiscuous_pkt_type_t type)
{
    uint8_t *data = pkt->payload;
    wifi_mac_hdr_t *hdr = (wifi_mac_hdr_t *)data;

    ESP_LOGI(TAG, "Packet Type: %s", type == WIFI_PKT_MGMT ? "Management" : type == WIFI_PKT_DATA ? "Data"
                                                                        : type == WIFI_PKT_CTRL   ? "Control"
                                                                                                  : "Unknown");
    ESP_LOGI(TAG, "Packet Length: %d bytes", pkt->rx_ctrl.sig_len);
    ESP_LOGI(TAG, "MAC Destination: %02X:%02X:%02X:%02X:%02X:%02X",
             hdr->addr1[0], hdr->addr1[1], hdr->addr1[2], hdr->addr1[3], hdr->addr1[4], hdr->addr1[5]);
    ESP_LOGI(TAG, "MAC Source: %02X:%02X:%02X:%02X:%02X:%02X",
             hdr->addr2[0], hdr->addr2[1], hdr->addr2[2], hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
    ESP_LOGI(TAG, "MAC BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
             hdr->addr3[0], hdr->addr3[1], hdr->addr3[2], hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]);
}

static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;

    if (pkt->rx_ctrl.sig_len < sizeof(wifi_mac_hdr_t))
    {
        ESP_LOGW(TAG, "Packet too short, ignoring");
        return;
    }


    switch (selected_filter)
    {
    case FILTER_MANAGEMENT_ONLY:
        if (true /*type == WIFI_PKT_MGMT*/)
        {
            wifi_packet_t wifi_pkt = create_wifi_packet(pkt, type);
            if (type == WIFI_PKT_MGMT)
            { 
                // check_for_deauth_attack(&wifi_pkt);  
                // analyze_evil_twin(&wifi_pkt);        
                // detect_beacon_flood(&wifi_pkt);      
                // send_wifi_packet_json(&wifi_pkt);
            }
            else if (type == WIFI_PKT_CTRL)
            {   
                ESP_LOGI(TAG, "Received Control packet");   
            }
            else if (type == WIFI_PKT_DATA) 
            {
                process_wifi_frame(pkt->payload, pkt->rx_ctrl.sig_len, &wifi_pkt);
                // detect_arp_packet(pkt);
            }
            break;
        }
        break;
    case FILTER_MANAGEMENT_AND_CONTROL:
        if (type == WIFI_PKT_MGMT || type == WIFI_PKT_CTRL)
        {
            ESP_LOGI(TAG, "Received Management or Control packet");
            extract_header_data(pkt, type);
        }
        break;
    case FILTER_ALL:
        if (false /*type == WIFI_PKT_MGMT || type == WIFI_PKT_CTRL || type == WIFI_PKT_DATA*/)
        {

            // ESP_LOGI(TAG, "Received Management, Control or Data packet");
        }
        break;
    default:
        return;
    }
}

void wifi_sniffer_init(sniffer_filter_t filter)
{
    ESP_LOGI(TAG, "Sniffer filter: %d", filter);
    selected_filter = filter;
    init_channel_hop_timer();
    // ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_cb));
}

void wifi_sniffer_start(void)
{
    ESP_LOGI(TAG, "Starting Wi-Fi sniffer...");
    ESP_ERROR_CHECK(esp_wifi_start());
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
