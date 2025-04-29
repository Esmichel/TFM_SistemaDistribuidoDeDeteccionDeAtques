#include "l7_processor.h"
#include "../attack_detection/traffic_analyzer.h"

// #define IP_PROTOCOL_TCP 6
static const char *TAG = "sniffer_l7";
// #define max_payload_len 1023
// #define min_printable_seq 10
// #define low_entropy_threshold 3.5

typedef struct
{
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} wifi_ieee80211_hdr_t;

// #define WLAN_FC_TYPE(fc)    (((fc) & 0x000C) >> 2)
// #define WLAN_FC_SUBTYPE(fc) (((fc) & 0x00F0) >> 4)
// #define WLAN_FC_TODS(fc)    (((fc) & 0x0100) >> 8)
// #define WLAN_FC_FROMDS(fc)  (((fc) & 0x0200) >> 9)
// #define WIFI_FC_TYPE_MGMT  0
// #define WIFI_FC_TYPE_CTRL  1
// #define WIFI_FC_TYPE_DATA  2

//loaded config values
int max_payload_len = 1023;
int min_printable_seq = 10;
float low_entropy_threshold = 3.5f;
wifi_packet_t *l7_wifi_pkt = NULL;

void process_layer_7_data(const uint8_t *payload, uint16_t length);
void process_tcp_packet(const uint8_t *payload, uint16_t length);
void process_ip_packet(const uint8_t *payload, uint16_t length, wifi_packet_t *wifi_pkt);

bool is_local_ip(uint32_t ip)
{
    ip = ntohl(ip);
    uint8_t *bytes = (uint8_t *)&ip;
    return (bytes[0] == 192 && bytes[1] == 168) ||
           (bytes[0] == 10) ||
           (bytes[0] == 172 && (bytes[1] >= 16 && bytes[1] <= 31));
}

// static void print_hex_payload(const uint8_t *data, uint16_t length)
// {
//     ESP_LOGI(TAG, "Raw Payload (%d bytes):", length);
//     for (int i = 0; i < length; i++)
//     {
//         ESP_LOGI(TAG, "%02x ", data[i]);
//         if ((i + 1) % 16 == 0)
//         {
//             ESP_LOGI(TAG, "");
//         }
//     }
//     ESP_LOGI(TAG, "");
// }

bool is_unicast_mac(const uint8_t *mac)
{
    return (mac[0] & 0x01) == 0;
}

void process_wifi_data_frame(const uint8_t *frame, uint16_t length, wifi_packet_t *wifi_pkt)
{
    l7_wifi_pkt = wifi_pkt;
    if (length < sizeof(wifi_ieee80211_hdr_t))
    {
        ESP_LOGI(TAG, "Frame too short for 802.11 header");
        return;
    }

    const wifi_ieee80211_hdr_t *hdr = (const wifi_ieee80211_hdr_t *)frame;
    uint16_t fc = hdr->frame_control;
    uint8_t type = WLAN_FC_TYPE(fc);
    uint16_t header_len = 24;
    uint8_t tods = WLAN_FC_TODS(fc);
    uint8_t fromds = WLAN_FC_FROMDS(fc);

    if (tods && fromds)
    {
        header_len += 6;
    }

    uint8_t subtype = WLAN_FC_SUBTYPE(fc);
    if (subtype & 0x08)
    {
        header_len += 2;
    }

    if (length < header_len)
    {
        ESP_LOGD(TAG, "Frame length (%d) is less than header length (%d)", length, header_len);
        return;
    }

    const uint8_t *payload = frame + header_len;
    uint16_t payload_len = length - header_len;

    if (payload_len >= 8 && payload[0] == 0xAA && payload[1] == 0xAA && payload[2] == 0x03)
    {
        payload += 8;
        payload_len -= 8;
    }

    if (payload_len < sizeof(ip_header_t))
    {
        // ESP_LOGI(TAG, "Payload is too short to be an IP packet");
        return;
    }

    ip_header_t *ip_hdr = (ip_header_t *)payload;
    wifi_pkt->ip_hdr = ip_hdr;



    if (ip_hdr->protocol != IP_PROTOCOL_TCP) {
        // ESP_LOGI(TAG, "Not a TCP packet");
        return;
    }

    if ((ip_hdr->version_ihl >> 4) != 4)
    {
        // ESP_LOGI(TAG, "Not an IPv4 packet");
        return;
    }

    process_ip_packet(payload, payload_len, wifi_pkt);
}

void process_wifi_frame(const uint8_t *frame, uint16_t length, wifi_packet_t *wifi_pkt)
{
    if (length < 2)
    {
        ESP_LOGI(TAG, "Frame too short to extract frame control");
        return;
    }
    uint16_t fc = *((const uint16_t *)frame);
    uint8_t type = WLAN_FC_TYPE(fc);

    switch (type)
    {
    case WIFI_FC_TYPE_DATA:
        process_wifi_data_frame(frame, length, wifi_pkt);
        break;
    default:
        ESP_LOGI(TAG, "Ignoring non-data frame (type: %d)", type);
        break;
    }
}

static float calc_entropy(const char *str, size_t len)
{
    int freq[256] = {0};
    for (size_t i = 0; i < len; i++)
    {
        freq[(unsigned char)str[i]]++;
    }
    float entropy = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] > 0)
        {
            float p = (float)freq[i] / len;
            entropy -= p * logf(p);
        }
    }
    return entropy;
}

static int contains_sensitive_keyword(const char *str)
{
    const char *keywords[] = {"user", "pass", "login", "cred", "token", NULL};
    for (int i = 0; keywords[i] != NULL; i++)
    {
        if (strcasestr(str, keywords[i]))
        {
            return 1;
        }
    }
    return 0;
}

void process_layer_7_data(const uint8_t *payload, uint16_t length)
{
    char buf[max_payload_len + 1];
    uint16_t copy_len = (length < max_payload_len) ? length : max_payload_len;
    memcpy(buf, payload, copy_len);
    buf[copy_len] = '\0';

    if (strncmp(buf, "GET ", 4) == 0)
    {
        ESP_LOGI(TAG, "HTTP GET Request detected");
    }
    else if (strncmp(buf, "POST ", 5) == 0)
    {
        ESP_LOGI(TAG, "HTTP POST Request detected");
    }
    else if (strncmp(buf, "PUT ", 4) == 0)
    {
        ESP_LOGI(TAG, "HTTP PUT Request detected");
    }
    else if (strncmp(buf, "DELETE ", 7) == 0)
    {
        ESP_LOGI(TAG, "HTTP DELETE Request detected");
    }

    uint16_t start = 0;
    for (uint16_t i = 0; i <= copy_len; i++)
    {
        if (i == copy_len || !isprint((unsigned char)buf[i]))
        {
            uint16_t seq_len = i - start;
            if (seq_len >= min_printable_seq)
            {
                char seq[max_payload_len + 1];
                memcpy(seq, &buf[start], seq_len);
                seq[seq_len] = '\0';
                float entropy = calc_entropy(seq, seq_len);
                if (entropy < low_entropy_threshold || contains_sensitive_keyword(seq))
                {
                    ESP_LOGW(TAG, "Potential sensitive plaintext detected: %s", seq);
                }
            }
            start = i + 1;
        }
    }

    for (uint16_t i = 0; i < copy_len; i++)
    {
        if ((i + 1) < copy_len && buf[i] == '\r' && buf[i + 1] == '\n')
            break;
        putchar(buf[i]);
    }
    putchar('\n');
}

void process_tcp_packet(const uint8_t *payload, uint16_t length)
{
    if (length < sizeof(tcp_header_t))
    {
        // ESP_LOGD(TAG, "TCP packet too small to contain a valid header");
        return;
    }
    tcp_header_t *tcp_hdr = (tcp_header_t *)payload;
    l7_wifi_pkt->ip_hdr->tcp_hdr = tcp_hdr;
    uint16_t tcp_hdr_len = (tcp_hdr->data_offset >> 4) * 4;
    if (length < tcp_hdr_len)
    {
        // ESP_LOGD(TAG, "TCP packet length less than header length");
        return;
    }
    ESP_LOGI(TAG, "TCP Packet: Source Port: %d, Destination Port: %d",
             ntohs(tcp_hdr->src_port), ntohs(tcp_hdr->dst_port));
    const uint8_t *app_data = payload + tcp_hdr_len;
    uint16_t app_data_len = length - tcp_hdr_len;
    process_layer_7_data(app_data, app_data_len);
}

void process_ip_packet(const uint8_t *payload, uint16_t length, wifi_packet_t *wifi_pkt)
{
    if (length < sizeof(ip_header_t))
    {
        // ESP_LOGD(TAG, "IP packet too short for header");
        return;
    }
    ip_header_t *ip_hdr = (ip_header_t *)payload;
    uint8_t ihl = ip_hdr->version_ihl & 0x0F;
    uint16_t ip_hdr_len = ihl * 4;
    if (length < ip_hdr_len)
    {
        // ESP_LOGD(TAG, "IP packet length (%d) is less than header length (%d)", length, ip_hdr_len);
        return;
    }

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    struct in_addr src_addr_in, dst_addr_in;

    src_addr_in.s_addr = ip_hdr->src_addr;
    dst_addr_in.s_addr = ip_hdr->dst_addr;

    if (inet_ntop(AF_INET, &src_addr_in, src_ip, INET_ADDRSTRLEN) == NULL)
    {
        ESP_LOGE(TAG, "Error converting source IP to string");
        strcpy(src_ip, "Invalid IP");
    }
    if (inet_ntop(AF_INET, &dst_addr_in, dst_ip, INET_ADDRSTRLEN) == NULL)
    {
        ESP_LOGE(TAG, "Error converting destination IP to string");
        strcpy(dst_ip, "Invalid IP");
    }

    ESP_LOGI(TAG, "Source MAC: %s Destination MAC: %s  IP Packet: Source IP: %s, Destination IP: %s, Protocol: %d", mac_to_string(wifi_pkt->src_mac), mac_to_string(wifi_pkt->dst_mac), src_ip, dst_ip, ip_hdr->protocol);
    wifi_pkt->ip_hdr = ip_hdr;

    if (is_local_ip(ip_hdr->src_addr) && is_unicast_mac(wifi_pkt->src_mac))
    {
        mac_spoof_detector_process(ip_hdr->src_addr, wifi_pkt->src_mac);
    }

    if (ip_hdr->protocol == IP_PROTOCOL_TCP)
    {
        process_tcp_packet(payload + ip_hdr_len, length - ip_hdr_len);
    }
    attack_detector_process(wifi_pkt, payload + ip_hdr_len, length - ip_hdr_len);
}

void l7_processor_init(void)
{
    ESP_LOGI(TAG, "Initializing Layer 7 Processor...");
    AppConfig *app_config = get_config();
    max_payload_len = app_config->max_payload_len;
    min_printable_seq = app_config->min_printable_seq;
    low_entropy_threshold = app_config->low_entropy_threshold;
    ESP_LOGI(TAG, "Max Payload Length: %d", max_payload_len);
    ESP_LOGI(TAG, "Min Printable Sequence: %d", min_printable_seq);
    ESP_LOGI(TAG, "Low Entropy Threshold: %.2f", low_entropy_threshold);

}
