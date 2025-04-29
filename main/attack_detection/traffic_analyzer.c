#include "traffic_analyzer.h"
#include <string.h>
#include <arpa/inet.h>
#include "esp_log.h"

#define TAG "attack_detector"
#define MAX_TRACKED_DNS 64
#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

// UDP header (network byte order)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

// DNS header (packed)
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) dns_hdr_t;

// Track DNS queries
typedef struct {
    uint16_t id;           // transaction ID
    uint32_t client_ip;    // client IP (net order)
} dns_track_t;
static dns_track_t dns_table[MAX_TRACKED_DNS];
static int dns_count = 0;

// Helpers
static bool is_local_ip(uint32_t addr_net)
{
    uint32_t addr = ntohl(addr_net);
    uint8_t b0 = (addr >> 24) & 0xFF;
    uint8_t b1 = (addr >> 16) & 0xFF;
    if (b0 == 10) return true;
    if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return true;
    if (b0 == 192 && b1 == 168) return true;
    return false;
}

// --- DNS Hijacking Detection ---
static void detect_dns_hijack(const dns_hdr_t *hdr, const uint8_t *data, uint16_t len, wifi_packet_t *wifi_pkt)
{
    bool is_response = (hdr->flags & htons(0x8000)) != 0;
    if (!is_response && ntohs(hdr->qdcount) > 0) {
        if (dns_count < MAX_TRACKED_DNS) {
            dns_table[dns_count].id = hdr->id;
            dns_table[dns_count].client_ip = wifi_pkt->ip_hdr->src_addr;
            dns_count++;
        }
    } else if (is_response && ntohs(hdr->ancount) > 0) {
        for (int i = 0; i < dns_count; i++) {
            if (dns_table[i].id == hdr->id && dns_table[i].client_ip == wifi_pkt->ip_hdr->dst_addr) {
                if (!is_local_ip(wifi_pkt->ip_hdr->src_addr)) {
                    ESP_LOGW(TAG, "DNS spoofing: ID=0x%04x from %s",
                             ntohs(hdr->id), mac_to_string(wifi_pkt->src_mac));
                    build_attack_alert_payload(wifi_pkt, "DNS spoofing detected");
                }
                dns_table[i] = dns_table[--dns_count];
                break;
            }
        }
    }
}

// SSL-strip detection
static void detect_ssl_strip(wifi_packet_t *wifi_pkt, tcp_header_t *tcp, uint16_t tcp_len, const uint8_t *app, uint16_t app_len)
{
    if (ntohs(tcp->dst_port) == 443 && app_len > 4 && strncmp((char*)app, "GET ", 4) == 0) {
        ESP_LOGW(TAG, "SSL stripping: HTTP over port 443");
        build_attack_alert_payload(wifi_pkt, "SSL stripping detected");
    }
}

// HTTP injection
static void detect_http_injection(wifi_packet_t *wifi_pkt, const uint8_t *data, uint16_t len)
{
    if (len > 7 && (memmem(data, len, "<script", 7) || memmem(data, len, "document.write", 14))) {
        ESP_LOGW(TAG, "HTTP injection: script tags present");
        build_attack_alert_payload(wifi_pkt, "HTTP injection detected");
    }
}

// Captive portal
static void detect_captive_portal(wifi_packet_t *wifi_pkt, const uint8_t *data, uint16_t len)
{
    const char *buf = (const char*)data;
    if (strstr(buf, "302 Found") && strstr(buf, "Location: http://")) {
        ESP_LOGW(TAG, "Captive portal redirect detected");
        build_attack_alert_payload(wifi_pkt, "Captive portal redirect detected");
    }
}

// Public API
void attack_detector_init(void)
{
    dns_count = 0;
    ESP_LOGI(TAG, "Attack Detector initialized");
}

void attack_detector_process(wifi_packet_t *wifi_pkt, const uint8_t *payload, uint16_t length)
{
    if (!wifi_pkt || !payload || length < 1 || !wifi_pkt->ip_hdr) return;

    uint8_t proto = wifi_pkt->ip_hdr->protocol;
    uint16_t ihl = (wifi_pkt->ip_hdr->version_ihl & 0x0F) * 4;
    if (length <= ihl) return;

    if (proto == IP_PROTOCOL_TCP) {
        const uint8_t *tcp_start = payload + ihl;
        uint16_t tcp_len = length - ihl;
        if (tcp_len < sizeof(tcp_header_t)) return;
        tcp_header_t *tcp = (tcp_header_t*)tcp_start;
        uint16_t hdr_len = (tcp->data_offset >> 4) * 4;
        if (tcp_len <= hdr_len) return;
        const uint8_t *app = tcp_start + hdr_len;
        uint16_t app_len = tcp_len - hdr_len;

        detect_ssl_strip(wifi_pkt, tcp, tcp_len, app, app_len);

        if (ntohs(tcp->dst_port) == 80 || ntohs(tcp->src_port) == 80) {
            detect_http_injection(wifi_pkt, app, app_len);
            detect_captive_portal(wifi_pkt, app, app_len);
        }
    }
    else if (proto == IP_PROTOCOL_UDP) {
        const uint8_t *udp_start = payload + ihl;
        uint16_t udp_len = length - ihl;
        if (udp_len < sizeof(udp_header_t)) return;
        udp_header_t *udp = (udp_header_t*)udp_start;
        uint16_t src = ntohs(udp->src_port), dst = ntohs(udp->dst_port);
        if (src == 53 || dst == 53) {
            const uint8_t *dns_data = udp_start + sizeof(udp_header_t);
            uint16_t dns_len = udp_len - sizeof(udp_header_t);
            if (dns_len >= sizeof(dns_hdr_t)) {
                detect_dns_hijack((dns_hdr_t*)dns_data, dns_data + sizeof(dns_hdr_t), dns_len - sizeof(dns_hdr_t), wifi_pkt);
            }
        }
    }
}


