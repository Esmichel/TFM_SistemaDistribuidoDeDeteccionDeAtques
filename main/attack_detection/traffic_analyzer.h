// attack_detector.h
#ifndef TRAFFIC_ANALYZER_H
#define TRAFFIC_ANALYZER_H

#include "../tools/l7_processor.h"

// UDP header (network byte order)
typedef struct
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

// DNS header (packed)
typedef struct
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) dns_hdr_t;

// Track DNS queries
typedef struct
{
    uint16_t id;        // transaction ID
    uint32_t client_ip; // client IP (net order)
} dns_track_t;

/**
 * Initialize the attack detector module.
 */
void attack_detector_init(void);

/**
 * Inspect a Layer‑7 payload for known malicious AP attack techniques.
 * @param wifi_pkt The associated WiFi packet metadata (MACs, IP header pointer).
 * @param payload Pointer to application payload (e.g. HTTP, DNS).
 * @param length Length of the payload in bytes.
 */
void attack_detector_process(wifi_packet_t *wifi_pkt, const uint8_t *payload, uint16_t length, ip_header_t *ip_hdr);

#endif // ATTACK_DETECTOR_H