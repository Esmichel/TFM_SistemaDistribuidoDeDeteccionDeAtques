// attack_detector.h
#ifndef TRAFFIC_ANALYZER_H
#define TRAFFIC_ANALYZER_H

#include "../tools/l7_processor.h"

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
void attack_detector_process(wifi_packet_t *wifi_pkt, const uint8_t *payload, uint16_t length);

#endif // ATTACK_DETECTOR_H