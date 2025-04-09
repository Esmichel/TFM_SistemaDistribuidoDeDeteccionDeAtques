#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "l3_processor.h"
#include "esp_system.h"
#include "esp_mac.h"

#define ETH_TYPE_IP 0x0800 
static const char *TAG = "sniffer_l3";

typedef struct {
    uint8_t  version_ihl;     
    uint8_t  tos;             
    uint16_t total_length;    
    uint16_t identification;  
    uint16_t flags_offset;    
    uint8_t  ttl;             
    uint8_t  protocol;        
    uint16_t checksum;        
    uint32_t src_addr;        
    uint32_t dst_addr;        
} ip_header_t;


void process_l3_packet(const uint8_t *payload, uint16_t length) {
    if (length < 24 + 8) {
        ESP_LOGW(TAG, "Paquete demasiado corto para contener encabezados necesarios");
        return;
    }

    int offset = 24;

    uint16_t frame_control = (payload[1] << 8) | payload[0];
    if ((frame_control & 0x0080) == 0x0080) {
        offset += 2;
    }

    if (payload[offset] != 0xAA || payload[offset + 1] != 0xAA || payload[offset + 2] != 0x03) {
        ESP_LOGW(TAG, "Encabezado SNAP no encontrado");
        return;
    }

    uint16_t eth_type = ntohs(*(uint16_t *)(payload + offset + 6));
    if (eth_type != ETH_TYPE_IP) {
        ESP_LOGI(TAG, "Paquete no es IPv4, EtherType: 0x%04X", eth_type);
        return;
    }

    const uint8_t *ip_header_start = payload + offset + 8;
    if (length < (ip_header_start - payload) + sizeof(ip_header_t)) {
        ESP_LOGW(TAG, "Paquete demasiado corto para contener encabezado IP completo");
        return;
    }
    ip_header_t *ip_hdr = (ip_header_t *)ip_header_start;

    char src_ip[16], dst_ip[16];
    inet_ntop(AF_INET, &ip_hdr->src_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip_hdr->dst_addr, dst_ip, sizeof(dst_ip));

    ESP_LOGI(TAG, "Paquete IPv4 detectado: %s -> %s, Protocolo: %d",
             src_ip, dst_ip, ip_hdr->protocol);

}
