#ifndef SNIFFER_MODULE_H
#define SNIFFER_MODULE_H

#include <stdint.h>
#include <stdbool.h>
typedef enum {
    FILTER_MANAGEMENT_ONLY,
    FILTER_MANAGEMENT_AND_CONTROL,
    FILTER_ALL
} sniffer_filter_t;

typedef struct {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];  
    uint8_t addr2[6];  
    uint8_t addr3[6];  
    uint16_t seq_ctrl;
} wifi_mac_hdr_t;

typedef struct {
    uint16_t src_port;   
    uint16_t dst_port;   
    uint32_t seq_num;    
    uint32_t ack_num;    
    uint8_t data_offset; 
    uint8_t flags;       
    uint16_t window_size;
    uint16_t checksum;  
    uint16_t urgent_ptr;
} tcp_header_t;
 
typedef struct {
    uint8_t version_ihl;     
    uint8_t type_of_service; 
    uint16_t total_length;  
    uint16_t identification;
    uint16_t flags_offset;
    uint8_t ttl;          
    uint8_t protocol;     
    uint16_t checksum;    
    uint32_t src_addr;    
    uint32_t dst_addr;    
    tcp_header_t *tcp_hdr;
} ip_header_t;

typedef struct {
    uint8_t type; 
    uint8_t subtype; 
    uint8_t src_mac[6];     
    uint8_t dst_mac[6];     
    uint32_t timestamp;     
    uint8_t *payload;       
    uint16_t payload_length;
    int8_t signal_strength;
    uint8_t ssid_length;
    uint8_t ssid[32];
    char packet_id[32]; 
    uint16_t src_port; 
    uint16_t dst_port;   
    bool is_broadcast;  
    uint8_t channel;
    char protocol[16];
    ip_header_t *ip_hdr;   
} wifi_packet_t;

void wifi_sniffer_init(sniffer_filter_t filter);
void wifi_sniffer_start(void);
void wifi_sniffer_stop(void);
void sniffer_update_config();

#endif
