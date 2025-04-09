#ifndef ARP_TABLE_H
#define ARP_TABLE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include "lwip/ip_addr.h"

    
    typedef struct
    {
        uint32_t ip;
        uint8_t mac[6];
    } arp_entry_t;

    void arp_table_init(void);
    void process_arp_response(const uint8_t *buffer, uint16_t len);
    void arp_table_stop(void);
    void arp_table_start(void);

#ifdef __cplusplus
}
#endif

#endif
