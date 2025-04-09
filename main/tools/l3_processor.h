#ifndef L3_PROCESSOR_H
#define L3_PROCESSOR_H

#include <stdint.h>
#include <stdlib.h>

void process_l3_packet(const uint8_t *payload, uint16_t length);

#endif
