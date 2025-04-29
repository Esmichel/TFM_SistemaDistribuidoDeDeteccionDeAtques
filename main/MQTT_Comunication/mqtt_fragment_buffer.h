#pragma once

#include <stddef.h>
#include <stdbool.h>

typedef struct {
    char *buffer;
    size_t total_len;
    size_t received_len;
} mqtt_fragment_buffer_t;

bool mqtt_fragment_buffer_init(mqtt_fragment_buffer_t *frag_buf, size_t total_len);
bool mqtt_fragment_buffer_add(mqtt_fragment_buffer_t *frag_buf, const char *data, size_t data_len, size_t offset);
bool mqtt_fragment_buffer_is_complete(const mqtt_fragment_buffer_t *frag_buf);
const char* mqtt_fragment_buffer_get(const mqtt_fragment_buffer_t *frag_buf);
void mqtt_fragment_buffer_reset(mqtt_fragment_buffer_t *frag_buf);
void mqtt_fragment_buffer_free(mqtt_fragment_buffer_t *frag_buf);
