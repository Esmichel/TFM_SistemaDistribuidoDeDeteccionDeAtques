#include "mqtt_fragment_buffer.h"
#include <stdlib.h>
#include <string.h>

bool mqtt_fragment_buffer_init(mqtt_fragment_buffer_t *frag_buf, size_t total_len) {
    frag_buf->buffer = calloc(1, total_len + 1);  // +1 for null terminator
    if (!frag_buf->buffer) return false;
    frag_buf->total_len = total_len;
    frag_buf->received_len = 0;
    return true;
}

bool mqtt_fragment_buffer_add(mqtt_fragment_buffer_t *frag_buf, const char *data, size_t data_len, size_t offset) {
    if (!frag_buf->buffer || offset + data_len > frag_buf->total_len) return false;

    memcpy(frag_buf->buffer + offset, data, data_len);
    frag_buf->received_len += data_len;
    return true;
}

bool mqtt_fragment_buffer_is_complete(const mqtt_fragment_buffer_t *frag_buf) {
    return frag_buf->received_len >= frag_buf->total_len;
}

const char* mqtt_fragment_buffer_get(const mqtt_fragment_buffer_t *frag_buf) {
    return frag_buf->buffer;
}

void mqtt_fragment_buffer_reset(mqtt_fragment_buffer_t *frag_buf) {
    if (frag_buf->buffer) {
        memset(frag_buf->buffer, 0, frag_buf->total_len + 1);
    }
    frag_buf->received_len = 0;
}

void mqtt_fragment_buffer_free(mqtt_fragment_buffer_t *frag_buf) {
    free(frag_buf->buffer);
    frag_buf->buffer = NULL;
    frag_buf->total_len = 0;
    frag_buf->received_len = 0;
}
