#include "base64encoding.h"
#include "mbedtls/base64.h"
#include "esp_log.h"

static const char *TAG = "BASE64_ENCODING";

void base64_encode(const uint8_t *input, size_t input_len, char *output, size_t output_size) {
    size_t olen = 0;
    int ret = mbedtls_base64_encode((unsigned char *)output, output_size, &olen, input, input_len);
    if(ret != 0) {
        ESP_LOGE(TAG, "Base64 encoding failed, error: %d", ret);
        if(output_size > 0) {
            output[0] = '\0';
        }
    } else {
        if(olen < output_size)
            output[olen] = '\0';
        else
            output[output_size - 1] = '\0';
    }
}
