#ifndef BASE64ENCODING_H
#define BASE64ENCODING_H

#include <stdint.h>
#include <stdlib.h>

void base64_encode(const uint8_t *input, size_t input_len, char *output, size_t output_size);

#endif
