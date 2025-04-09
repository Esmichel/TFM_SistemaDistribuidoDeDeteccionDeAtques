#include "hash_function.h"

uint32_t hash_ssid(const char *ssid)
{
    uint32_t hash = 5381;
    int c;

    while ((c = *ssid++))
    {
        hash = ((hash << 5) + hash) + c; 
    }

    return hash;
}
