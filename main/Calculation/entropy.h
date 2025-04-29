#ifndef ENTROPY_H
#define ENTROPY_H

#include <math.h>
#include <stdint.h>
#include <string.h>
#include "../tools/centralized_config.h"

// #define MAX_BINS 10  
// #define MAX_VARIABLES 10  

typedef struct {
    char variable_name[20];
    int count[MAX_BINS];
    int total;
} entropy_data_t;

entropy_data_t* get_entropy_variable(const char *variable_name);
double update_entropy(const char *variable_name, int new_value);
void init_entropy(entropy_data_t *data);

#endif