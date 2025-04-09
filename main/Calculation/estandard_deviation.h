#ifndef ESTANDARD_DEVIATION_H
#define ESTANDARD_DEVIATION_H

#define MAX_SAMPLES 50
#define MAX_VARIABLES 10  // Número máximo de variables diferentes que podemos analizar

typedef struct {
    char variable_name[20];  // Nombre de la variable analizada (ej: "src_mac", "packet_size", "flags")
    double values[MAX_SAMPLES];  
    int count;               // Contador de elementos procesados
    double sum;              // Suma de los valores de la desviación estándar
} std_dev_data_t;


std_dev_data_t* get_std_dev_variable(const char *variable_name);
double update_std_dev(const char *variable_name, double new_sample);
double get_std_dev_mean(const std_dev_data_t *data);
void init_std_dev(std_dev_data_t *data);

#endif