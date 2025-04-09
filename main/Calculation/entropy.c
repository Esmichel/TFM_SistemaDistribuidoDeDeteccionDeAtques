#include <math.h>
#include <stdint.h>
#include <string.h>
#include "entropy.h"

static entropy_data_t entropy_variables[MAX_VARIABLES];
static int num_entropy_vars = 0;

// Busca o crea una estructura de datos para la variable analizada
entropy_data_t *get_entropy_variable(const char *variable_name)
{
    for (int i = 0; i < num_entropy_vars; i++)
    {
        if (strcmp(entropy_variables[i].variable_name, variable_name) == 0)
        {
            return &entropy_variables[i];
        }
    }

    if (num_entropy_vars < MAX_VARIABLES)
    {
        strncpy(entropy_variables[num_entropy_vars].variable_name, variable_name, 20);
        entropy_variables[num_entropy_vars].total = 0;
        memset(entropy_variables[num_entropy_vars].count, 0, sizeof(entropy_variables[num_entropy_vars].count));
        return &entropy_variables[num_entropy_vars++];
    }

    return NULL;
}

// Agregar nuevo valor y calcular la entropía
double update_entropy(const char *variable_name, int new_value)
{
    entropy_data_t *data = get_entropy_variable(variable_name);
    if (!data)
        return -1.0;

    if (new_value >= 0 && new_value < MAX_BINS)
    {
        data->count[new_value]++;
        data->total++;
    }

    double entropy = 0.0;
    for (int i = 0; i < MAX_BINS; i++)
    {
        if (data->count[i] > 0)
        {
            double p = (double)data->count[i] / data->total;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

void init_entropy(entropy_data_t *data)
{
    memset(data, 0, sizeof(entropy_data_t)); // Inicializamos la estructura a cero
    data->total = 0;
    memset(data->count, 0, sizeof(data->count));
}
