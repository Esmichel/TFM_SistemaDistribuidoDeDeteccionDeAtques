#include "estandard_deviation.h"

// loaded config values
// int MAX_VARIABLES = 0;
// int MAX_SAMPLES = 0;

static std_dev_data_t std_dev_variables[MAX_VARIABLES];
static int num_variables = 0;

std_dev_data_t *get_std_dev_variable(const char *variable_name)
{
    for (int i = 0; i < num_variables; i++)
    {
        if (strcmp(std_dev_variables[i].variable_name, variable_name) == 0)
        {
            return &std_dev_variables[i];
        }
    }

    if (num_variables < MAX_VARIABLES)
    {
        strncpy(std_dev_variables[num_variables].variable_name, variable_name, 20);
        std_dev_variables[num_variables].count = 0;
        std_dev_variables[num_variables].sum = 0.0;
        return &std_dev_variables[num_variables++];
    }

    return NULL;
}
double update_std_dev(const char *variable_name, double new_sample)
{
    std_dev_data_t *data = get_std_dev_variable(variable_name);
    if (!data)
        return -1.0;

    if (data->count < MAX_SAMPLES)
    {
        data->values[data->count++] = new_sample;
        data->sum += new_sample;
    }
    else
    {
        data->sum -= data->values[0];
        for (int i = 1; i < MAX_SAMPLES; i++)
        {
            data->values[i - 1] = data->values[i];
        }
        data->values[MAX_SAMPLES - 1] = new_sample;
        data->sum += new_sample;
    }

    double mean = data->sum / data->count;

    double variance = 0.0;
    for (int i = 0; i < data->count; i++)
    {
        variance += pow(data->values[i] - mean, 2);
    }
    variance /= data->count;

    return sqrt(variance);
}

double get_std_dev_mean(const std_dev_data_t *data)
{
    if (data->count == 0)
    {
        return 0.0;
    }

    return data->sum / data->count;
}

void init_std_dev(std_dev_data_t *data)
{
    memset(data, 0, sizeof(std_dev_data_t));
    data->count = 0;
    data->sum = 0.0;
    memset(data->values, 0, sizeof(data->values));
}
