#include "frequency_analysis.h"
#include <string.h>

static bool mac_equal(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

// Busca o crea. Si crea, inicializa el entry (incluye alerted=false).
static frequency_entry_t *find_or_create_entry(frequency_tracker_t *t,
                                               const uint8_t mac[6])
{
    // Buscamos
    for (uint32_t i = 0; i < t->num_entries; ++i)
    {
        if (mac_equal(t->entries[i].mac, mac))
            return &t->entries[i];
    }
    // Creamos
    if (t->num_entries >= MAX_TRACKED_SOURCES)
    {
        return NULL;
    }
    frequency_entry_t *e = &t->entries[t->num_entries++];
    memset(e, 0, sizeof(*e));
    memcpy(e->mac, mac, 6);
    e->alerted = false;
    return e;
}

// Elimina la entry i (moviendo la última a su lugar).
static void remove_entry(frequency_tracker_t *t, uint32_t idx)
{
    if (idx + 1 < t->num_entries)
    {
        t->entries[idx] = t->entries[t->num_entries - 1];
    }
    --t->num_entries;
}

void init_frequency_tracker(frequency_tracker_t *t,
                            uint32_t time_window_ms,
                            uint32_t attack_threshold)
{
    memset(t, 0, sizeof(*t));
    t->time_window = time_window_ms;
    t->attack_threshold = attack_threshold;
}

void reconfigure_frequency_tracker(frequency_tracker_t *t,
                                   uint32_t time_window_ms,
                                   uint32_t attack_threshold)
{
    t->time_window = time_window_ms;
    t->attack_threshold = attack_threshold;
}

uint32_t get_tracker_count(const frequency_tracker_t *t, const uint8_t key[6])
{
    for (uint32_t i = 0; i < t->num_entries; ++i)
    {
        if (memcmp(t->entries[i].mac, key, 6) == 0)
        {
            return t->entries[i].count;
        }
    }
    return 0;
}

void update_frequency(frequency_tracker_t *t,
                      const uint8_t source_mac[6],
                      uint32_t now)
{
    frequency_entry_t *e = find_or_create_entry(t, source_mac);
    if (!e)
        return;

    if (e->count < MAX_EVENTS_PER_SOURCE)
        e->timestamps[e->count++] = now;

    uint32_t j = 0;
    for (uint32_t i = 0; i < e->count; ++i)
    {
        if (now - e->timestamps[i] <= t->time_window)
        {
            e->timestamps[j++] = e->timestamps[i];
        }
    }
    e->count = j;

    uint8_t global_key[6] = GLOBAL_KEY;
    if (memcmp(e->mac, global_key, 6) != 0 && e->count == 0)
    {
        uint32_t idx = e - &t->entries[0];
        remove_entry(t, idx);
    }
}

bool detect_high_frequency(frequency_tracker_t *t,
                           const uint8_t source_mac[6],
                           uint32_t now)
{
    update_frequency(t, source_mac, now);
    frequency_entry_t *e = find_or_create_entry(t, source_mac);
    if (!e)
        return false;
    return (e->count >= t->attack_threshold);
}

bool detect_high_frequency_once(frequency_tracker_t *t,
                                const uint8_t source_mac[6],
                                uint32_t now)
{
    update_frequency(t, source_mac, now);
    frequency_entry_t *e = find_or_create_entry(t, source_mac);
    if (!e)
        return false;

    if (e->count >= t->attack_threshold)
    {
        if (!e->alerted)
        {
            e->alerted = true;
            return true;
        }
        return false;
    }
    else
    {
        e->alerted = false;
        return false;
    }
}
