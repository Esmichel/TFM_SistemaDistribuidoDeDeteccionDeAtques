#include "evil_twin.h"
#include "tools/centralized_config.h"
#include "../../components/mqtt_communication/network_status.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static const char *TAG = "evil_twin_detection";
static ap_history_t *ap_history = NULL;
static esp_timer_handle_t ap_history_print_timer = NULL;
static esp_timer_handle_t remove_stale_aps_timer = NULL;

// loaded config values
int ap_history_timeout_ms = 0;
int ap_print_timeout_ms = 0;
int flagging_start_delay_ms = 0;
int evil_twin_signal_threshold = 0;
int alert_suppression_timeout_ms = 0;
bool enable_dedicated_mode = 0;
bool mesh_ie_check_enabled = false;

static uint32_t boot_time_ms = 0;
static bool suppress_ap_history_prune = false;
static const wifi_packet_t *last_pkt = NULL;

// Check whitelist delay
static bool is_flagging_enabled(void)
{
    uint32_t now = esp_timer_get_time() / 1000;
    return (now - boot_time_ms) >= (uint32_t)flagging_start_delay_ms;
}

void suppress_history_cleanup(bool enable)
{
    suppress_ap_history_prune = enable;
}

void remove_stale_aps(void *arg)
{
    if (!ap_history || suppress_ap_history_prune)
        return;
    uint32_t now = esp_timer_get_time() / 1000;
    int w = 0;
    for (int i = 0; i < ap_history->current_index; ++i)
    {
        if (now - ap_history->aps[i].timestamp < (uint32_t)ap_history_timeout_ms)
        {
            ap_history->aps[w++] = ap_history->aps[i];
        }
    }
    ap_history->current_index = w;
}

static detected_ap_t *find_ssid_match(const ap_history_t *history, const char *ssid)
{
    for (int i = 0; i < history->current_index; ++i)
    {
        if (strcmp(history->aps[i].ssid, ssid) == 0)
            return &history->aps[i];
    }
    return NULL;
}

void print_ap_history(void *arg)
{
    ESP_LOGI(TAG, "AP History (%d entries):", ap_history ? ap_history->current_index : 0);
    if (!ap_history)
        return;
    for (int i = 0; i < ap_history->current_index; ++i)
    {
        detected_ap_t *e = &ap_history->aps[i];
        ESP_LOGW(TAG,
                 "[%d] SSID=\"%s\" MAC=%02X:%02X:%02X:%02X:%02X:%02X avgRSSI=%d t=%u last_alert=%u mesh_id_len=%u",
                 i, e->ssid,
                 e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5],
                 e->signal_strength, e->timestamp,
                 e->last_alert_ts, e->mesh_id_len);
    }
}

void cleanup_evil_twin()
{
    if (ap_history)
    {
        free(ap_history);
        ap_history = NULL;
    }
    if (ap_history_print_timer)
    {
        esp_timer_stop(ap_history_print_timer);
        esp_timer_delete(ap_history_print_timer);
        ap_history_print_timer = NULL;
    }
    if (remove_stale_aps_timer)
    {
        esp_timer_stop(remove_stale_aps_timer);
        esp_timer_delete(remove_stale_aps_timer);
        remove_stale_aps_timer = NULL;
    }
}

void initialize_evil_twin()
{
    const AppConfig *config = get_config();
    ap_history_timeout_ms = config->ap_history_timeout_ms;
    enable_dedicated_mode = config->enable_dedicated_mode;
    ap_print_timeout_ms = config->ap_print_timeout_ms;
    flagging_start_delay_ms = config->flagging_start_delay_ms;
    evil_twin_signal_threshold = config->evil_twin_signal_threshold;
    alert_suppression_timeout_ms = DEDICATED_MODE_TIMEOUT * 3; // config->alert_suppression_timeout_ms;
    mesh_ie_check_enabled = true;                              // config->mesh_ie_check_enabled;
    boot_time_ms = esp_timer_get_time() / 1000;

    cleanup_evil_twin();

    ap_history = calloc(1, sizeof(*ap_history));
    if (!ap_history)
    {
        ESP_LOGE(TAG, "Failed to alloc AP history");
        return;
    }

    ESP_LOGI(TAG,
             "Evil Twin init: history=%dms, print=%dms, delay=%dms, rssi_thresh=%d, suppress_alert=%dms, mesh_check=%d",
             ap_history_timeout_ms,
             ap_print_timeout_ms,
             flagging_start_delay_ms,
             evil_twin_signal_threshold,
             alert_suppression_timeout_ms,
             mesh_ie_check_enabled);

    // esp_timer_create_args_t print_args = {.callback = print_ap_history, .arg = NULL, .name = "print_ap_history"};
    // ESP_ERROR_CHECK(esp_timer_create(&print_args, &ap_history_print_timer));
    // ESP_ERROR_CHECK(esp_timer_start_periodic(ap_history_print_timer, ap_print_timeout_ms));

    esp_timer_create_args_t stale_args = {.callback = remove_stale_aps, .arg = NULL, .name = "remove_stale_aps"};
    ESP_ERROR_CHECK(esp_timer_create(&stale_args, &remove_stale_aps_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(remove_stale_aps_timer, ap_history_timeout_ms));
}

static void store_mesh_id(detected_ap_t *e, const wifi_packet_t *pkt)
{
    e->mesh_id_len = 0;
    if (!pkt->ie || pkt->ie_len < 2)
        return;
    int idx = 0;
    while (idx + 2 <= pkt->ie_len)
    {
        uint8_t tag = pkt->ie[idx];
        uint8_t len = pkt->ie[idx + 1];
        if (idx + 2 + len > pkt->ie_len)
            break;
        if (tag == MESH_ID_IE_NUMBER)
        {
            int copy_len = len < MAX_MESH_ID_LEN ? len : MAX_MESH_ID_LEN;
            memcpy(e->mesh_id, &pkt->ie[idx + 2], copy_len);
            e->mesh_id_len = copy_len;
            break;
        }
        idx += 2 + len;
    }
}

bool add_ap_to_history_helper(ap_history_t *history,
                              const uint8_t *mac,
                              const char *ssid,
                              int8_t signal_strength,
                              uint32_t timestamp,
                              const wifi_packet_t *pkt)
{
    for (int i = 0; i < history->current_index; i++)
    {
        detected_ap_t *e = &history->aps[i];
        if (memcmp(e->mac, mac, 6) == 0 && strcmp(e->ssid, ssid) == 0)
        {
            e->signal_strength = (e->signal_strength + signal_strength) / 2;
            e->timestamp = timestamp;
            store_mesh_id(e, pkt);
            return false;
        }
    }
    return true;
}

void add_ap_to_history(ap_history_t *history,
                       const uint8_t *mac,
                       const char *ssid,
                       int8_t signal_strength,
                       uint32_t timestamp,
                       const wifi_packet_t *pkt)
{
    if (history->current_index >= MAX_APS)
        return;
    if (add_ap_to_history_helper(history, mac, ssid, signal_strength, timestamp, pkt))
    {
        detected_ap_t *e = &history->aps[history->current_index++];
        memcpy(e->mac, mac, 6);
        strncpy(e->ssid, ssid, sizeof(e->ssid) - 1);
        e->signal_strength = signal_strength;
        e->timestamp = timestamp;
        e->last_alert_ts = 0;
        store_mesh_id(e, pkt);
    }
}

// static void send_alert(const wifi_packet_t *pkt, const char *fmt, ...)
// {
//     char buf[128];
//     va_list ap;
//     va_start(ap, fmt);
//     vsnprintf(buf, sizeof(buf), fmt, ap);
//     va_end(ap);
//     ESP_LOGW(TAG, "%s", buf);
//     build_attack_alert_payload((wifi_packet_t *)pkt, buf);
// }

static bool can_send_alert(detected_ap_t *e, uint32_t now)
{
    return (now - e->last_alert_ts) >= (uint32_t)alert_suppression_timeout_ms;
}

// Helper: extrae únicamente el Mesh ID IE (tag 114) de pkt->ie
static void extract_mesh_id(const wifi_packet_t *pkt,
                            uint8_t *out_buf,
                            uint8_t *out_len)
{
    *out_len = 0;
    if (!pkt->ie || pkt->ie_len < 2)
        return;

    int idx = 0;
    while (idx + 2 <= pkt->ie_len)
    {
        uint8_t tag = pkt->ie[idx];
        uint8_t len = pkt->ie[idx + 1];
        if (idx + 2 + len > pkt->ie_len)
            break;
        if (tag == MESH_ID_IE_NUMBER)
        {
            *out_len = (len < MAX_MESH_ID_LEN ? len : MAX_MESH_ID_LEN);
            memcpy(out_buf, &pkt->ie[idx + 2], *out_len);
            return;
        }
        idx += 2 + len;
    }
}

bool check_for_evil_twin_signal_based(ap_history_t *history,
                                      const char *ssid,
                                      const uint8_t *mac,
                                      int8_t signal_strength)
{
    uint32_t now = esp_timer_get_time() / 1000;

    // Extraemos el Mesh ID del paquete actual
    uint8_t pkt_mesh_id[MAX_MESH_ID_LEN];
    uint8_t pkt_mesh_id_len;
    extract_mesh_id(last_pkt, pkt_mesh_id, &pkt_mesh_id_len);

    for (int i = 0; i < history->current_index; i++)
    {
        detected_ap_t *e = &history->aps[i];
        // Mismo SSID y misma MAC → posible salto de RSSI
        if (strcmp(e->ssid, ssid) == 0 && memcmp(e->mac, mac, 6) == 0)
        {
            int delta = abs(e->signal_strength - signal_strength);
            if (delta < evil_twin_signal_threshold)
            {
                // Si tenemos Mesh ID, comparamos solo ese campo
                if (mesh_ie_check_enabled && e->mesh_id_len > 0 && pkt_mesh_id_len > 0)
                {
                    ESP_LOGD(TAG, "=== RSSI-based Mesh ID comparison ===");
                    ESP_LOGD(TAG, "Historic mesh_id (%u bytes):", e->mesh_id_len);
                    ESP_LOG_BUFFER_HEXDUMP(TAG, e->mesh_id, e->mesh_id_len, ESP_LOG_DEBUG);
                    ESP_LOGD(TAG, "Packet  mesh_id (%u bytes):", pkt_mesh_id_len);
                    ESP_LOG_BUFFER_HEXDUMP(TAG, pkt_mesh_id, pkt_mesh_id_len, ESP_LOG_DEBUG);
                    if (e->mesh_id_len == pkt_mesh_id_len && memcmp(e->mesh_id, pkt_mesh_id, e->mesh_id_len) == 0)
                    {
                        ESP_LOGI(TAG, "Mesh ID match on RSSI check → skipping alert");
                        return false;
                    }
                }
                // Si no hay match de Mesh ID o no está habilitado, alertamos
                if (can_send_alert(e, now))
                {
                    send_alert(last_pkt,
                               "Evil Twin (RSSI jump): SSID \"%s\" ΔRSSI=%d dB",
                               ssid, delta);
                }
                return true;
            }
        }
    }
    return false;
}

bool check_for_evil_twin_in_history(ap_history_t *history,
                                    const char *ssid,
                                    const uint8_t *mac,
                                    int8_t signal_strength)
{
    if (whitelist_contains_mac((const char *)mac, ssid))
    {
        ESP_LOGI(TAG, "SSID \"%s\" MAC %02X:%02X:%02X:%02X:%02X:%02X está en la whitelist → ignorando",
                 ssid, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return false;
    }
    uint32_t now = esp_timer_get_time() / 1000;

    // Extraemos el Mesh ID del paquete actual
    uint8_t pkt_mesh_id[MAX_MESH_ID_LEN];
    uint8_t pkt_mesh_id_len;
    extract_mesh_id(last_pkt, pkt_mesh_id, &pkt_mesh_id_len);

    for (int i = 0; i < history->current_index; i++)
    {
        detected_ap_t *e = &history->aps[i];
        // Mismo SSID pero distinta MAC → posible evil twin
        if (strcmp(e->ssid, ssid) == 0 && memcmp(e->mac, mac, 6) != 0)
        {
            // ¿ap histórico demasiado viejo?
            if (e->timestamp < (boot_time_ms + flagging_start_delay_ms))
                continue;
            // Mesh ID check: si coincide, es mismo mesh node, no twin
            if (mesh_ie_check_enabled && e->mesh_id_len > 0 && pkt_mesh_id_len > 0)
            {
                ESP_LOGD(TAG, "=== SSID+MAC-based Mesh ID comparison ===");
                ESP_LOGD(TAG, "Historic mesh_id (%u bytes):", e->mesh_id_len);
                ESP_LOG_BUFFER_HEXDUMP(TAG, e->mesh_id, e->mesh_id_len, ESP_LOG_DEBUG);
                ESP_LOGD(TAG, "Packet  mesh_id (%u bytes):", pkt_mesh_id_len);
                ESP_LOG_BUFFER_HEXDUMP(TAG, pkt_mesh_id, pkt_mesh_id_len, ESP_LOG_DEBUG);
                if (e->mesh_id_len == pkt_mesh_id_len && memcmp(e->mesh_id, pkt_mesh_id, e->mesh_id_len) == 0)
                {
                    ESP_LOGI(TAG, "Mesh ID match on SSID+MAC check → ignoring node");
                    return false;
                }
            }
            // No coincide Mesh ID → alertamos
            if (can_send_alert(e, now))
            {
                send_alert(last_pkt,
                           "Evil Twin detected: SSID \"%s\" new MAC %02X:%02X:%02X:%02X:%02X:%02X replacing %02X:%02X:%02X:%02X:%02X:%02X",
                           ssid,
                           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                           e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5]);
            }
            return true;
        }
    }
    return false;
}

void analyze_evil_twin(const wifi_packet_t *wifi_pkt)
{
    last_pkt = wifi_pkt;
    const char *ssid = (const char *)wifi_pkt->ssid;
    if (wifi_pkt->type != WIFI_PKT_MGMT || !(wifi_pkt->subtype == 0x08 || wifi_pkt->subtype == 0x05) ||
        strcmp(ssid, "<Hidden>") == 0 || strcmp(ssid, "<No SSID>") == 0 ||
        current_wifi_state == STATE_DEDICATED_LISTENING)
        return;

    bool detected = false;
    if (is_flagging_enabled())
    {
        detected = check_for_evil_twin_signal_based(
            ap_history, ssid, wifi_pkt->src_mac, wifi_pkt->signal_strength);
        if (!detected)
        {
            detected = check_for_evil_twin_in_history(
                ap_history, ssid, wifi_pkt->src_mac, wifi_pkt->signal_strength);
        }
    }

    uint32_t now = esp_timer_get_time() / 1000;
    if (!detected)
    {
        add_ap_to_history(ap_history,
                          wifi_pkt->src_mac,
                          ssid,
                          wifi_pkt->signal_strength,
                          now,
                          wifi_pkt);
    }
    else
    {
        // Only initiate dedicated listening if alert was actually sent
        // Find the history entry for this AP
        detected_ap_t *e = find_ssid_match(ap_history, ssid);
        if (e)
        {
            if (can_send_alert(e, now) && enable_dedicated_mode)
            {
                e->last_alert_ts = now;
                ESP_LOGI(TAG, "Starting dedicated listening mode for SSID \"%s\" MAC %02X:%02X:%02X:%02X:%02X:%02X",
                         ssid,
                         wifi_pkt->src_mac[0], wifi_pkt->src_mac[1], wifi_pkt->src_mac[2],
                         wifi_pkt->src_mac[3], wifi_pkt->src_mac[4], wifi_pkt->src_mac[5]);
                start_dedicated_listening_mode(wifi_pkt);
            }
            else
            {
                ESP_LOGD(TAG, "Dedicated listening suppressed by cooldown for SSID \"%s\" MAC %02X:%02X:%02X:%02X:%02X:%02X",
                         ssid,
                         wifi_pkt->src_mac[0], wifi_pkt->src_mac[1], wifi_pkt->src_mac[2],
                         wifi_pkt->src_mac[3], wifi_pkt->src_mac[4], wifi_pkt->src_mac[5]);
            }
        }
        else
        {
            ESP_LOGI(TAG, "Detected AP not found in history for dedicated listening");
        }
    }
}

void update_evil_twin_config()
{
    const AppConfig *cfg = get_config();

    ap_history_timeout_ms = cfg->ap_history_timeout_ms;
    enable_dedicated_mode = cfg->enable_dedicated_mode;
    ap_print_timeout_ms = cfg->ap_print_timeout_ms;
    flagging_start_delay_ms = cfg->flagging_start_delay_ms;
    evil_twin_signal_threshold = cfg->evil_twin_signal_threshold;

    if (remove_stale_aps_timer)
    {
        ESP_ERROR_CHECK(esp_timer_stop(remove_stale_aps_timer));
        ESP_ERROR_CHECK(esp_timer_start_periodic(remove_stale_aps_timer,
                                                 ap_history_timeout_ms * 1000ULL));
    }

    if (ap_history_print_timer)
    {
        ESP_ERROR_CHECK(esp_timer_stop(ap_history_print_timer));
        ESP_ERROR_CHECK(esp_timer_start_periodic(ap_history_print_timer,
                                                 ap_print_timeout_ms * 1000ULL));
    }
}
