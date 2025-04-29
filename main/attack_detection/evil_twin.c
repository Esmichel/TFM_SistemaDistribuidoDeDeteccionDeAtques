#include "evil_twin.h"

static const char *TAG = "evil_twin_detection";
static ap_history_t *ap_history = NULL; // Global AP history pointer
static esp_timer_handle_t ap_history_print_timer = NULL;
static esp_timer_handle_t remove_stale_aps_timer = NULL;

// #define ap_history_timeout_ms 25000 // 6 seconds timeout
// #define ap_print_timeout_ms 20000000
// #define FLAGGING_START_DELAY_MS 60000 // 1 minute delay

// loaded config values
int ap_history_timeout_ms = 0;
int ap_print_timeout_ms = 0;
int flagging_start_delay_ms = 0;
// int max_aps = 0;
int evil_twin_signal_threshold = 0;


static uint32_t boot_time_ms = 0;
const wifi_packet_t *actual_wifi_pkt;


static bool is_flagging_enabled(void)
{
    uint32_t now = esp_timer_get_time() / 1000;
    return ((now - boot_time_ms) >= flagging_start_delay_ms);
}

void remove_stale_aps(void *arg)
{
    ap_history_t *history = ap_history;
    if (!history)
    {
        ESP_LOGW(TAG, "AP history is not initialized");
        return;
    }
    if (!history || history->current_index == 0)
    {
        return;
    }

    uint32_t now = esp_timer_get_time() / 1000;
    int new_index = 0;                          

    for (int i = 0; i < history->current_index; i++)
    {
        if (now - history->aps[i].timestamp < ap_history_timeout_ms)
        {
            if (new_index != i)
            {
                history->aps[new_index] = history->aps[i];
            }
            new_index++;
        }
        else
        {
            // ESP_LOGI(TAG, "Removing stale AP: %s (MAC: %02X:%02X:%02X:%02X:%02X:%02X)",
            //          history->aps[i].ssid,
            //          history->aps[i].mac[0], history->aps[i].mac[1], history->aps[i].mac[2],
            //          history->aps[i].mac[3], history->aps[i].mac[4], history->aps[i].mac[5]);
        }
    }

    history->current_index = new_index;
}

void print_ap_history(void *arg)
{
    ESP_LOGI(TAG, "Printing AP History:");
    if (!ap_history)
    {
        ESP_LOGW(TAG, "AP history is not initialized");
        return;
    }

    for (int i = 0; i < ap_history->current_index; i++)
    {
        ESP_LOGI(TAG, "AP %d: MAC: %02X:%02X:%02X:%02X:%02X:%02X, SSID: %s, Signal: %d, Timestamp: %u",
                 i,
                 ap_history->aps[i].mac[0], ap_history->aps[i].mac[1], ap_history->aps[i].mac[2],
                 ap_history->aps[i].mac[3], ap_history->aps[i].mac[4], ap_history->aps[i].mac[5],
                 ap_history->aps[i].ssid,
                 ap_history->aps[i].signal_strength,
                 ap_history->aps[i].timestamp);
    }
}

void cleanup_evil_twin()
{
    if (ap_history != NULL)
    {
        free(ap_history);
        ap_history = NULL;
    }

    if (ap_history_print_timer != NULL)
    {
        esp_timer_stop(ap_history_print_timer);
        esp_timer_delete(ap_history_print_timer);
        ap_history_print_timer = NULL;
    }

    if (remove_stale_aps_timer != NULL)
    {
        esp_timer_stop(remove_stale_aps_timer);
        esp_timer_delete(remove_stale_aps_timer);
        remove_stale_aps_timer = NULL;
    }
}

void initialize_evil_twin()
{
    AppConfig *config = get_config();
    ap_history_timeout_ms = config->ap_history_timeout_ms;
    ap_print_timeout_ms = config->ap_print_timeout_ms;
    flagging_start_delay_ms = config->flagging_start_delay_ms;
    // max_aps = config->max_aps;
    evil_twin_signal_threshold = config->evil_twin_signal_threshold;
    cleanup_evil_twin();

    ap_history = malloc(sizeof(ap_history_t));
    if (ap_history == NULL)
    {
        ESP_LOGE(TAG, "Failed to allocate memory for AP history");
        return;
    }
    memset(ap_history, 0, sizeof(ap_history_t));
    ap_history->current_index = 0;
    ESP_LOGI(TAG, "Evil Twin detection initialized");

    esp_timer_create_args_t timer_args = {
        .callback = print_ap_history,
        .arg = NULL,
        .name = "ap_history_print_timer"};
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &ap_history_print_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(ap_history_print_timer, ap_print_timeout_ms));

    esp_timer_create_args_t deleter_args = {
        .callback = remove_stale_aps,
        .arg = NULL,
        .name = "remove_stale_aps_timer"};
    ESP_ERROR_CHECK(esp_timer_create(&deleter_args, &remove_stale_aps_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(remove_stale_aps_timer, ap_history_timeout_ms));
}
bool add_ap_to_history_helper(ap_history_t *history, const uint8_t *mac, const char *ssid, int8_t signal_strength, uint32_t timestamp)
{
    for (int i = 0; i < history->current_index; i++)
    {
        if (memcmp(history->aps[i].mac, mac, 6) == 0 && strcmp(history->aps[i].ssid, ssid) == 0)
        {
            history->aps[i].signal_strength = signal_strength;
            history->aps[i].timestamp = timestamp;
            // ESP_LOGI(TAG, "Updated existing AP: %s (MAC: %02X:%02X:%02X:%02X:%02X:%02X)",
            //          ssid,
            //          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return false;
        }
    }
    return true;
}

void add_ap_to_history(ap_history_t *history, const uint8_t *mac, const char *ssid, int8_t signal_strength, uint32_t timestamp)
{
    if (history->current_index >= MAX_APS)
    {
        ESP_LOGW(TAG, "AP history is full, cannot add new AP");
        return;
    }

    if (add_ap_to_history_helper(history, mac, ssid, signal_strength, timestamp))
    {
        memcpy(history->aps[history->current_index].mac, mac, 6);
        snprintf(history->aps[history->current_index].ssid, sizeof(history->aps[history->current_index].ssid), "%s", ssid);
        history->aps[history->current_index].signal_strength = signal_strength;
        history->aps[history->current_index].timestamp = timestamp;
        history->current_index++;
    }
}

bool check_signal_difference(ap_history_t *history, const char *ssid, const uint8_t *mac, int8_t signal_strength, int index)
{

    if (abs(history->aps[index].signal_strength - signal_strength) < evil_twin_signal_threshold)
    {
        ESP_LOGW(TAG, "Signal inesity significantly higher", ssid);
        return true;
    }
    return false;
}

bool check_for_evil_twin_in_history(ap_history_t *history, const char *ssid, const uint8_t *mac, int8_t signal_strength)
{
    for (int i = 0; i < history->current_index; i++)
    {
        if (strcmp(history->aps[i].ssid, ssid) == 0 && memcmp(history->aps[i].mac, mac, 6) != 0)
        {
            ESP_LOGW(TAG, "Possible Evil Twin Attack Detected: SSID %s seen from different MACs", ssid);
            build_attack_alert_payload(actual_wifi_pkt, "Evil Twin");
            check_signal_difference(history, ssid, mac, signal_strength, i);
            return true;
        }
    }
    return false;
}

bool check_for_evil_twin_signal_based(ap_history_t *history, const char *ssid, const uint8_t *mac, int8_t signal_strength)
{
    int index;
    for (index = 0; (strcmp(history->aps[index].ssid, ssid) == 0 && memcmp(history->aps[index].mac, mac, 6) == 0) || index >= history->current_index; index++)
    {
        break;
    }
    return check_signal_difference(history, ssid, mac, signal_strength, index);
}

void analyze_evil_twin(const wifi_packet_t *wifi_pkt)
{
    actual_wifi_pkt = wifi_pkt;
    bool evil_twin_detected = false;
    const char *ssid = (const char *)wifi_pkt->ssid;
    if (wifi_pkt->type != WIFI_PKT_MGMT || !(wifi_pkt->subtype == 0x08 || wifi_pkt->subtype == 0x05) || strcmp(ssid, "<Hidden>") == 0 || strcmp(ssid, "<No SSID>") == 0 || current_wifi_state == STATE_DEDICATED_LISTENING)
    {
        ESP_LOGD(TAG, "Ignoring non-relevant packet or in dedicated listening mode");
        return;
    }
    if (is_flagging_enabled())
    {
        if (!add_ap_to_history_helper(ap_history, wifi_pkt->src_mac, ssid, wifi_pkt->signal_strength, esp_timer_get_time() / 1000))
        {
            evil_twin_detected = check_for_evil_twin_signal_based(ap_history, ssid, wifi_pkt->src_mac, wifi_pkt->signal_strength);
        }
        else
        {
            evil_twin_detected = check_for_evil_twin_in_history(ap_history, (const char *)wifi_pkt->ssid, wifi_pkt->src_mac, wifi_pkt->signal_strength);
        }
    }

    if (!evil_twin_detected)
    {
        add_ap_to_history(ap_history, wifi_pkt->src_mac, ssid, wifi_pkt->signal_strength, esp_timer_get_time() / 1000);
    }
    else
    {
        start_dedicated_listening_mode(wifi_pkt);
    }
}
