#include "evil_twin.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "sdkconfig.h"
#include "esp_mac.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "evil_twin_detection";
static ap_history_t *ap_history = NULL; // Global AP history pointer

// Timer handle for periodic printing of AP history
static esp_timer_handle_t ap_history_print_timer = NULL;
static esp_timer_handle_t remove_stale_aps_timer = NULL;

#define AP_HISTORY_TIMEOUT_MS 6000 // 6 seconds timeout
#define AP_PRINT_TIMEOUT_MS 20000000
#define FLAGGING_START_DELAY_MS 60000 // 1 minute delay

// Global boot time (set during initialization)
static uint32_t boot_time_ms = 0;

// Returns true if flagging (evil twin detection) is enabled (i.e. after initial delay)
static bool is_flagging_enabled(void)
{
    uint32_t now = esp_timer_get_time() / 1000;
    return ((now - boot_time_ms) >= FLAGGING_START_DELAY_MS);
}

void remove_stale_aps(void *arg)
{
    ap_history_t *history = ap_history;
    if (!history)
    {
        ESP_LOGW(TAG, "AP history is not initialized");
        return;
    }
    // Remove stale APs based on the timeout
    // Check if the history is empty or if the current index is 0
    if (!history || history->current_index == 0)
    {
        return;
    }

    uint32_t now = esp_timer_get_time() / 1000; // Get current time in milliseconds
    int new_index = 0;                          // To track the new position of valid entries

    for (int i = 0; i < history->current_index; i++)
    {
        if (now - history->aps[i].timestamp < AP_HISTORY_TIMEOUT_MS)
        {
            // Keep this AP, move it to the new position if needed
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

    history->current_index = new_index; // Update the count after removal
}

// Function to print AP history periodically
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

// Cleanup function to free allocated memory and stop timers
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

// Initialize the Evil Twin detection system
void initialize_evil_twin()
{
    cleanup_evil_twin(); // Clean up any previously allocated resources

    ap_history = malloc(sizeof(ap_history_t));
    if (ap_history == NULL)
    {
        ESP_LOGE(TAG, "Failed to allocate memory for AP history");
        return;
    }
    memset(ap_history, 0, sizeof(ap_history_t));
    ap_history->current_index = 0;
    ESP_LOGI(TAG, "Evil Twin detection initialized");

    // Create and start a periodic timer to print AP history every 20 seconds
    esp_timer_create_args_t timer_args = {
        .callback = print_ap_history,
        .arg = NULL,
        .name = "ap_history_print_timer"};
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &ap_history_print_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(ap_history_print_timer, AP_PRINT_TIMEOUT_MS)); // 20 seconds

    // Create and start a periodic timer to print AP history every 20 seconds
    esp_timer_create_args_t deleter_args = {
        .callback = remove_stale_aps,
        .arg = NULL,
        .name = "remove_stale_aps_timer"};
    ESP_ERROR_CHECK(esp_timer_create(&deleter_args, &remove_stale_aps_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(remove_stale_aps_timer, AP_HISTORY_TIMEOUT_MS)); // 20 seconds
}

// Helper: Check if the AP (by MAC and SSID) exists and update its values if so
bool add_ap_to_history_helper(ap_history_t *history, const uint8_t *mac, const char *ssid, int8_t signal_strength, uint32_t timestamp)
{
    for (int i = 0; i < history->current_index; i++)
    {
        if (memcmp(history->aps[i].mac, mac, 6) == 0 && strcmp(history->aps[i].ssid, ssid) == 0)
        {
            // Update the signal strength and timestamp of the existing entry
            history->aps[i].signal_strength = signal_strength;
            history->aps[i].timestamp = timestamp;
            return false; // Entry already existed
        }
    }
    return true; // Entry not found
}

// Add a new AP to the history if it is not already present
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
        // Use snprintf to ensure safe copy and null termination
        snprintf(history->aps[history->current_index].ssid, sizeof(history->aps[history->current_index].ssid), "%s", ssid);
        history->aps[history->current_index].signal_strength = signal_strength;
        history->aps[history->current_index].timestamp = timestamp;
        history->current_index++;
    }
}

bool check_signal_difference(ap_history_t *history, const char *ssid, const uint8_t *mac, int8_t signal_strength, int index)
{

    if (abs(history->aps[index].signal_strength - signal_strength) < EVIL_TWIN_SIGNAL_THRESHOLD)
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
        // Check if the SSID matches, but the MAC is different
        if (strcmp(history->aps[i].ssid, ssid) == 0 && memcmp(history->aps[i].mac, mac, 6) != 0)
        {
            ESP_LOGW(TAG, "Possible Evil Twin Attack Detected: SSID %s seen from different MACs", ssid);
            // Only check for evil twin if the signal strength difference is within the threshold
            check_signal_difference(history, ssid, mac, signal_strength, i);
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
    check_signal_difference(history, ssid, mac, signal_strength, index);

    return false;
}

// Analyze a Wi-Fi packet to determine if it is part of an Evil Twin attack
void analyze_evil_twin(const wifi_packet_t *wifi_pkt)
{
    bool evil_twin_detected = false;
    const char *ssid = NULL;

    // Only process beacon (subtype 0x08) or probe response (subtype 0x05) management frames
    if (wifi_pkt->type != WIFI_PKT_MGMT || !(wifi_pkt->subtype == 0x08 || wifi_pkt->subtype == 0x05))
    {
        return;
    }

    ssid = (const char *)wifi_pkt->ssid; // Assumed to be pre-extracted correctly
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
        // Add this AP to the history if no evil twin is detected
        add_ap_to_history(ap_history, wifi_pkt->src_mac, ssid, wifi_pkt->signal_strength, esp_timer_get_time() / 1000);
    }
}
