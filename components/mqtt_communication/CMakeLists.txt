idf_component_register(
    SRCS
        "requester.c"
        "mqtt_fragment_buffer.c"
        "network_status.c"
        "../../main/tools/hash_function.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        freertos
        newlib
        esp_system
        esp_hw_support
        esp_rom
        log
        esp_netif
        esp_wifi
        esp_event
        nvs_flash
        esp_timer
        mqtt
        cjson
        esp_pm
)


