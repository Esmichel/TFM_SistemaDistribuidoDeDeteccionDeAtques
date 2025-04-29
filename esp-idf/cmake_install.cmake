# Install script for directory: /home/sergio/esp/esp-idf

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/riscv/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_gpio/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_pm/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/mbedtls/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/bootloader/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esptool_py/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/partition_table/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_app_format/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_bootloader_format/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/app_update/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_partition/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/efuse/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/bootloader_support/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_mm/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/spi_flash/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_system/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_common/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_rom/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/hal/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/log/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/heap/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/soc/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_security/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_hw_support/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/freertos/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/newlib/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/pthread/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/cxx/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_timer/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_gptimer/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_ringbuf/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_uart/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/app_trace/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_event/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/nvs_flash/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_phy/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_usb_serial_jtag/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_vfs_console/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/vfs/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/lwip/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_netif_stack/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_netif/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/wpa_supplicant/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_coex/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_wifi/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/bt/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/unity/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/cmock/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/console/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_pcnt/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_spi/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_mcpwm/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_ana_cmpr/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_i2s/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/sdmmc/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_sdmmc/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_sdspi/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_sdio/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_dac/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_rmt/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_tsens/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_sdm/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_i2c/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_ledc/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_parlio/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/driver/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/http_parser/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp-tls/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_adc/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_bitscrambler/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_isp/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_cam/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_jpeg/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_ppa/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_driver_touch_sens/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_eth/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_gdbstub/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_hid/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/tcp_transport/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_http_client/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_http_server/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_https_ota/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_https_server/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_psram/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_lcd/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/protobuf-c/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/protocomm/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_local_ctrl/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/esp_tee/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/espcoredump/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/wear_levelling/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/fatfs/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/idf_test/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/ieee802154/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/json/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/mqtt/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/nvs_sec_provider/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/openthread/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/rt/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/spiffs/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/ulp/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/usb/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/wifi_provisioning/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/cjson/cmake_install.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/esp-idf/main/cmake_install.cmake")
endif()

