cmake_minimum_required(VERSION 3.16)

# SecretStream over BLE GATT on the ESP32-C3, using hdht's crypto (no WiFi).
set(EXTRA_COMPONENT_DIRS
  ${CMAKE_CURRENT_LIST_DIR}/../poc/components
  ${CMAKE_CURRENT_LIST_DIR}/../hdht
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(hdht_ble)
