cmake_minimum_required(VERSION 3.16)

# hdht on the ESP32-C3: the HyperDHT library plus the PoC's libuv shim and libudx.
set(EXTRA_COMPONENT_DIRS
  $ENV{IDF_PATH}/examples/common_components/protocol_examples_common
  ${CMAKE_CURRENT_LIST_DIR}/../poc/components
  ${CMAKE_CURRENT_LIST_DIR}/../hdht
)

# WiFi credentials live in the PoC's gitignored sdkconfig.wifi
set(SDKCONFIG_DEFAULTS "sdkconfig.defaults")
if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../poc/sdkconfig.wifi)
  list(APPEND SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/../poc/sdkconfig.wifi")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(hdht_c3)
