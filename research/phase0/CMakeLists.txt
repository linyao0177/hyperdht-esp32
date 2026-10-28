cmake_minimum_required(VERSION 3.16)

# Phase 0 feasibility PoC: libsodium checks and libudx echo/heap measurements.
set(EXTRA_COMPONENT_DIRS
  "$ENV{IDF_PATH}/examples/common_components/protocol_examples_common"
  "${CMAKE_CURRENT_LIST_DIR}/../../components/libudx"
  "${CMAKE_CURRENT_LIST_DIR}/../../components/uv_esp"
)

# WiFi credentials: the repo root's gitignored sdkconfig.wifi (see sdkconfig.wifi.example)
set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults")
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../../sdkconfig.wifi")
  list(APPEND SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/../../sdkconfig.wifi")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(hyperdht_esp32_phase0)
