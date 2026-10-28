cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "$ENV{IDF_PATH}/examples/common_components/protocol_examples_common")

# WiFi credentials live in an untracked file so they never land in the repo.
# See README.md: copy sdkconfig.wifi.example to sdkconfig.wifi and fill it in.
set(SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.defaults")
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.wifi")
  list(APPEND SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.wifi")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(holepunch_c3_poc)
