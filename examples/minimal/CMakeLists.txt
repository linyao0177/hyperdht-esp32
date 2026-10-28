cmake_minimum_required(VERSION 3.16)

# In your own project, point this at the components/ directory of hyperdht-esp32.
set(EXTRA_COMPONENT_DIRS
  $ENV{IDF_PATH}/examples/common_components/protocol_examples_common
  ${CMAKE_CURRENT_LIST_DIR}/../../components
)

# WiFi credentials: the repo root's gitignored sdkconfig.wifi (see sdkconfig.wifi.example)
set(SDKCONFIG_DEFAULTS "sdkconfig.defaults")
if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../../sdkconfig.wifi)
  list(APPEND SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/../../sdkconfig.wifi")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(hdht_minimal)
