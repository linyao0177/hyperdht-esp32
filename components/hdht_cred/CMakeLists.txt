# hdht_cred: manufacturer credentials, checked by a device (docs/credentials.md).
#
# Built two ways, like hdht: as an ESP-IDF component, or on a desktop for the
# tests (cmake -S components/hdht_cred -B build).

if(ESP_PLATFORM)
  idf_component_register(
    SRCS hdht_cred.c
    INCLUDE_DIRS include
    REQUIRES hdht espressif__libsodium
  )
  return()
endif()

cmake_minimum_required(VERSION 3.16)
project(hdht_cred C)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../hdht hdht)

add_library(hdht_cred STATIC hdht_cred.c)
target_include_directories(hdht_cred PUBLIC include)
target_link_libraries(hdht_cred PUBLIC hdht)

add_executable(test_cred test/test_cred.c)
target_link_libraries(test_cred hdht_cred)
