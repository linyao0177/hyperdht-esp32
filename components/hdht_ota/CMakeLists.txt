# hdht_ota: firmware from a Hypercore, over HyperDHT (include/hdht_ota.h).
# hc_proof.c, the Hypercore proof checks, is plain C over libsodium and also
# builds on the desktop for its tests (test/test_hc_proof.c, driven by
# packages/boat-ota/test/run.js).
if(ESP_PLATFORM)
  idf_component_register(
    SRCS "hc_proof.c" "hdht_ota.c"
    INCLUDE_DIRS "include"
    REQUIRES hdht espressif__libsodium app_update esp_timer
  )
else()
  cmake_minimum_required(VERSION 3.16)
  project(hdht_ota C)
  find_path(SODIUM_INCLUDE sodium.h)
  find_library(SODIUM_LIB sodium)
  add_executable(test_hc_proof test/test_hc_proof.c hc_proof.c)
  target_include_directories(test_hc_proof PRIVATE include ${SODIUM_INCLUDE})
  target_link_libraries(test_hc_proof ${SODIUM_LIB})
endif()
