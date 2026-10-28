cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS
  $ENV{IDF_PATH}/examples/common_components/protocol_examples_common
  ${CMAKE_CURRENT_LIST_DIR}/../../components
)

# BoAT MER build profile: the buyer engine, nanopayment signing and attestation
set(BOAT_PROFILE "buyer" CACHE STRING "" FORCE)

# WiFi credentials: the repo root's gitignored sdkconfig.wifi (see sdkconfig.wifi.example)
set(SDKCONFIG_DEFAULTS "sdkconfig.defaults")
if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/../../sdkconfig.wifi)
  list(APPEND SDKCONFIG_DEFAULTS "${CMAKE_CURRENT_LIST_DIR}/../../sdkconfig.wifi")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(hdht_boat_mer)

# BoAT MER defines a global randombytes() to feed TweetNaCl, and libsodium (used
# by hdht) defines one too, so the link fails with a duplicate symbol. Renaming
# MER's copy inside its own component keeps TweetNaCl wired to MER's RNG.
idf_component_get_property(boat_mer_lib boat-mer COMPONENT_LIB)
target_compile_definitions(${boat_mer_lib} PRIVATE randombytes=boat_mer_randombytes)
