# hdht: HyperDHT client/server in C for constrained devices.
#
# Built two ways:
#   - as an ESP-IDF component (ESP_PLATFORM), using uv_esp + libudx + espressif/libsodium
#   - standalone on a desktop for interop tests, using libuv + libudx + libsodium

set(HDHT_SOURCES
  src/connect.c
  src/crypto.c
  src/dht.c
  src/hdht.c
  src/holepunch.c
  src/messages.c
  src/noise.c
  src/secret_stream.c
  src/server.c
  src/stream.c
)

if(ESP_PLATFORM)
  idf_component_register(
    SRCS ${HDHT_SOURCES}
    INCLUDE_DIRS "include" "src"
    REQUIRES libudx uv_esp espressif__libsodium
  )
  return()
endif()

cmake_minimum_required(VERSION 3.20)
project(hdht C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_path(SODIUM_INCLUDE sodium.h HINTS /opt/homebrew/include /usr/local/include REQUIRED)
find_library(SODIUM_LIB sodium HINTS /opt/homebrew/lib /usr/local/lib REQUIRED)
find_path(UV_INCLUDE uv.h HINTS /opt/homebrew/include /usr/local/include REQUIRED)
find_library(UV_LIB uv HINTS /opt/homebrew/lib /usr/local/lib REQUIRED)

# libudx (vendored and patched in the PoC)
set(UDX_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../poc/components/libudx/libudx)
add_library(udx STATIC
  ${UDX_DIR}/src/cirbuf.c
  ${UDX_DIR}/src/endian.c
  ${UDX_DIR}/src/io_posix.c
  ${UDX_DIR}/src/queue.c
  ${UDX_DIR}/src/udx.c
  ${UDX_DIR}/src/udx_rate.c
  ${UDX_DIR}/src/win_filter.c
  ${UDX_DIR}/src/win_filter_f64.c
  ${UDX_DIR}/src/udx_bbr.c
  ${UDX_DIR}/src/udx_sack_tree.c
  ${UDX_DIR}/src/udx_stream_table.c
)
target_include_directories(udx PUBLIC ${UDX_DIR}/include ${UV_INCLUDE})
target_link_libraries(udx PUBLIC ${UV_LIB})

add_library(hdht STATIC ${HDHT_SOURCES})
target_include_directories(hdht PUBLIC include src ${SODIUM_INCLUDE})
target_compile_options(hdht PRIVATE -Wall -Wextra)
target_link_libraries(hdht PUBLIC udx ${SODIUM_LIB} ${UV_LIB})

add_executable(test_vectors test/test_vectors.c)
target_link_libraries(test_vectors hdht)

add_executable(test_query test/test_query.c)
target_link_libraries(test_query hdht)

add_executable(test_connect test/test_connect.c)
target_link_libraries(test_connect hdht)

add_executable(test_server test/test_server.c)
target_link_libraries(test_server hdht)

add_executable(test_ss test/test_ss.c)
target_link_libraries(test_ss hdht)

enable_testing()
add_test(NAME vectors COMMAND test_vectors)
