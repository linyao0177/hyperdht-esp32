# Builds BoAT MER's x402 client on a computer, against a BoAT MER checkout:
#   cmake -S . -B build -DBOAT_MER_DIR=<path to boat-mer> -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake_minimum_required(VERSION 3.16)
project(mer_x402_client C)

set(BOAT_MER_DIR "" CACHE PATH "BoAT MER source tree (github.com/TLAY-IO/boat-mer, v1.0.1)")
if(NOT BOAT_MER_DIR)
  message(FATAL_ERROR "set BOAT_MER_DIR to a BoAT MER checkout")
endif()
set(BOAT_PROFILE "full" CACHE STRING "" FORCE)
add_subdirectory(${BOAT_MER_DIR} boat-mer EXCLUDE_FROM_ALL)

add_executable(mer_x402_client main.c)
target_link_libraries(mer_x402_client PRIVATE boat_mer)
