set(UDX_DIR "${CMAKE_CURRENT_LIST_DIR}/libudx")

idf_component_register(
  SRCS
    "${UDX_DIR}/src/cirbuf.c"
    "${UDX_DIR}/src/endian.c"
    "${UDX_DIR}/src/queue.c"
    "${UDX_DIR}/src/udx.c"
    "${UDX_DIR}/src/udx_bbr.c"
    "${UDX_DIR}/src/udx_rate.c"
    "${UDX_DIR}/src/udx_sack_tree.c"
    "${UDX_DIR}/src/udx_stream_table.c"
    "${UDX_DIR}/src/win_filter.c"
    "${UDX_DIR}/src/win_filter_f64.c"
    "port/io_esp.c"
    "port/udx_alloc.c"
  INCLUDE_DIRS "${UDX_DIR}/include" "port"
  REQUIRES uv_esp
)

# Route libudx's malloc/free through the accounting wrappers. udx_alloc.c
# itself must call the real allocator, so it is excluded.
set_source_files_properties(
  "${UDX_DIR}/src/cirbuf.c"
  "${UDX_DIR}/src/udx.c"
  "${UDX_DIR}/src/udx_sack_tree.c"
  "${UDX_DIR}/src/udx_stream_table.c"
  PROPERTIES COMPILE_OPTIONS "-include;${CMAKE_CURRENT_LIST_DIR}/port/udx_alloc.h;-DUDX_ALLOC_TRACK=1"
)

target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-parameter -Wno-sign-compare -Wno-format)
