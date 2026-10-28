idf_component_register(
  SRCS "src/uv_esp.c"
  INCLUDE_DIRS "include"
  REQUIRES lwip esp_timer freertos vfs
)
