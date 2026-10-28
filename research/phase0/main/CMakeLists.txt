idf_component_register(
  SRCS "main.c" "heap_report.c" "sodium_check.c" "udx_echo.c"
  INCLUDE_DIRS "."
  LDFRAGMENTS "linker.lf"
  REQUIRES libudx uv_esp nvs_flash esp_netif esp_wifi esp_event esp_timer protocol_examples_common
)
