idf_component_register(
  SRCS "main.c"
  INCLUDE_DIRS "."
  REQUIRES hdht nvs_flash esp_netif esp_event esp_timer protocol_examples_common
)
