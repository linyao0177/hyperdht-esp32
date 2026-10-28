idf_component_register(
  SRCS "main.c"
  INCLUDE_DIRS "."
  REQUIRES hdht hdht_ble nvs_flash esp_netif esp_event esp_timer protocol_examples_common
)
