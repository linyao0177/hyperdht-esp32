idf_component_register(
  SRCS "main.c"
  REQUIRES hdht boat-mer nvs_flash esp_netif esp_event esp_timer protocol_examples_common
)
