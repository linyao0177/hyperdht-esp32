idf_component_register(
  SRCS "main.c" "app.c"
  REQUIRES hdht nvs_flash esp_netif esp_event esp_timer esp_driver_tsens protocol_examples_common
)
