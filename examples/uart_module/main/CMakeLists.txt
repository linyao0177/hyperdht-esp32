idf_component_register(
  SRCS "main.c" "at.c" "port.c" "zk.c" "mqtt.c"
  REQUIRES hdht hdht_cred hdht_mqtt mqtt zk nvs_flash esp_timer esp_netif esp_event esp_wifi esp_driver_uart esp_driver_usb_serial_jtag protocol_examples_common
)
