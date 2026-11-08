idf_component_register(
  SRCS "hdht_mqtt.c"
  INCLUDE_DIRS "include"
  REQUIRES hdht tcp_transport espressif__libsodium esp_timer
)
