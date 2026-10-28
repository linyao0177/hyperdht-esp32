# Built only when NimBLE is enabled, so apps can include it unconditionally.
set(srcs)
if(CONFIG_BT_NIMBLE_ENABLED)
  set(srcs "hdht_ble.c")
endif()

idf_component_register(
  SRCS ${srcs}
  INCLUDE_DIRS "include"
  REQUIRES hdht bt esp_timer
)
