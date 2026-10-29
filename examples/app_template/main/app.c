// Example application: the ESP32-C3's internal temperature sensor, read every
// interval_s seconds. The owner can change interval_s.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/temperature_sensor.h"
#include "nvs.h"

#include "app.h"

static temperature_sensor_handle_t sensor;
static uint32_t interval_s = 30;

void
app_init (void) {
  temperature_sensor_config_t config = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
  if (temperature_sensor_install(&config, &sensor) == ESP_OK) temperature_sensor_enable(sensor);

  nvs_handle_t nvs;
  if (nvs_open("app", NVS_READONLY, &nvs) == ESP_OK) {
    nvs_get_u32(nvs, "interval_s", &interval_s);
    nvs_close(nvs);
  }
}

uint32_t
app_interval_s (void) {
  return interval_s;
}

int
app_reading (char *out, size_t cap) {
  float celsius;
  if (sensor == NULL || temperature_sensor_get_celsius(sensor, &celsius) != ESP_OK) return -1;
  int len = snprintf(out, cap, "\"temp_c\":%.1f", celsius);
  return len > 0 && (size_t) len < cap ? len : -1;
}

int
app_settings (char *out, size_t cap) {
  int len = snprintf(out, cap, "\"interval_s\":%lu", (unsigned long) interval_s);
  return len > 0 && (size_t) len < cap ? len : -1;
}

bool
app_set (const char *key, const char *value) {
  if (strcmp(key, "interval_s") != 0) return false;
  char *end;
  unsigned long v = strtoul(value, &end, 10);
  if (*end != '\0' || v < 5 || v > 3600) return false;
  interval_s = (uint32_t) v;

  nvs_handle_t nvs;
  if (nvs_open("app", NVS_READWRITE, &nvs) == ESP_OK) {
    nvs_set_u32(nvs, "interval_s", interval_s);
    nvs_commit(nvs);
    nvs_close(nvs);
  }
  return true;
}
