#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#if CONFIG_MODULE_PORT_UART
#include "driver/uart.h"
#define PORT_UART UART_NUM_1
#else
#include "driver/usb_serial_jtag.h"
#endif

#include "port.h"

static SemaphoreHandle_t lock;
static port_line_cb line_cb;

static int
port_read (uint8_t *buf, size_t len) {
#if CONFIG_MODULE_PORT_UART
  return uart_read_bytes(PORT_UART, buf, len, pdMS_TO_TICKS(100));
#else
  return usb_serial_jtag_read_bytes(buf, len, pdMS_TO_TICKS(100));
#endif
}

static void
port_write (const char *data, size_t len) {
#if CONFIG_MODULE_PORT_UART
  uart_write_bytes(PORT_UART, data, len);
#else
  // a host that stops reading must not stall the network for long
  usb_serial_jtag_write_bytes(data, len, pdMS_TO_TICKS(200));
#endif
}

static void
reader_task (void *arg) {
  (void) arg;
  static char line[PORT_LINE_MAX + 1];
  size_t len = 0;
  bool overflow = false;
  uint8_t buf[64];

  for (;;) {
    int n = port_read(buf, sizeof(buf));
    for (int i = 0; i < n; i++) {
      char c = (char) buf[i];
      if (c == '\r') continue;
      if (c != '\n') {
        if (len < PORT_LINE_MAX) line[len++] = c;
        else overflow = true;
        continue;
      }
      if (overflow) port_line("ERROR:line too long");
      else if (len > 0) {
        line[len] = '\0';
        line_cb(line, len);
      }
      len = 0;
      overflow = false;
    }
  }
}

void
port_init (port_line_cb on_line) {
  line_cb = on_line;
  lock = xSemaphoreCreateMutex();
#if CONFIG_MODULE_PORT_UART
  uart_config_t config = {
    .baud_rate = CONFIG_MODULE_UART_BAUD,
    .data_bits = UART_DATA_8_BITS,
    .parity = UART_PARITY_DISABLE,
    .stop_bits = UART_STOP_BITS_1,
    .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    .source_clk = UART_SCLK_DEFAULT,
  };
  uart_driver_install(PORT_UART, 4096, 4096, 0, NULL, 0);
  uart_param_config(PORT_UART, &config);
  uart_set_pin(PORT_UART, CONFIG_MODULE_UART_TX_PIN, CONFIG_MODULE_UART_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
#else
  usb_serial_jtag_driver_config_t config = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
  config.rx_buffer_size = 4096;
  config.tx_buffer_size = 4096;
  usb_serial_jtag_driver_install(&config);
#endif
  xTaskCreate(reader_task, "port", 4096, NULL, 6, NULL);
}

void
port_line (const char *line) {
  xSemaphoreTake(lock, portMAX_DELAY);
  port_write(line, strlen(line));
  port_write("\r\n", 2);
  xSemaphoreGive(lock);
}

void
port_printf (const char *fmt, ...) {
  static char buf[PORT_LINE_MAX + 64];
  xSemaphoreTake(lock, portMAX_DELAY);
  va_list ap;
  va_start(ap, fmt);
  int len = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (len > (int) sizeof(buf) - 1) len = sizeof(buf) - 1;
  if (len > 0) port_write(buf, (size_t) len);
  port_write("\r\n", 2);
  xSemaphoreGive(lock);
}
