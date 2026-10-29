// The command port: the line-based link to the host MCU. USB Serial/JTAG for
// development, or UART1 on two pins in a product (CONFIG_MODULE_PORT_*).

#ifndef PORT_H
#define PORT_H

#include <stdbool.h>
#include <stddef.h>

#define PORT_LINE_MAX 2304 // AT+PUT= with a 1000-byte value in hex, plus room

// Called on the reader task with each complete line, without CR/LF.
typedef void (*port_line_cb)(char *line, size_t len);

void
port_init (port_line_cb on_line);

// Writes one line and CRLF. Safe from any task; lines never interleave.
void
port_line (const char *line);

// printf to the port, as one line.
void
port_printf (const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
