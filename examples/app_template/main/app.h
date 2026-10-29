// The application part of the template: what the device measures and what
// its owner may configure. Replace app.c with your own; main.c (identity,
// access, records, protocol) stays as it is.
//
// Everything here runs on the hdht task. Keep each call short: the network
// waits while it runs.

#ifndef APP_H
#define APP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APP_SERVICE "app-template/1" // goes in the device's record as "svc"

void
app_init (void);

// Seconds between readings.
uint32_t
app_interval_s (void);

// Writes one reading as JSON members without braces, for example
// "\"temp_c\":24.5". Returns the length, or -1.
int
app_reading (char *out, size_t cap);

// Writes the current settings as JSON members without braces.
int
app_settings (char *out, size_t cap);

// Applies an owner's setting. Returns false if the key is unknown or the
// value is invalid; valid settings are kept across reboots.
bool
app_set (const char *key, const char *value);

#endif
