// Shared between main.c (identity, WiFi, the loop) and at.c (commands).
// Everything here is used on the hdht task unless noted.

#ifndef MODULE_H
#define MODULE_H

#include <stdbool.h>
#include <stdint.h>

#include "hdht.h"

#define MODULE_VERSION "hdht-module/0.2"

extern uv_loop_t loop;
extern hdht_t dht;
extern bool dht_ready;
extern uint8_t pk[32], sk[64];
extern char did[72];

// WiFi (safe from any task)
bool
wifi_connected (void);

const char *
wifi_ip (void);

const char *
wifi_ssid (void);

// Stores the network in NVS and reconnects; an empty ssid goes back to the
// one built into the firmware.
void
wifi_set (const char *ssid, const char *password);

// at.c
void
at_init (void);

void
at_line (char *line);

void
at_dht_ready (void);

#endif
