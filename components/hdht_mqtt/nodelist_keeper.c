// hdht_mqtt node list keeper: the trusted verifiers in NVS, the list fetched
// now and every 10 minutes, handed to the transport (see hdht_mqtt.h).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "nvs.h"
#include "hdht_mqtt.h"

#define REFRESH_MS (10 * 60 * 1000)

typedef struct {
  hdht_t *dht;
  esp_transport_handle_t transport;
  char ns[16];
  uint32_t pick;
  uint8_t trusted[HDHT_MQTT_NODELIST_VERIFIERS][32];
  size_t trusted_len;
  uv_timer_t timer;
  bool first_done;
  hdht_mqtt_nodelist_ready_cb ready;
  void *data;
} keeper_t;

static keeper_t *keeper;

static void
save_trusted (keeper_t *k) {
  nvs_handle_t nvs;
  if (nvs_open(k->ns, NVS_READWRITE, &nvs) != ESP_OK) return;
  nvs_set_blob(nvs, "verifiers", k->trusted, k->trusted_len * 32);
  nvs_commit(nvs);
  nvs_close(nvs);
}

static void
load_trusted (keeper_t *k, const char *csv) {
  nvs_handle_t nvs;
  size_t len = sizeof(k->trusted);
  if (nvs_open(k->ns, NVS_READONLY, &nvs) == ESP_OK) {
    if (nvs_get_blob(nvs, "verifiers", k->trusted, &len) == ESP_OK && len % 32 == 0) k->trusted_len = len / 32;
    nvs_close(nvs);
  }
  if (k->trusted_len) return;
  const char *p = csv ? csv : "";
  while (strlen(p) >= 64 && k->trusted_len < HDHT_MQTT_NODELIST_VERIFIERS) {
    if (sodium_hex2bin(k->trusted[k->trusted_len], 32, p, 64, NULL, NULL, NULL) != 0) break;
    k->trusted_len++;
    p += 64;
    if (*p == ',') p++;
  }
}

static void fetch (keeper_t *k);

static void
on_list (int status, const hdht_mqtt_nodelist_t *l, size_t votes, void *data) {
  keeper_t *k = data;
  if (status == 0) {
    hdht_mqtt_transport_set_nodes(k->transport, (const uint8_t (*)[32]) l->nodes, l->nodes_len);
    printf("NODELIST|epoch=%llu nodes=%u (page %u of %u, %u in all) verifiers=%u votes=%u/%u chain=%llu\n", (unsigned long long) l->epoch, l->nodes_len, (unsigned) l->page + 1, (unsigned) l->pages_len, (unsigned) l->total, l->verifiers_len, (unsigned) votes, (unsigned) k->trusted_len, (unsigned long long) l->chain_id);
    // the verifiers a quorum of ours names are the ones we trust next
    bool same = l->verifiers_len == k->trusted_len;
    for (size_t i = 0; same && i < k->trusted_len; i++) {
      bool found = false;
      for (int j = 0; j < l->verifiers_len && !found; j++) found = memcmp(k->trusted[i], l->verifiers[j], 32) == 0;
      same = found;
    }
    if (!same && l->verifiers_len > 0) {
      memcpy(k->trusted, l->verifiers, (size_t) l->verifiers_len * 32);
      k->trusted_len = l->verifiers_len;
      save_trusted(k);
      printf("NODELIST|now trusting the %u verifiers it names\n", (unsigned) k->trusted_len);
    }
  } else {
    printf("NODELIST|no list a quorum of %u verifiers agrees on%s\n", (unsigned) k->trusted_len, k->first_done ? "" : ": looking up the network name");
  }
  if (!k->first_done) {
    k->first_done = true;
    if (k->ready) k->ready(status == 0, k->data);
  }
}

static void
fetch (keeper_t *k) {
  if (hdht_mqtt_nodelist_fetch(k->dht, (const uint8_t (*)[32]) k->trusted, k->trusted_len, k->pick, on_list, k) != 0) on_list(-1, NULL, 0, k);
}

static void
on_timer (uv_timer_t *t) {
  fetch(t->data);
}

int
hdht_mqtt_nodelist_keep (hdht_t *dht, esp_transport_handle_t transport, const char *nvs_namespace, const char *verifiers, uint32_t pick, hdht_mqtt_nodelist_ready_cb ready, void *data) {
  if (keeper) return -1;
  keeper_t *k = calloc(1, sizeof(*k));
  if (k == NULL) return -1;
  k->dht = dht;
  k->transport = transport;
  snprintf(k->ns, sizeof(k->ns), "%s", nvs_namespace);
  k->pick = pick;
  k->ready = ready;
  k->data = data;
  load_trusted(k, verifiers);
  if (k->trusted_len == 0) {
    free(k);
    return -1;
  }
  keeper = k;
  printf("NODELIST|reading the lists of %u verifiers\n", (unsigned) k->trusted_len);
  fetch(k);
  uv_timer_init(dht->loop, &k->timer);
  k->timer.data = k;
  uv_timer_start(&k->timer, on_timer, REFRESH_MS, REFRESH_MS);
  return 0;
}
