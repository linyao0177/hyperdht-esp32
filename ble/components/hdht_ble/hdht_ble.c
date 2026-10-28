// SecretStream over BLE GATT on the ESP32-C3 (component used by ble/ and firmware/).
//
// One custom service: the central writes to RX, we notify on TX. The bytes on
// both are a plain @hyperswarm/secret-stream byte stream (Noise XX handshake,
// then encrypted messages), keyed by the same Ed25519 key pair the device
// uses on HyperDHT. Every message is echoed back. Output is "BLE|..." lines.

#include <stdio.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "sdkconfig.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "crypto.h"
#include "hdht_ble.h"
#include "secret_stream.h"

// 1d9e000X-3c2a-4b8e-9f5e-6864687462ee (X = 1 service, 2 rx, 3 tx), little-endian
#define HDHT_UUID(x) BLE_UUID128_INIT(0xee, 0x62, 0x74, 0x68, 0x64, 0x68, 0x5e, 0x9f, 0x8e, 0x4b, 0x2a, 0x3c, x, 0x00, 0x9e, 0x1d)

static const ble_uuid128_t SVC_UUID = HDHT_UUID(0x01);
static const ble_uuid128_t RX_UUID = HDHT_UUID(0x02);
static const ble_uuid128_t TX_UUID = HDHT_UUID(0x03);

static uint8_t public_key[32];
static uint8_t secret_key[64];
static char device_name[16];
static uint8_t own_addr_type;
static uint16_t tx_handle;

// one connection at a time
static uint16_t conn = BLE_HS_CONN_HANDLE_NONE;
static bool subscribed;
static uint16_t mtu = 23;
static hdht_ss_t ss;
static bool ss_active;
static int64_t connected_at;
static int64_t handshake_started;
static uint32_t bytes_rx, bytes_tx, messages;

// outgoing bytes waiting for notification buffers
static uint8_t queue[CONFIG_HDHT_BLE_TX_QUEUE];
static size_t q_head, q_len;
static struct ble_npl_callout retry;
static uint32_t queue_overflows;

static void
start_advertising (void);

static uint32_t
ms_since (int64_t t) {
  return (uint32_t) ((esp_timer_get_time() - t) / 1000);
}

// notifications

static void
drain (void) {
  // only the host task runs this, so the buffer can live outside its stack
  static uint8_t chunk[512];
  // ble_gatts_notify_custom raises NOTIFY_TX synchronously; don't recurse from it
  static bool draining;
  if (draining) return;
  draining = true;

  while (q_len > 0 && conn != BLE_HS_CONN_HANDLE_NONE && subscribed) {
    size_t n = q_len;
    if (n > (size_t) (mtu - 3)) n = mtu - 3;
    if (n > sizeof(chunk)) n = sizeof(chunk);
    for (size_t i = 0; i < n; i++) chunk[i] = queue[(q_head + i) % sizeof(queue)];

    struct os_mbuf *om = ble_hs_mbuf_from_flat(chunk, (uint16_t) n);
    if (om == NULL || ble_gatts_notify_custom(conn, tx_handle, om) != 0) {
      // out of buffers: try again shortly (a NOTIFY_TX event also retries)
      ble_npl_callout_reset(&retry, ble_npl_time_ms_to_ticks32(5));
      break;
    }

    q_head = (q_head + n) % sizeof(queue);
    q_len -= n;
    bytes_tx += (uint32_t) n;
  }

  draining = false;
}

static void
on_retry (struct ble_npl_event *ev) {
  (void) ev;
  drain();
}

static void
on_ss_send (hdht_ss_t *s, const uint8_t *data, size_t len) {
  (void) s;
  if (len > sizeof(queue) - q_len) {
    queue_overflows++;
    return; // the stream breaks; the client notices a decrypt or timeout error
  }
  for (size_t i = 0; i < len; i++) queue[(q_head + q_len + i) % sizeof(queue)] = data[i];
  q_len += len;
  drain();
}

// secret stream

static void
on_ss_open (hdht_ss_t *s) {
  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), s->remote_public_key, 32);
  printf("BLE|open|handshake_ms=%lu|remote=%.16s|mtu=%u|heap=%u\n", (unsigned long) ms_since(handshake_started), hex, mtu, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
}

static void
on_ss_data (hdht_ss_t *s, const uint8_t *data, size_t len) {
  messages++;
  hdht_ss_write(s, data, len); // echo
}

static void
on_ss_error (hdht_ss_t *s, int error) {
  (void) s;
  printf("BLE|ss_error|error=%d\n", error);
  if (conn != BLE_HS_CONN_HANDLE_NONE) ble_gap_terminate(conn, BLE_ERR_REM_USER_CONN_TERM);
}

// GATT

static int
on_access (uint16_t conn_handle, uint16_t attr_handle, struct ble_gatt_access_ctxt *ctxt, void *arg) {
  (void) attr_handle;
  (void) arg;
  if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR || conn_handle != conn || !ss_active) return 0;

  static uint8_t buf[512]; // host task only; the handshake below needs the stack
  uint16_t len = 0;
  if (ble_hs_mbuf_to_flat(ctxt->om, buf, sizeof(buf), &len) != 0) return BLE_ATT_ERR_INSUFFICIENT_RES;

  if (handshake_started == 0) handshake_started = esp_timer_get_time();
  bytes_rx += len;
  hdht_ss_feed(&ss, buf, len);
  return 0;
}

static const struct ble_gatt_svc_def SERVICES[] = {
  {
    .type = BLE_GATT_SVC_TYPE_PRIMARY,
    .uuid = &SVC_UUID.u,
    .characteristics = (struct ble_gatt_chr_def[]) {
      {
        .uuid = &RX_UUID.u,
        .access_cb = on_access,
        .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
      },
      {
        .uuid = &TX_UUID.u,
        .access_cb = on_access,
        .flags = BLE_GATT_CHR_F_NOTIFY,
        .val_handle = &tx_handle,
      },
      {0},
    },
  },
  {0},
};

// GAP

static void
reset_connection (void) {
  if (ss_active) hdht_ss_destroy(&ss);
  ss_active = false;
  conn = BLE_HS_CONN_HANDLE_NONE;
  subscribed = false;
  mtu = 23;
  q_head = q_len = 0;
  ble_npl_callout_stop(&retry);
}

static int
on_gap_event (struct ble_gap_event *event, void *arg) {
  (void) arg;

  switch (event->type) {
  case BLE_GAP_EVENT_CONNECT:
    if (event->connect.status != 0) {
      start_advertising();
      return 0;
    }
    conn = event->connect.conn_handle;
    connected_at = esp_timer_get_time();
    handshake_started = 0;
    bytes_rx = bytes_tx = messages = queue_overflows = 0;

    hdht_ss_init(&ss, false, HDHT_NOISE_XX, public_key, secret_key, NULL);
    ss.on_send = on_ss_send;
    ss.on_open = on_ss_open;
    ss.on_data = on_ss_data;
    ss.on_error = on_ss_error;
    ss_active = true;

    // ask for the faster PHY and longer link-layer packets; both are best effort
    ble_gap_set_prefered_le_phy(conn, BLE_GAP_LE_PHY_2M_MASK, BLE_GAP_LE_PHY_2M_MASK, BLE_GAP_LE_PHY_CODED_ANY);
    ble_gap_set_data_len(conn, 251, 2120);
    // shorter connection interval (units of 1.25 ms): 15-30 ms, supervision timeout 4 s
    struct ble_gap_upd_params params = {.itvl_min = 12, .itvl_max = 24, .latency = 0, .supervision_timeout = 400};
    ble_gap_update_params(conn, &params);
    printf("BLE|connect|heap=%u\n", (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
    return 0;

  case BLE_GAP_EVENT_DISCONNECT:
    printf("BLE|disconnect|reason=0x%x|ms=%lu|rx=%lu|tx=%lu|messages=%lu|overflows=%lu|heap=%u\n", event->disconnect.reason,
           (unsigned long) ms_since(connected_at), (unsigned long) bytes_rx, (unsigned long) bytes_tx, (unsigned long) messages,
           (unsigned long) queue_overflows, (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
    reset_connection();
    start_advertising();
    return 0;

  case BLE_GAP_EVENT_SUBSCRIBE:
    if (event->subscribe.attr_handle == tx_handle) {
      subscribed = event->subscribe.cur_notify;
      drain();
    }
    return 0;

  case BLE_GAP_EVENT_MTU:
    mtu = event->mtu.value;
    printf("BLE|mtu|%u\n", mtu);
    return 0;

  case BLE_GAP_EVENT_CONN_UPDATE: {
    struct ble_gap_conn_desc desc;
    if (ble_gap_conn_find(event->conn_update.conn_handle, &desc) == 0) {
      printf("BLE|conn_params|status=%d|interval_ms=%u.%02u\n", event->conn_update.status, desc.conn_itvl * 125 / 100, (desc.conn_itvl * 125) % 100);
    }
    return 0;
  }

  case BLE_GAP_EVENT_PHY_UPDATE_COMPLETE:
    printf("BLE|phy|status=%d|tx=%u|rx=%u\n", event->phy_updated.status, event->phy_updated.tx_phy, event->phy_updated.rx_phy);
    return 0;

  case BLE_GAP_EVENT_NOTIFY_TX:
    // a buffer was freed; continue from the event queue, not from inside notify
    if (q_len > 0) ble_npl_callout_reset(&retry, 0);
    return 0;

  case BLE_GAP_EVENT_ADV_COMPLETE:
    start_advertising();
    return 0;
  }
  return 0;
}

static void
start_advertising (void) {
  struct ble_hs_adv_fields fields = {0};
  fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
  fields.uuids128 = &SVC_UUID;
  fields.num_uuids128 = 1;
  fields.uuids128_is_complete = 1;
  ble_gap_adv_set_fields(&fields);

  // scan response: name + manufacturer data 0xffff || first 8 bytes of BLAKE2b(public key)
  // (that hash is also the device's HyperDHT target)
  uint8_t mfg[2 + 8] = {0xff, 0xff};
  uint8_t target[32];
  hdht_hash(target, public_key, 32);
  memcpy(mfg + 2, target, 8);

  struct ble_hs_adv_fields rsp = {0};
  rsp.name = (const uint8_t *) device_name;
  rsp.name_len = (uint8_t) strlen(device_name);
  rsp.name_is_complete = 1;
  rsp.mfg_data = mfg;
  rsp.mfg_data_len = sizeof(mfg);
  ble_gap_adv_rsp_set_fields(&rsp);

  struct ble_gap_adv_params params = {0};
  params.conn_mode = BLE_GAP_CONN_MODE_UND;
  params.disc_mode = BLE_GAP_DISC_MODE_GEN;
  int rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER, &params, on_gap_event, NULL);
  if (rc != 0 && rc != BLE_HS_EALREADY) printf("BLE|adv_error|%d\n", rc);
}

static void
on_sync (void) {
  ble_hs_util_ensure_addr(0);
  ble_hs_id_infer_auto(0, &own_addr_type);

  uint8_t addr[6];
  ble_hs_id_copy_addr(own_addr_type, addr, NULL);
  printf("BLE|advertising|name=%s|addr=%02x:%02x:%02x:%02x:%02x:%02x|heap=%u\n", device_name, addr[5], addr[4], addr[3], addr[2], addr[1], addr[0],
         (unsigned) heap_caps_get_free_size(MALLOC_CAP_8BIT));
  start_advertising();
}

static void
host_task (void *param) {
  (void) param;
  nimble_port_run();
  nimble_port_freertos_deinit();
}

int
hdht_ble_start (const uint8_t pk[32], const uint8_t sk[64]) {
  memcpy(public_key, pk, 32);
  memcpy(secret_key, sk, 64);

  char hex[65];
  sodium_bin2hex(hex, sizeof(hex), public_key, 32);
  snprintf(device_name, sizeof(device_name), "hdht-%.4s", hex);
  printf("BLE|key|%s\n", hex);

  size_t before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
  int err = nimble_port_init();
  if (err != 0) return err;
  ble_hs_cfg.sync_cb = on_sync;
  ble_svc_gap_init();
  ble_svc_gatt_init();
  ble_gatts_count_cfg(SERVICES);
  ble_gatts_add_svcs(SERVICES);
  ble_svc_gap_device_name_set(device_name);
  ble_npl_callout_init(&retry, nimble_port_get_dflt_eventq(), on_retry, NULL);
  printf("BLE|nimble|heap_used=%u\n", (unsigned) (before - heap_caps_get_free_size(MALLOC_CAP_8BIT)));

  nimble_port_freertos_init(host_task);
  return 0;
}
