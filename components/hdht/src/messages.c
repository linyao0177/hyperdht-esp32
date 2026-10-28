#include <string.h>

#include <sodium.h>

#include "messages.h"

static int
finish_enc (const cenc_t *e) {
  return e->err ? -1 : (int) e->pos;
}

static int
finish_dec (const cdec_t *d) {
  return d->err ? -1 : 0;
}

static void
enc_addrs (cenc_t *e, const hdht_addr_t *addrs, size_t n) {
  cenc_uint(e, n);
  for (size_t i = 0; i < n; i++) cenc_addr(e, &addrs[i]);
}

// Decodes an ipv4 array, keeping at most cap entries.
static uint8_t
dec_addrs (cdec_t *d, hdht_addr_t *addrs, size_t cap) {
  uint64_t n = cdec_uint(d);
  if (n > 0x100000) d->err = true;
  if (d->err) return 0;

  uint8_t kept = 0;
  for (uint64_t i = 0; i < n && !d->err; i++) {
    hdht_addr_t a;
    cdec_addr(d, &a);
    if (kept < cap) addrs[kept++] = a;
  }
  return kept;
}

// noise payload

int
hdht_noise_payload_encode (const hdht_noise_payload_t *m, uint8_t *out, size_t cap) {
  cenc_t e;
  cenc_init(&e, out, cap);

  uint32_t flags = 0;
  if (m->has_holepunch) flags |= 1;
  if (m->addresses4_len) flags |= 2;
  if (m->has_udx) flags |= 8;
  if (m->has_secret_stream) flags |= 16;
  if (m->has_relay_through) flags |= 32;
  if (m->has_relay_addresses) flags |= 64;

  cenc_uint(&e, 1); // version
  cenc_uint(&e, flags);
  cenc_uint(&e, m->error);
  cenc_uint(&e, m->firewall);

  if (m->has_holepunch) {
    cenc_uint(&e, m->holepunch_id);
    cenc_uint(&e, m->relays_len);
    for (size_t i = 0; i < m->relays_len; i++) {
      cenc_addr(&e, &m->relays[i].relay_address);
      cenc_addr(&e, &m->relays[i].peer_address);
    }
  }
  if (m->addresses4_len) enc_addrs(&e, m->addresses4, m->addresses4_len);
  if (m->has_udx) {
    cenc_uint(&e, 1); // version
    cenc_uint(&e, m->udx_reusable_socket ? 1 : 0);
    cenc_uint(&e, m->udx_id);
    cenc_uint(&e, m->udx_seq);
  }
  if (m->has_secret_stream) cenc_uint(&e, 1);
  if (m->has_relay_through) {
    cenc_uint(&e, 1);
    cenc_uint(&e, 0);
    cenc_fixed32(&e, m->relay_through_public_key);
    cenc_fixed32(&e, m->relay_through_token);
  }
  if (m->has_relay_addresses) enc_addrs(&e, m->relay_addresses, m->relay_addresses_len);

  return finish_enc(&e);
}

int
hdht_noise_payload_decode (hdht_noise_payload_t *m, const uint8_t *buf, size_t len) {
  cdec_t d;
  cdec_init(&d, buf, len);
  memset(m, 0, sizeof(*m));

  m->version = cdec_uint32(&d);
  if (d.err) return -1;
  if (m->version != 1) return 0; // caller reports the version mismatch

  uint32_t flags = cdec_uint32(&d);
  m->error = cdec_uint32(&d);
  m->firewall = cdec_uint32(&d);

  if (flags & 1) {
    m->has_holepunch = true;
    m->holepunch_id = cdec_uint32(&d);
    uint64_t n = cdec_uint(&d);
    if (n > 0x100000) d.err = true;
    for (uint64_t i = 0; i < n && !d.err; i++) {
      hdht_relay_info_t r;
      cdec_addr(&d, &r.relay_address);
      cdec_addr(&d, &r.peer_address);
      if (m->relays_len < HDHT_MAX_RELAYS) m->relays[m->relays_len++] = r;
    }
  }
  if (flags & 2) m->addresses4_len = dec_addrs(&d, m->addresses4, HDHT_MAX_ADDRESSES);
  if (flags & 4) {
    uint64_t n = cdec_uint(&d); // ipv6 addresses are skipped
    if (n > 0x100000) d.err = true;
    for (uint64_t i = 0; i < n && !d.err; i++) cdec_raw(&d, 18);
  }
  if (flags & 8) {
    m->has_udx = true;
    cdec_uint(&d); // version
    m->udx_reusable_socket = (cdec_uint(&d) & 1) != 0;
    m->udx_id = cdec_uint32(&d);
    m->udx_seq = cdec_uint32(&d);
  }
  if (flags & 16) {
    m->has_secret_stream = true;
    cdec_uint(&d);
  }
  if (flags & 32) {
    m->has_relay_through = true;
    cdec_uint(&d);
    cdec_uint(&d);
    const uint8_t *pk = cdec_fixed32(&d);
    const uint8_t *tok = cdec_fixed32(&d);
    if (pk) memcpy(m->relay_through_public_key, pk, 32);
    if (tok) memcpy(m->relay_through_token, tok, 32);
  }
  if (flags & 64) {
    m->has_relay_addresses = true;
    m->relay_addresses_len = dec_addrs(&d, m->relay_addresses, HDHT_MAX_RELAYS);
  }

  return finish_dec(&d);
}

// handshake

int
hdht_handshake_encode (const hdht_handshake_msg_t *m, uint8_t *out, size_t cap) {
  cenc_t e;
  cenc_init(&e, out, cap);

  cenc_uint(&e, (m->has_peer_address ? 1 : 0) | (m->has_relay_address ? 2 : 0));
  cenc_uint(&e, m->mode);
  cenc_buffer(&e, m->noise, m->noise_len);
  if (m->has_peer_address) cenc_addr(&e, &m->peer_address);
  if (m->has_relay_address) cenc_addr(&e, &m->relay_address);

  return finish_enc(&e);
}

int
hdht_handshake_decode (hdht_handshake_msg_t *m, const uint8_t *buf, size_t len) {
  cdec_t d;
  cdec_init(&d, buf, len);
  memset(m, 0, sizeof(*m));

  uint32_t flags = cdec_uint32(&d);
  m->mode = cdec_uint32(&d);
  cenc_bytes_t noise = cdec_buffer(&d);
  m->noise = noise.data;
  m->noise_len = noise.len;
  if (flags & 1) {
    m->has_peer_address = true;
    cdec_addr(&d, &m->peer_address);
  }
  if (flags & 2) {
    m->has_relay_address = true;
    cdec_addr(&d, &m->relay_address);
  }

  return finish_dec(&d);
}

// holepunch

int
hdht_holepunch_encode (const hdht_holepunch_msg_t *m, uint8_t *out, size_t cap) {
  cenc_t e;
  cenc_init(&e, out, cap);

  cenc_uint(&e, m->has_peer_address ? 1 : 0);
  cenc_uint(&e, m->mode);
  cenc_uint(&e, m->id);
  cenc_buffer(&e, m->payload, m->payload_len);
  if (m->has_peer_address) cenc_addr(&e, &m->peer_address);

  return finish_enc(&e);
}

int
hdht_holepunch_decode (hdht_holepunch_msg_t *m, const uint8_t *buf, size_t len) {
  cdec_t d;
  cdec_init(&d, buf, len);
  memset(m, 0, sizeof(*m));

  uint32_t flags = cdec_uint32(&d);
  m->mode = cdec_uint32(&d);
  m->id = cdec_uint32(&d);
  cenc_bytes_t payload = cdec_buffer(&d);
  m->payload = payload.data;
  m->payload_len = payload.len;
  if (flags & 1) {
    m->has_peer_address = true;
    cdec_addr(&d, &m->peer_address);
  }

  return finish_dec(&d);
}

// holepunch payload

int
hdht_holepunch_payload_encode (const hdht_holepunch_payload_t *m, uint8_t *out, size_t cap) {
  cenc_t e;
  cenc_init(&e, out, cap);

  uint32_t flags = (m->connected ? 1 : 0) |
                   (m->punching ? 2 : 0) |
                   (m->has_addresses ? 4 : 0) |
                   (m->has_remote_address ? 8 : 0) |
                   (m->has_token ? 16 : 0) |
                   (m->has_remote_token ? 32 : 0);

  cenc_uint(&e, flags);
  cenc_uint(&e, m->error);
  cenc_uint(&e, m->firewall);
  cenc_uint(&e, m->round);
  if (m->has_addresses) enc_addrs(&e, m->addresses, m->addresses_len);
  if (m->has_remote_address) cenc_addr(&e, &m->remote_address);
  if (m->has_token) cenc_fixed32(&e, m->token);
  if (m->has_remote_token) cenc_fixed32(&e, m->remote_token);

  return finish_enc(&e);
}

int
hdht_holepunch_payload_decode (hdht_holepunch_payload_t *m, const uint8_t *buf, size_t len) {
  cdec_t d;
  cdec_init(&d, buf, len);
  memset(m, 0, sizeof(*m));

  uint32_t flags = cdec_uint32(&d);
  m->error = cdec_uint32(&d);
  m->firewall = cdec_uint32(&d);
  m->round = cdec_uint32(&d);
  m->connected = (flags & 1) != 0;
  m->punching = (flags & 2) != 0;
  if (flags & 4) {
    m->has_addresses = true;
    m->addresses_len = dec_addrs(&d, m->addresses, HDHT_MAX_ADDRESSES);
  }
  if (flags & 8) {
    m->has_remote_address = true;
    cdec_addr(&d, &m->remote_address);
  }
  if (flags & 16) {
    const uint8_t *t = cdec_fixed32(&d);
    if (t) {
      m->has_token = true;
      memcpy(m->token, t, 32);
    }
  }
  if (flags & 32) {
    const uint8_t *t = cdec_fixed32(&d);
    if (t) {
      m->has_remote_token = true;
      memcpy(m->remote_token, t, 32);
    }
  }

  return finish_dec(&d);
}

int
hdht_holepunch_payload_seal (const hdht_holepunch_payload_t *m, const uint8_t secret[32], uint8_t *out, size_t cap) {
  if (cap < 24 + 16) return -1;

  uint8_t *nonce = out;
  uint8_t *plain = out + 24 + 16;
  int n = hdht_holepunch_payload_encode(m, plain, cap - 24 - 16);
  if (n < 0) return -1;

  randombytes_buf(nonce, 24);
  // in place: ciphertext (MAC first) starts 16 bytes before the plaintext
  crypto_secretbox_easy(out + 24, plain, (unsigned long long) n, nonce, secret);
  return 24 + 16 + n;
}

int
hdht_holepunch_payload_open (hdht_holepunch_payload_t *m, const uint8_t secret[32], const uint8_t *buf, size_t len) {
  uint8_t plain[256];

  if (len <= 24 + 16 || len - 24 - 16 > sizeof(plain)) return -1;
  if (crypto_secretbox_open_easy(plain, buf + 24, len - 24, buf, secret) != 0) return -1;

  return hdht_holepunch_payload_decode(m, plain, len - 24 - 16);
}

// peer

int
hdht_peer_encode (const hdht_peer_t *m, uint8_t *out, size_t cap) {
  cenc_t e;
  cenc_init(&e, out, cap);
  cenc_fixed32(&e, m->public_key);
  enc_addrs(&e, m->relay_addresses, m->relay_addresses_len);
  return finish_enc(&e);
}

int
hdht_peer_decode (hdht_peer_t *m, const uint8_t *buf, size_t len) {
  cdec_t d;
  cdec_init(&d, buf, len);
  memset(m, 0, sizeof(*m));

  const uint8_t *pk = cdec_fixed32(&d);
  if (pk) memcpy(m->public_key, pk, 32);
  m->relay_addresses_len = dec_addrs(&d, m->relay_addresses, HDHT_MAX_RELAYS);

  return finish_dec(&d);
}

// announce

int
hdht_announce_encode_signed (uint8_t *out, size_t cap, const uint8_t ns[32], const uint8_t target[32], const uint8_t node_id[32], const uint8_t token[32], const uint8_t public_key[32], const uint8_t secret_key[64]) {
  hdht_peer_t peer = {0};
  memcpy(peer.public_key, public_key, 32);

  uint8_t peer_buf[64];
  int peer_len = hdht_peer_encode(&peer, peer_buf, sizeof(peer_buf));
  if (peer_len < 0) return -1;

  // signable = ns || BLAKE2b-256(target || node id || token || peer || refresh)
  uint8_t signable[64];
  memcpy(signable, ns, 32);

  crypto_generichash_state st;
  crypto_generichash_init(&st, NULL, 0, 32);
  crypto_generichash_update(&st, target, 32);
  crypto_generichash_update(&st, node_id, 32);
  crypto_generichash_update(&st, token, 32);
  crypto_generichash_update(&st, peer_buf, (size_t) peer_len);
  crypto_generichash_final(&st, signable + 32, 32);

  uint8_t signature[64];
  crypto_sign_detached(signature, NULL, signable, sizeof(signable), secret_key);

  cenc_t e;
  cenc_init(&e, out, cap);
  cenc_uint(&e, 1 | 4); // peer + signature
  cenc_raw(&e, peer_buf, (size_t) peer_len);
  cenc_raw(&e, signature, 64);
  return finish_enc(&e);
}
