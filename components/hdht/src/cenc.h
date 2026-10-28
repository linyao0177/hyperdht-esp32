// compact-encoding primitives (github.com/holepunchto/compact-encoding).
//
// Encoding writes into a caller-sized buffer; decoding reads from a bounded
// view. Both set `err` instead of returning per call, so a message can be
// encoded or decoded field by field and checked once at the end.

#ifndef HDHT_CENC_H
#define HDHT_CENC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  uint8_t *buf; // NULL while measuring (preencode)
  size_t len;   // capacity when encoding
  size_t pos;
  bool err;
} cenc_t;

typedef struct {
  const uint8_t *buf;
  size_t len;
  size_t pos;
  bool err;
} cdec_t;

// IPv4 address in network order as text "a.b.c.d" is never used on the wire;
// ip[0] is the first dotted octet.
typedef struct {
  uint8_t ip[4];
  uint16_t port;
} hdht_addr_t;

typedef struct {
  const uint8_t *data;
  size_t len;
} cenc_bytes_t;

static inline void
cenc_init (cenc_t *e, uint8_t *buf, size_t len) {
  e->buf = buf;
  e->len = len;
  e->pos = 0;
  e->err = false;
}

static inline void
cdec_init (cdec_t *d, const uint8_t *buf, size_t len) {
  d->buf = buf;
  d->len = len;
  d->pos = 0;
  d->err = false;
}

static inline bool
cdec_more (const cdec_t *d) {
  return !d->err && d->pos < d->len;
}

// encode

static inline void
cenc_raw (cenc_t *e, const void *data, size_t n) {
  if (e->err) return;
  if (e->buf != NULL) {
    if (e->pos + n > e->len) {
      e->err = true;
      return;
    }
    if (n) memcpy(e->buf + e->pos, data, n);
  }
  e->pos += n;
}

static inline void
cenc_u8 (cenc_t *e, uint8_t v) {
  cenc_raw(e, &v, 1);
}

static inline void
cenc_u16 (cenc_t *e, uint16_t v) {
  uint8_t b[2] = {(uint8_t) v, (uint8_t) (v >> 8)};
  cenc_raw(e, b, 2);
}

static inline void
cenc_u24 (cenc_t *e, uint32_t v) {
  uint8_t b[3] = {(uint8_t) v, (uint8_t) (v >> 8), (uint8_t) (v >> 16)};
  cenc_raw(e, b, 3);
}

static inline void
cenc_u32 (cenc_t *e, uint32_t v) {
  uint8_t b[4] = {(uint8_t) v, (uint8_t) (v >> 8), (uint8_t) (v >> 16), (uint8_t) (v >> 24)};
  cenc_raw(e, b, 4);
}

static inline void
cenc_uint (cenc_t *e, uint64_t v) {
  if (v <= 0xfc) {
    cenc_u8(e, (uint8_t) v);
  } else if (v <= 0xffff) {
    cenc_u8(e, 0xfd);
    cenc_u16(e, (uint16_t) v);
  } else if (v <= 0xffffffff) {
    cenc_u8(e, 0xfe);
    cenc_u32(e, (uint32_t) v);
  } else {
    cenc_u8(e, 0xff);
    cenc_u32(e, (uint32_t) v);
    cenc_u32(e, (uint32_t) (v >> 32));
  }
}

static inline void
cenc_buffer (cenc_t *e, const void *data, size_t n) {
  cenc_uint(e, n);
  cenc_raw(e, data, n);
}

static inline void
cenc_fixed32 (cenc_t *e, const uint8_t v[32]) {
  cenc_raw(e, v, 32);
}

static inline void
cenc_addr (cenc_t *e, const hdht_addr_t *a) {
  cenc_raw(e, a->ip, 4);
  cenc_u16(e, a->port);
}

// decode

static inline const uint8_t *
cdec_raw (cdec_t *d, size_t n) {
  if (d->err || d->len - d->pos < n) {
    d->err = true;
    return NULL;
  }
  const uint8_t *p = d->buf + d->pos;
  d->pos += n;
  return p;
}

static inline uint8_t
cdec_u8 (cdec_t *d) {
  const uint8_t *p = cdec_raw(d, 1);
  return p ? p[0] : 0;
}

static inline uint16_t
cdec_u16 (cdec_t *d) {
  const uint8_t *p = cdec_raw(d, 2);
  return p ? (uint16_t) (p[0] | (p[1] << 8)) : 0;
}

static inline uint32_t
cdec_u24 (cdec_t *d) {
  const uint8_t *p = cdec_raw(d, 3);
  return p ? (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) : 0;
}

static inline uint32_t
cdec_u32 (cdec_t *d) {
  const uint8_t *p = cdec_raw(d, 4);
  return p ? (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24) : 0;
}

static inline uint64_t
cdec_uint (cdec_t *d) {
  uint8_t a = cdec_u8(d);
  if (a <= 0xfc) return a;
  if (a == 0xfd) return cdec_u16(d);
  if (a == 0xfe) return cdec_u32(d);
  uint64_t lo = cdec_u32(d);
  uint64_t hi = cdec_u32(d);
  return lo | (hi << 32);
}

// Decodes a uint that must fit in 32 bits; larger values set err.
static inline uint32_t
cdec_uint32 (cdec_t *d) {
  uint64_t v = cdec_uint(d);
  if (v > UINT32_MAX) d->err = true;
  return (uint32_t) v;
}

static inline cenc_bytes_t
cdec_buffer (cdec_t *d) {
  cenc_bytes_t b = {NULL, 0};
  uint64_t n = cdec_uint(d);
  if (d->err) return b;
  if (n > d->len - d->pos) {
    d->err = true;
    return b;
  }
  b.data = d->buf + d->pos;
  b.len = (size_t) n;
  d->pos += (size_t) n;
  return b;
}

static inline const uint8_t *
cdec_fixed32 (cdec_t *d) {
  return cdec_raw(d, 32);
}

static inline void
cdec_addr (cdec_t *d, hdht_addr_t *a) {
  const uint8_t *p = cdec_raw(d, 6);
  if (p == NULL) {
    memset(a, 0, sizeof(*a));
    return;
  }
  memcpy(a->ip, p, 4);
  a->port = (uint16_t) (p[4] | (p[5] << 8));
}

static inline bool
hdht_addr_eq (const hdht_addr_t *a, const hdht_addr_t *b) {
  return a->port == b->port && memcmp(a->ip, b->ip, 4) == 0;
}

#endif
