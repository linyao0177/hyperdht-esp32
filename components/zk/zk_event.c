#include <string.h>

#include "zk_event.h"

// a strict reader for one flat JSON object

typedef struct {
  const char *p, *end;
} rd_t;

static void
ws (rd_t *r) {
  while (r->p < r->end && (*r->p == ' ' || *r->p == '\t' || *r->p == '\n' || *r->p == '\r')) r->p++;
}

static int
eat (rd_t *r, char c) {
  ws(r);
  if (r->p >= r->end || *r->p != c) return -1;
  r->p++;
  return 0;
}

// a string without escapes; *s and *n point into the input
static int
str (rd_t *r, const char **s, size_t *n) {
  if (eat(r, '"')) return -1;
  *s = r->p;
  while (r->p < r->end && *r->p != '"') {
    if (*r->p == '\\' || (unsigned char) *r->p < 0x20) return -1;
    r->p++;
  }
  if (r->p >= r->end) return -1;
  *n = (size_t) (r->p - *s);
  r->p++;
  return 0;
}

// digits only, no sign, fraction or exponent
static int
num (rd_t *r, uint64_t *v, uint64_t max) {
  ws(r);
  const char *s = r->p;
  *v = 0;
  while (r->p < r->end && *r->p >= '0' && *r->p <= '9') {
    uint64_t d = (uint64_t) (*r->p - '0');
    if (*v > (max - d) / 10) return -1;
    *v = *v * 10 + d;
    r->p++;
  }
  size_t n = (size_t) (r->p - s);
  if (n == 0 || (n > 1 && *s == '0')) return -1;
  if (r->p < r->end && (*r->p == '.' || *r->p == 'e' || *r->p == 'E')) return -1;
  return 0;
}

// 0 to 1 with at most 3 decimals that are not zero, as permille: the text,
// not a float, so 0.872 is 872 exactly
static int
permille (rd_t *r, uint16_t *v) {
  ws(r);
  if (r->p >= r->end || (*r->p != '0' && *r->p != '1')) return -1;
  unsigned whole = (unsigned) (*r->p++ - '0'), frac = 0;
  int digits = 0;
  if (r->p < r->end && *r->p == '.') {
    r->p++;
    const char *s = r->p;
    for (; r->p < r->end && *r->p >= '0' && *r->p <= '9'; r->p++, digits++) {
      if (digits < 3) frac = frac * 10 + (unsigned) (*r->p - '0');
      else if (*r->p != '0') return -1;
    }
    if (r->p == s) return -1;
  }
  for (; digits < 3; digits++) frac *= 10;
  if (r->p < r->end && (*r->p == 'e' || *r->p == 'E' || (*r->p >= '0' && *r->p <= '9'))) return -1;
  unsigned pm = whole * 1000 + frac;
  if (pm > 1000) return -1;
  *v = (uint16_t) pm;
  return 0;
}

// any value, for keys we do not use
static int
skip (rd_t *r) {
  ws(r);
  if (r->p >= r->end || !*r->p || !strchr("\"{[-0123456789tfn", *r->p)) return -1;
  int depth = 0;
  do {
    if (r->p >= r->end) return -1;
    char c = *r->p++;
    if (c == '"') {
      while (r->p < r->end && *r->p != '"') r->p += *r->p == '\\' ? 2 : 1;
      if (r->p >= r->end) return -1;
      r->p++;
    } else if (c == '{' || c == '[') {
      depth++;
    } else if (c == '}' || c == ']') {
      if (--depth < 0) return -1;
    } else if (depth == 0) {
      // a number, true, false or null: up to the next delimiter
      while (r->p < r->end && *r->p && !strchr(",}] \t\r\n", *r->p)) r->p++;
    }
  } while (depth > 0);
  return 0;
}

static int
hexval (char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static const struct {
  const char *name;
  uint8_t id;
} ev_names[] = {{"motion", 0}, {"person", 1}, {"motion_end", 2}};

static int
key_is (const char *k, size_t n, const char *name) {
  return strlen(name) == n && memcmp(k, name, n) == 0;
}

int
zk_event_parse (zk_event_t *e, const char *json, size_t len) {
  // most messages are not events: look for the key before parsing
  int has_zk = 0;
  for (size_t i = 0; i + 4 <= len && !has_zk; i++) has_zk = memcmp(json + i, "\"zk\"", 4) == 0;
  if (!has_zk) return 1;

  memset(e, 0, sizeof(*e));
  rd_t r = {json, json + len};
  unsigned seen = 0; // a bit per key, in the order below
  if (eat(&r, '{')) return -1;
  ws(&r);
  if (r.p < r.end && *r.p == '}') return -1;
  for (;;) {
    const char *k, *s;
    size_t kn, n;
    uint64_t v;
    unsigned bit;
    if (str(&r, &k, &kn) || eat(&r, ':')) return -1;
    if (key_is(k, kn, "seq")) {
      bit = 1;
      if (num(&r, &e->seq, UINT64_MAX)) return -1;
    } else if (key_is(k, kn, "t")) {
      bit = 2;
      if (num(&r, &e->t_ms, UINT64_MAX)) return -1;
    } else if (key_is(k, kn, "ev")) {
      bit = 4;
      if (str(&r, &s, &n)) return -1;
      size_t i = 0;
      while (i < sizeof(ev_names) / sizeof(ev_names[0]) && !key_is(s, n, ev_names[i].name)) i++;
      if (i == sizeof(ev_names) / sizeof(ev_names[0])) return -1;
      e->ev = ev_names[i].id;
    } else if (key_is(k, kn, "conf")) {
      bit = 8;
      if (permille(&r, &e->conf)) return -1;
    } else if (key_is(k, kn, "box")) {
      bit = 16;
      if (eat(&r, '[')) return -1;
      for (int i = 0; i < 4; i++) {
        if ((i && eat(&r, ',')) || num(&r, &v, UINT16_MAX)) return -1;
        e->box[i] = (uint16_t) v;
      }
      if (eat(&r, ']')) return -1;
    } else if (key_is(k, kn, "zk")) {
      bit = 32;
      if (str(&r, &s, &n) || n != 2 * G16_PROOF_LEN) return -1;
      for (size_t i = 0; i < G16_PROOF_LEN; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        e->proof[i] = (uint8_t) (hi << 4 | lo);
      }
    } else {
      bit = 0;
      if (skip(&r)) return -1;
    }
    if (seen & bit) return -1; // twice
    seen |= bit;
    ws(&r);
    if (r.p < r.end && *r.p == ',') {
      r.p++;
      continue;
    }
    if (eat(&r, '}')) return -1;
    break;
  }
  ws(&r);
  if (r.p != r.end || seen != 63) return -1;
  return 0;
}

void
zk_event_hash (uint8_t m[32], const zk_event_t *e) {
  g16_event_hash(m, e->seq, e->t_ms, e->ev, e->conf, e->box);
}

int
zk_event_verify (const g16_vk_t *vk, const uint8_t root[32], const uint8_t m[32], const zk_event_t *e) {
  uint8_t pub[2][32];
  memcpy(pub[0], root, 32);
  memcpy(pub[1], m, 32);
  return g16_verify(vk, e->proof, (const uint8_t (*)[32]) pub, 2);
}

int
zk_fr_ok (const uint8_t be[32]) {
  static const uint8_t r[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
  };
  return memcmp(be, r, 32) < 0;
}
