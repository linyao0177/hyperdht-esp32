// Bare has no global TextEncoder, which @noble/curves uses while it loads.
// Defined here only where it is missing, from b4a.

const b4a = require('b4a')

if (typeof globalThis.TextEncoder === 'undefined') {
  globalThis.TextEncoder = class TextEncoder {
    get encoding () { return 'utf-8' }
    encode (s = '') { return new Uint8Array(b4a.from(String(s), 'utf8')) }
  }
}
