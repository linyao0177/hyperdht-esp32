# hdht_cred

Manufacturer credentials ([docs/credentials.md](../../docs/credentials.md)), checked on the device. A device that must admit only genuine peers can now do what `tools/host/credential.js` `verifyDevice` does, in C:

1. read the peer's DID record and the credential in it (`cred`);
2. check that the credential is for that DID and that the issuer's Ed25519 signature verifies;
3. check that the issuer is one it trusts;
4. read the issuer's record and check that it does not revoke the credential.

```c
static hdht_cred_verify_t check;
static const uint8_t trusted[1][32] = {{ /* issuer key */ }};

static void
on_checked (hdht_cred_verify_t *v, int result, const hdht_cred_t *cred) {
  printf("%s %s\n", hdht_cred_reason(result), cred ? cred->model : "");
}

hdht_cred_verify_device(&check, &dht, peer_key, trusted, 1, on_checked, NULL);
```

| Result | |
|---|---|
| `HDHT_CRED_VALID` (0) | Genuine and not revoked |
| `HDHT_CRED_NO_RECORD`, `HDHT_CRED_NO_CRED` | The peer has no record, or no credential in it |
| `HDHT_CRED_MALFORMED`, `HDHT_CRED_OTHER_DEVICE`, `HDHT_CRED_BAD_SIGNATURE` | Not a credential for this peer |
| `HDHT_CRED_NOT_TRUSTED` | Signed by an issuer not on the list |
| `HDHT_CRED_ISSUER_UNKNOWN` | No issuer record, so revocation cannot be checked: treat the peer as unchecked |
| `HDHT_CRED_REVOKED` | The issuer revoked it |

`hdht_cred_parse`, `hdht_cred_check` and `hdht_cred_check_issuer_record` are the steps on their own, for a credential you already hold. The parser is strict: flat fields, no escapes, a lower-case hex id, and a model of 1–32 of `A-Z a-z 0-9 space . _ -`. On the UART module it is `AT+CHECK` ([docs/module-uart.md](../../docs/module-uart.md)).

## Tests

```bash
cmake -S components/hdht_cred -B build/cred && cmake --build build/cred --target test_cred
build/cred/test_cred                       # 16 checks, offline
```

Against a DHT, `tools/host/cred-fixture.js` publishes a device and an issuer for every result, and `test_cred <bootstrap | public> <device did> <issuer did> <expected>` checks one. On 2026-11-07 all 7 results matched, both on a private testnet and on the public HyperDHT.
