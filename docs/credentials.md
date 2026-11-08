# Manufacturer credentials

Any key can join the DHT and call itself a meter. A credential says that a manufacturer made the device behind a given DID. It is a signature that anyone can check offline, with no registry or server to ask.

| Piece | Where |
|---|---|
| Format, issuing and verifying | [`tools/host/credential.js`](../tools/host/credential.js) |
| The manufacturer's tool | [`tools/host/issuer.js`](../tools/host/issuer.js): `init`, `issue`, `revoke`, `verify` |
| A device that accepts credentials from one issuer | [`examples/app_template`](../examples/app_template) (`CONFIG_APP_ISSUER`) |
| A module whose host provisions it | [`examples/uart_module`](../examples/uart_module) (`AT+CRED`, optionally `CONFIG_MODULE_ISSUER`) |
| Checking a device from an app | `node tools/host/app-peer.js resolve <did> --issuer <issuer did>` |

## Formats

**Issuer**: an Ed25519 key pair kept by the manufacturer. Its DID is `did:mw:<public key>`. The issuer publishes a signed record under its key:

```json
{"v":1,"did":"did:mw:9a12...","name":"Test Manufacturer","revoked":["e049f585f1306a45"]}
```

**Credential**: the issuer's Ed25519 signature over this text:

```
hdht-credential/1 <id> <issuer key hex> <device key hex> <iat> <model>
```

The model is 1–32 characters of `A-Z a-z 0-9 space . _ -`. It goes last, so it may contain spaces. The `id` is 8 random bytes. `iat` is the time of issue in Unix seconds. As JSON:

```json
{"v":1,"id":"63590727e6aeffe2","iss":"did:mw:9a12...","sub":"did:mw:2ced...","iat":1793269310,"model":"meter X1","sig":"<128 hex>"}
```

**Where it lives**: in the `cred` field of the device's own DID record. Anyone who resolves the device sees it, and the device can be offline while they check.

## Verifying

A verifier, for example an app, a gateway or a buyer of the device's data, keeps a list of issuers it trusts. For a device DID, it:

1. resolves the device's record (signed by the device's key) and reads `cred`;
2. checks that `sub` is that DID and that the signature verifies against `iss`;
3. checks that `iss` is on its trust list;
4. resolves the issuer's record and checks that the `id` is not in `revoked`. If the issuer's record cannot be found, the result is "cannot check revocation", not valid.

`credential.verifyDevice(dht, did, trustedIssuers)` does all four.

## Provisioning

1. The device creates its key on first boot, as always. Nothing secret leaves it.
2. At the end of the production line, the factory reads the device's DID: from the serial log, `AT+ID?`, or a label.
3. The issuer signs a credential for that DID:

   ```bash
   node issuer.js issue did:mw:<device> "meter X1" --provision
   ```

4. The credential travels to the device:
   - **`app_template`** accepts it over HyperDHT from any peer (`--provision`). It keeps a credential only when the signature verifies against the issuer built into the firmware and is for its own key, so a forged or misdirected credential is refused.
   - **The UART module** gets it from its host as `AT+CRED=<id>,<issuer did>,<iat>,<model>,<signature>`. It checks the signature and that the credential is for itself (and the issuer, if `CONFIG_MODULE_ISSUER` is set). The host then includes the credential as `"cred"` in the record it publishes with `AT+PUT`.

The credential is not secret. Its value is only in the issuer's signature and its binding to the device's key.

## Revoking

```bash
node issuer.js revoke <credential id>
```

The command adds the id to the issuer's record and republishes it with a higher seq. Verifiers then see it as revoked the next time they read the issuer's record. A device whose credential was revoked can be given a new one, which replaces it.

## Results (2026-10-29, ESP32-C3 on the public HyperDHT)

| | Result |
|---|---|
| Before provisioning | `verify`: INVALID, no credential in the device record |
| Credential from another issuer | Refused by the device: "not from the trusted issuer" |
| Credential issued for another device's key | Refused: "bad signature" (the device checks against its own key) |
| Genuine credential with the model changed from "meter X1" to "meter X9" | Refused: "bad signature" |
| Genuine credential | Accepted. The record was republished with `cred`, and `verify` returned VALID with the issuer's name |
| Trusting a different issuer | `verify --issuer <other>`: INVALID, issuer not trusted |
| Revoked | `verify`: INVALID, revoked |
| Reboot and reflash | The credential is still in NVS and in the republished record |
| New credential after revocation | Replaced the revoked one; `verify`: VALID |
| UART module | `AT+CRED` refused a tampered model and accepted the genuine credential. `AT+CRED?` returned it, the host published it in its record, and `issuer.js verify` returned VALID (in `tools/module_test.py`, 48 of 48) |

## Limits

- **A credential proves who signed it, not where the key is.** A device whose firmware or flash can be read leaks its key, and with it the credential's worth. Production devices need [key protection](key-protection.md).
- **Revocation lists are small.** One issuer record holds about 45 ids within the DHT's 1000-byte limit. A large fleet needs the list in an append-only log (Hypercore) named in the issuer record, or one record per batch.
- **Revocation needs the issuer's record.** A verifier that cannot resolve it should treat the device as unchecked, as `verifyDevice` does.
- **Devices check each other in C** with [`components/hdht_cred`](../components/hdht_cred) (the UART module's `AT+CHECK`). Its results matched JavaScript's for all seven cases of `tools/host/cred-fixture.js`, on a private testnet and the public HyperDHT.
- **Issuer keys need care.** `issuer.js` keeps the key in a file with mode 0600. A manufacturer would keep it offline or in a hardware security module, and could sign batch keys with it instead of using it on the line.
