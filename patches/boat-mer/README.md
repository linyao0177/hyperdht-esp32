# BoAT MER patches

Against [BoAT MER](https://github.com/TLAY-IO/boat-mer) v1.0.1, for upstream.

| Patch | |
|---|---|
| [0001](0001-fix-pay-sign-under-a-per-call-EIP-712-domain-not-the.patch) | Sign under a per-call EIP-712 domain. `boat_nano_sign`, the x402 client and attestation's x402 path set one global domain separator and then signed with it, so a device whose buyer, anchoring and x402 run on different tasks could sign under the wrong domain. Adds `boat_pay_authorize_ext` and `tests/test_domain_race.c`: two threads signing under two domains got 1 of 800 signatures wrong in each of 3 runs before, 0 in 5 runs after. MER's own tests pass unchanged (5 and 23). On the board, the buyer, anchoring, x402 and the device signer then ran together without a wrong signature |
| [0002](0002-feat-buyer-session-settlement-one-transfer-per-payin.patch) | Session settlement: with `BOAT_NANO_OFFER_SESSION_SETTLE` in the offer's flags (the first reserved byte), every slice of a session carries one nonce and validity and the buyer signs the running total, so the seller settles one authorization per session instead of one per slice. A changed nonce or validity mid-session is refused; per-slice offers behave as before. `tests/test_buyer.c`: 34 of 34, 8 of them new. On the board with `apps/pear-seller --per-session`, 28 slices in 4 sessions became 4 transfers |

To build `examples/boat_mer` with a patch, clone boat-mer at v1.0.1, `git am` the patch, and point `main/idf_component.yml` at the checkout:

```yaml
dependencies:
  boat-mer:
    override_path: /path/to/boat-mer
```
