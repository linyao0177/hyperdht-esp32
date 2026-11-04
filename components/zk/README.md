# zk

Groth16 proof verification on alt_bn128 (the curve of circom/snarkjs and the EVM precompiles), and the camera event format that uses it. It runs on the ESP32-C3 without hardware help. [`examples/uart_module`](../../examples/uart_module) uses it to check events as they arrive on a link (`AT+ZKROOT`, [docs/module-uart.md](../../docs/module-uart.md#camera-events-with-proofs)).

| File | |
|---|---|
| [`include/g16.h`](include/g16.h), [`g16.c`](g16.c) | `g16_init`, `g16_vk_load`, `g16_verify`. Proofs, keys and public inputs use the EVM calldata encoding (32-byte big-endian field elements, Fp2 imaginary part first), so `snarkjs zkey export soliditycalldata` output works as is |
| [`g16_poseidon.c`](g16_poseidon.c), [`poseidon_t6.h`](poseidon_t6.h) | circomlib's Poseidon of 5 inputs, which the event hash uses |
| [`include/zk_event.h`](include/zk_event.h), [`zk_event.c`](zk_event.c) | event_v2: parse the JSON message, compute M from its fields, verify the proof against `[root, M]` |
| [`mcl/`](mcl) | The parts of [herumi/mcl](https://github.com/herumi/mcl) (BSD-3-Clause) that `src/fp.cpp` needs, with one fix for riscv32 ([`mcl/VENDORED.txt`](mcl/VENDORED.txt)) |
| [`gen/`](gen) | `vk_header.py` turns a snarkjs `verification_key.json` into the C array `g16_vk_load` reads. `gen_poseidon.mjs` regenerates `poseidon_t6.h` from circomlibjs |
| [`test/`](test) | `./run.sh` builds and runs the test on the computer |

## event_v2

A camera sends each event as one JSON object:

```json
{"seq":3,"t":1793720788109,"ev":"person","conf":0.872,"box":[0,80,64,128],"zk":"<256 bytes as hex>"}
```

`zk` proves that a device registered in a Poseidon Merkle tree (depth 16) signed the event, without saying which device. The proof has two public inputs:

- the tree's root, which the verifier is configured with;
- M = Poseidon(seq, t, ev, conf, x | y << 16 | w << 32 | h << 48), which the verifier computes from the message itself. `ev` is 0 for motion, 1 for person, 2 for motion_end, and `conf` is in permille.

A proof therefore fits only the fields it came with: a change to any one of them makes it fail. The parser is strict about anything that could make two readers see different fields:
- `conf` must have at most 3 non-zero decimals and no exponent. It is read as text, so 0.872 is 872 exactly.
- Integers must have no sign, fraction or leading zero.
- Each of the six keys must appear exactly once.
- Strings must not contain escapes.

Other keys are skipped. The circuit and the prover are on the camera side (reCamera).

Replays are the caller's job. M covers seq and t, so different events never share an M. A verifier can reject events whose `t` is far from its clock, and remember the M values it accepted within that window. `examples/uart_module/main/zk.c` does both.

## Cost on the ESP32-C3 (160 MHz)

| | |
|---|---|
| Verify one event | 1.24 s: M (Poseidon) 74 ms, the proof 1.14 s. Most of the rest is the G2 subgroup check on B (166 ms), one Miller loop for three pairs, and one final exponentiation |
| Start | `g16_init` 1.2 s, `g16_vk_load` 1.3 s (computes e(alpha, beta) once) |
| RAM | about 22 KB of stack while verifying, no heap. 25 KB of static RAM: 13 KB of Poseidon constants and mcl's own tables. About 2 KB for a loaded key |
| Flash | about 145 KB |

The camera needs about 2.2 s to make a proof, so one C3 keeps up with a camera.

## Settings

mcl builds from the single file `mcl/src/fp.cpp` with `MCL_STANDALONE MCL_SIZEOF_UNIT=4 MCL_FP_BIT=256 MCL_FR_BIT=256 MCL_BINT_ASM=0 MCL_DONT_USE_XBYAK`, without exceptions or RTTI. These definitions are public in `CMakeLists.txt`, because every file that includes `mcl/bn.h` must use the same ones. `g16_init` turns on mcl's G2 subgroup check: a B outside the group is refused as malformed, not just as invalid.

MIRACL Core, the other small pairing library, cannot be used here. Its BN254 multiplies Fp2 by 2^k + i, while alt_bn128 needs 9 + i.
