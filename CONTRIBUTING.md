# Contributing

Thanks for helping. This repository is HyperDHT in C for the ESP32-C3 and what is built directly on it:

| Part | Where | Tests |
| --- | --- | --- |
| HyperDHT, UDX, the libuv subset | `components/hdht`, `components/libudx`, `components/uv_esp` | `test_vectors` and the desktop interop programs ([components/hdht/README.md](components/hdht/README.md#desktop-build-and-tests)) |
| BLE, credentials, OTA, MQTT over HyperDHT, zk | `components/hdht_ble`, `hdht_cred`, `hdht_ota`, `hdht_mqtt`, `zk` | the desktop tests in each component's `test/`; on a board, the examples |
| Firmware | `examples/` (ESP-IDF 5.5) | `idf.py build`; `tools/module_test.py` and `tools/module_mqtt_test.py` for `uart_module` |
| BoAT MER and WDK | `packages/boat-peer`, `boat-ota`, `wdk-protocol-boat-*`, `apps/pear-seller` | `npm test` in each |

The network built on this (nodes, contracts, `boat_device`, the site) is [xid-network](https://github.com/linyao0177/xid-network); its issues and pull requests go there. Some tools here (`tools/module_mqtt_test.py`, `tools/host/mqtt-peer.mjs`) run its MQTT node from a checkout of xid-network next to this one.

## Before you send a pull request

- Run the tests of what you touched. If a change touches a wire format, regenerate the vectors with `tools/host/gen-vectors.js` and say so.
- One change per pull request, with what it changes and how you tested it (on a board, on a desktop).
- Never commit `sdkconfig`, `sdkconfig.wifi`, key files (`*.key`, `seed`, `*.pem`) or anything with a password in it. `.gitignore` covers the usual ones.
- Code style: what the file around it does. C follows ESP-IDF's; JavaScript is [standard](https://standardjs.com) style without a build step.

## Good first contributions

- Other ESP32 targets (S3, C6) for `components/hdht`.
- Smaller and faster crypto paths (an IRAM BLAKE2b, fixed-point BBR).
- Public relay nodes ([docs/relay-node.md](docs/relay-node.md)).
- Missing hyperdht features (see Limitations in the README).

## Questions and bugs

Open an issue with what you ran, what you expected and what happened, with the board, the ESP-IDF version and the console output. Leave out keys, seeds and Wi-Fi passwords.

Security problems: see [SECURITY.md](SECURITY.md), not an issue.

## License

By contributing you agree that your contribution is licensed under the license of the part you change: MIT for the repository (see [LICENSE](LICENSE)), Apache-2.0 for the packages whose `package.json` says so.
