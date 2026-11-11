# Release builds

`uart_module`'s released image: one file for the whole flash, written at 0x0, and an [ESP Web Tools](https://esphome.github.io/esp-web-tools/) manifest for installing it from a browser.

```bash
. ~/esp/esp-idf/export.sh
tools/release/build-firmware.sh            # dist/firmware/uart_module-esp32c3-<version>.bin and uart_module.manifest.json
```

A release build (`BOAT_RELEASE=1`) merges `sdkconfig.release` instead of your `sdkconfig.wifi`, so the image carries no Wi-Fi network; the host sets one with `AT+WIFI`. The script checks that your network's name and password are not in the image.

[xid-network](https://github.com/linyao0177/xid-network) builds this image too (from its `third_party/hyperdht-esp32` submodule) and serves it at [iot.xid.network](https://iot.xid.network/docs/#download), with its own firmware and node packages.
