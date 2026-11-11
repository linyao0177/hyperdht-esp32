#!/usr/bin/env bash
# The released uart_module image for the ESP32-C3, to flash at 0x0
# (esptool, or the browser installer with the ESP Web Tools manifests made
# here). The images carry no Wi-Fi network: release builds take
# tools/release/sdkconfig.release instead of your sdkconfig.wifi.
#
#   . ~/esp/esp-idf/export.sh
#   tools/release/build-firmware.sh [out-dir]       (default dist/firmware)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-$ROOT/dist/firmware}
APPS="uart_module"
command -v idf.py >/dev/null || { echo "source ESP-IDF's export.sh first" >&2; exit 1; }
mkdir -p "$OUT"

for app in $APPS; do
  dir=$ROOT/examples/$app
  build=$dir/build-release
  rm -rf "$build"
  echo "== $app"
  (cd "$dir" && BOAT_RELEASE=1 idf.py -B "$build" -D SDKCONFIG="$build/sdkconfig" build >"$build.log" 2>&1) || { tail -30 "$build.log"; exit 1; }
  # no network in the image: the defaults are empty, and your own network's
  # name is nowhere in it (checked without printing it)
  grep -q '^CONFIG_EXAMPLE_WIFI_SSID=""' "$build/sdkconfig" || { echo "$app: release sdkconfig has a Wi-Fi network" >&2; exit 1; }
  ver=$(sed -n 's/^set(PROJECT_VER "\(.*\)")/\1/p' "$dir/CMakeLists.txt")
  bin=$OUT/$app-esp32c3-$ver.bin
  (cd "$build" && python -m esptool --chip esp32c3 merge_bin -o "$bin" @flash_args >/dev/null)
  if [ -f "$ROOT/sdkconfig.wifi" ]; then
    mine=$(sed -n 's/^CONFIG_EXAMPLE_WIFI_SSID="\(.*\)"/\1/p' "$ROOT/sdkconfig.wifi")
    if [ -n "$mine" ] && grep -qF -- "$mine" "$bin"; then echo "$app: your Wi-Fi network's name is in the image" >&2; rm -f "$bin"; exit 1; fi
    mine=$(sed -n 's/^CONFIG_EXAMPLE_WIFI_PASSWORD="\(.*\)"/\1/p' "$ROOT/sdkconfig.wifi")
    if [ -n "$mine" ] && grep -qF -- "$mine" "$bin"; then echo "$app: your Wi-Fi password is in the image" >&2; rm -f "$bin"; exit 1; fi
    unset mine
  fi
  # ESP Web Tools: https://esphome.github.io/esp-web-tools/
  cat > "$OUT/$app.manifest.json" <<JSON
{
  "name": "$app",
  "version": "$ver",
  "new_install_prompt_erase": true,
  "builds": [
    { "chipFamily": "ESP32-C3", "parts": [{ "path": "$(basename "$bin")", "offset": 0 }] }
  ]
}
JSON
  echo "$(basename "$bin") $(wc -c <"$bin" | tr -d ' ') bytes"
done
