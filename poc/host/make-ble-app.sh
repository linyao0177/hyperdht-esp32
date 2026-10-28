#!/bin/sh
# Wraps ble-client.js in a minimal .app so macOS lets it use Bluetooth: TCC
# kills processes whose responsible app has no NSBluetoothAlwaysUsageDescription.
#
#   sh make-ble-app.sh <output dir>
#   open -W -n <output dir>/hdht-ble-client.app --args 0x33
#
# Output goes to <output dir>/ble-client.log. The first run shows a Bluetooth
# permission prompt.

set -e
OUT="${1:?output dir}"
HERE="$(cd "$(dirname "$0")" && pwd)"
NODE="$(command -v node)"
APP="$OUT/hdht-ble-client.app"

mkdir -p "$APP/Contents/MacOS"
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>local.hdht.ble-client</string>
  <key>CFBundleName</key><string>hdht BLE client</string>
  <key>CFBundleExecutable</key><string>run</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSUIElement</key><true/>
  <key>NSBluetoothAlwaysUsageDescription</key><string>Connects to the ESP32-C3 test device over Bluetooth LE.</string>
</dict>
</plist>
EOF
cat > "$APP/Contents/MacOS/run" <<EOF
#!/bin/sh
cd "$HERE"
exec "$NODE" "$HERE/ble-client.js" "\$@" > "$OUT/ble-client.log" 2>&1
EOF
chmod +x "$APP/Contents/MacOS/run"
codesign --force -s - "$APP" 2>/dev/null || true
echo "$APP"
