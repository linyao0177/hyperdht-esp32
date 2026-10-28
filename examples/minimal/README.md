# minimal: a device reachable by public key

The smallest useful integration of hyperdht-esp32, and the one to copy into your own project:

- **Persistent identity**: a random 32-byte seed is created on first boot and kept in NVS. The public key derived from it is the device's address on HyperDHT.
- **Server**: the device announces itself on the public HyperDHT and echoes whatever connected peers send.
- **Cross-task data**: a separate FreeRTOS task produces a reading every 5 s and hands it to the hdht loop with a FreeRTOS queue and `uv_async_send`. The loop then writes it to every connected peer. hdht is single-threaded, and this is the pattern for feeding it from the rest of your firmware.

## Run it

1. Copy `sdkconfig.wifi.example` to `sdkconfig.wifi` at the repo root and fill in a 2.4 GHz network.

2. Build, flash and watch the output:

   ```bash
   idf.py build flash monitor
   ```

3. Wait for the line after `listening`, which is the device's public key in hex.

4. Connect from any computer with Node.js:

   ```bash
   npm install hyperdht
   ```

   ```js
   const DHT = require('hyperdht')
   const node = new DHT()
   const socket = node.connect(Buffer.from('<device public key>', 'hex'))
   socket.on('open', () => socket.write('hello'))
   socket.on('data', (data) => console.log(data.toString()))
   ```

You should see `hello` echoed back, then a `uptime=… free_heap=…` line every 5 seconds. This works from anywhere, not just your LAN.

Tested 2026-10-28 on the public HyperDHT: 32 nodes after bootstrap, the client opened in ~3.5 s, and the echo and pushed readings arrived as expected.
