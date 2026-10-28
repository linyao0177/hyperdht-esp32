#!/usr/bin/env python
"""Reset the board and print its serial output until a `*|done` line or timeout.

Usage: python tools/capture.py /dev/cu.usbmodem21101 [timeout_s] [log_file]
Run with the ESP-IDF python env (it ships pyserial).
"""

import sys
import time

import serial

port = sys.argv[1]
timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 120
log_path = sys.argv[3] if len(sys.argv) > 3 else None

ser = serial.Serial(port, 115200, timeout=0.5)

# Same reset sequence esptool uses for the USB-Serial-JTAG port.
ser.dtr = False
ser.rts = True
time.sleep(0.1)
ser.rts = False
time.sleep(0.05)

log = open(log_path, "w") if log_path else None
deadline = time.time() + timeout
buf = b""

while time.time() < deadline:
    chunk = ser.read(4096)
    if not chunk:
        continue
    buf += chunk
    while b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        text = line.decode("utf-8", "replace").rstrip("\r")
        print(text, flush=True)
        if log:
            log.write(text + "\n")
            log.flush()
        if text.startswith("POC|done") or text.startswith("HDHT|done"):
            sys.exit(0)

print("capture: timed out", flush=True)
sys.exit(1)
