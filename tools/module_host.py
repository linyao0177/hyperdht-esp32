#!/usr/bin/env python
"""A host for examples/uart_module: what a host MCU does, from a computer.

Usage:
  python tools/module_host.py <serial port>            interactive: type commands, see replies and events
  python tools/module_host.py <serial port> --reset    reset the module first

As a library (tools/module_test.py uses it):
  m = Module(port); m.reset(); m.wait_event('+READY')
  lines = m.command('AT+INFO')            # the +INFO line(s); raises ModuleError on ERROR
  ev = m.wait_event('+CONN', timeout=30)  # next event of a kind

The protocol is in docs/module-uart.md. Responses are the lines up to OK or
ERROR. Events are unsolicited lines starting with "+" that can arrive at any
time, even between a command's response lines. A host tells them apart by
name: a command's own result lines carry the command's name (AT+INFO ->
+INFO), and everything else is an event.

Run with the ESP-IDF python env (it ships pyserial).
"""

import queue
import sys
import threading
import time

import serial

# result lines a command answers with directly; anything else starting with
# "+" is an event
RESULTS = {
    'AT+INFO': '+INFO', 'AT+ID': '+ID', 'AT+WIFI': '+WIFI', 'AT+HASH': '+HASH',
    'AT+SIGN': '+SIGN', 'AT+SIGNT': '+SIGN', 'AT+VERIFY': '+VERIFY', 'AT+ALLOW': '+ALLOW',
    'AT+LINKS': '+LINK', 'AT+LISTEN': '+LISTEN', 'AT+CONNECT': '+CONNECT',
    'AT+PUT': '+RECORD', 'AT+PUTT': '+RECORD', 'AT+RELAY': '+RELAY', 'AT+ANNOUNCE': '+TOPIC', 'AT+CRED': '+CRED',
}


class ModuleError(Exception):
    pass


class Module:
    def __init__(self, port, log=None):
        self.ser = serial.Serial(port, 115200, timeout=0.2)
        self.log = log
        self.events = queue.Queue()
        self.replies = queue.Queue()
        self.expect = None  # the result prefix of the command in flight
        threading.Thread(target=self._read, daemon=True).start()

    def reset(self):
        # the reset esptool uses on the USB Serial/JTAG port
        self.ser.dtr = False
        self.ser.rts = True
        time.sleep(0.1)
        self.ser.rts = False

    def _read(self):
        buf = b''
        while True:
            try:
                buf += self.ser.read(256)
            except serial.SerialException:
                time.sleep(0.5)
                continue
            while b'\n' in buf:
                raw, buf = buf.split(b'\n', 1)
                line = raw.decode('utf-8', 'replace').rstrip('\r')
                if not line:
                    continue
                if self.log:
                    self.log(line)
                is_result = self.expect and line.startswith(self.expect + ':')
                if line == 'OK' or line.startswith('ERROR') or is_result:
                    self.replies.put(line)
                elif line.startswith('+'):
                    self.events.put(line)

    def command(self, cmd, timeout=10):
        name = cmd.split('=')[0].split('?')[0].upper()
        self.expect = RESULTS.get(name)
        self.ser.write((cmd + '\r\n').encode())
        lines = []
        deadline = time.time() + timeout
        try:
            while True:
                line = self.replies.get(timeout=max(0.01, deadline - time.time()))
                if line == 'OK':
                    return lines
                if line.startswith('ERROR'):
                    raise ModuleError(f'{cmd}: {line}')
                lines.append(line)
        except queue.Empty:
            raise ModuleError(f'{cmd}: no reply in {timeout} s')
        finally:
            self.expect = None

    def wait_event(self, prefix, timeout=30, match=None):
        """The next event starting with prefix (and passing match); others are kept."""
        deadline = time.time() + timeout
        skipped = []
        try:
            while True:
                line = self.events.get(timeout=max(0.01, deadline - time.time()))
                if line.startswith(prefix) and (match is None or match(line)):
                    return line
                skipped.append(line)
        except queue.Empty:
            raise ModuleError(f'no {prefix} event in {timeout} s')
        finally:
            for line in skipped:
                self.events.put(line)

    def drain(self):
        out = []
        while not self.events.empty():
            out.append(self.events.get())
        return out


def interactive(port, reset):
    m = Module(port, log=lambda line: print('< ' + line))
    if reset:
        m.reset()
    print('type AT commands; Ctrl-C to quit')
    try:
        for line in sys.stdin:
            line = line.strip()
            if line:
                m.ser.write((line + '\r\n').encode())
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    interactive(sys.argv[1], '--reset' in sys.argv)
