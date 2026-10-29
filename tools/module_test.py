#!/usr/bin/env python
"""End-to-end test of examples/uart_module: this computer plays the host MCU
over the serial port, and Node.js peers (tools/host/module-peer.js) play the
network.

Usage: python tools/module_test.py <serial port>
Run with the ESP-IDF python env (pyserial, cryptography) and after
`npm ci` in tools/host.
"""

import hashlib
import os
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, os.path.dirname(__file__))
from module_host import Module, ModuleError  # noqa: E402

HOST = os.path.join(os.path.dirname(__file__), 'host')
results = []


def check(name, ok, detail=''):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'} {name}{'  ' + detail if detail else ''}")


def peer(*args):
    """Starts module-peer.js; returns the process."""
    return subprocess.Popen(['node', 'module-peer.js', *args], cwd=HOST, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def peer_line(p, prefix, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = p.stdout.readline()
        if not line:
            break
        if line.startswith('PEER|' + prefix):
            return line.strip()[5:]
    return None


def connect(m, did, tries=2):
    """AT+CONNECT, retried once: a connect can fail on the public network, and
    a host sees that as +CLOSED for the link instead of +CONN."""
    for attempt in range(tries):
        t = time.time()
        link = m.command('AT+CONNECT=' + did)[0].split(':')[1]
        ev = m.wait_event(f'+C', timeout=90, match=lambda x: x.startswith(f'+CONN:{link},') or x.startswith(f'+CLOSED:{link},'))
        if ev.startswith('+CONN'):
            return link, ev, time.time() - t, attempt
        print(f'     connect attempt {attempt + 1} failed: {ev}')
    raise ModuleError('connect failed')


def errors_with(m, cmd):
    try:
        m.command(cmd)
        return None
    except ModuleError as e:
        return str(e).split(': ', 1)[1]


def main(port):
    m = Module(port)
    m.reset()
    t0 = time.time()
    boot = m.wait_event('+BOOT', timeout=15)
    net = m.wait_event('+NET:CONNECTED', timeout=30)
    ready = m.wait_event('+READY', timeout=60)
    did = boot.split(',')[1]
    check('boot, WiFi and DHT', ready.split(',')[1] == '0', f'ready in {time.time() - t0:.1f} s, {net.split(",")[0]}')
    key = bytes.fromhex(did[7:])

    # basics
    check('AT', m.command('AT') == [])
    info = m.command('AT+INFO')[0]
    check('AT+INFO', info.startswith('+INFO:hdht-module/0.1,' + did + ',1,1,0,0,'), 'free heap ' + info.split(',')[-1])
    check('AT+ID?', m.command('AT+ID?') == ['+ID:' + did])
    wifi = m.command('AT+WIFI?')[0].split(',')
    check('AT+WIFI?', wifi[1] == '1', 'ssid hidden, ip ' + wifi[2])
    check('unknown command', errors_with(m, 'AT+NOPE=1') == 'ERROR:unknown command')

    # identity: hash, sign, verify
    h = m.command('AT+HASH=open-anchor')[0][6:]
    check('AT+HASH is BLAKE2b-256', h == hashlib.blake2b(b'open-anchor', digest_size=32).hexdigest())
    sig = bytes.fromhex(m.command('AT+SIGNT=hello from the host')[0][6:])
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, b'hello from the host')
        check('AT+SIGNT verifies with the DID key', True)
    except Exception:
        check('AT+SIGNT verifies with the DID key', False)
    msg = b'\x00\x01binary'
    sig2 = m.command('AT+SIGN=' + msg.hex())[0][6:]
    check('AT+VERIFY good', m.command(f'AT+VERIFY={did},{msg.hex()},{sig2}') == ['+VERIFY:1'])
    check('AT+VERIFY tampered', m.command(f'AT+VERIFY={did},{(msg + b"x").hex()},{sig2}') == ['+VERIFY:0'])

    # record: put, read back from the module and from a JS peer
    value = '{"v":1,"svc":"meter/1","name":"test meter"}'
    t = time.time()
    seq = m.command('AT+PUTT=' + value)[0].split(':')[1]
    put = m.wait_event('+PUT', timeout=60, match=lambda x: x.endswith(',' + seq))
    status, stored, _ = put[5:].split(',')
    check('AT+PUTT', status == '0' and int(stored) > 0, f'{put} in {time.time() - t:.1f} s')
    m.command('AT+GET=' + did)
    got = m.wait_event('+GET', timeout=60)
    parts = got[5:].split(',')
    check('AT+GET own record', parts[1] == '0' and parts[2] == seq and bytes.fromhex(parts[3]).decode() == value)
    p = peer('get', did)
    rec = peer_line(p, 'record')
    check('JS peer reads the record', rec == f'record seq={seq} value={value}', rec or 'none')

    # network peer: echo server announced under a topic
    server = peer('serve', 'uart-module-test')
    line = peer_line(server, 'did:mw:')
    server_did, topic = line.split(' topic=')
    check('topic hash matches AT+HASH', m.command('AT+HASH=uart-module-test')[0][6:] == topic)
    m.command('AT+LOOKUP=' + topic)
    lk = m.wait_event('+LOOKUP', timeout=60, match=lambda x: topic in x)
    check('AT+LOOKUP finds the announced peer', server_did in lk, lk[:60] + '...')

    # outbound connection
    link, conn, took, retries = connect(m, server_did)
    check('AT+CONNECT', conn == f'+CONN:{link},{server_did},OUT', f'{took:.1f} s, {retries} retries')
    payload = bytes(range(256)) * 2
    m.command(f'AT+SEND={link},{payload.hex()}')
    echoed = b''
    while len(echoed) < len(payload):
        d = m.wait_event(f'+DATA:{link},', timeout=30)
        echoed += bytes.fromhex(d.split(',')[2])
    check('AT+SEND 512 bytes, echoed back', echoed == payload)
    m.command(f'AT+SENDT={link},text with, commas')
    d = m.wait_event(f'+DATA:{link},', timeout=30)
    check('AT+SENDT with commas', bytes.fromhex(d.split(',')[2]) == b'text with, commas')
    links = m.command('AT+LINKS?')
    check('AT+LINKS?', links == [f'+LINK:{link},{server_did},OUT,1'])
    info = m.command('AT+INFO')[0].split(',')
    check('AT+INFO with a link open', info[-2] == '1', 'free heap ' + info[-1])
    m.command(f'AT+CLOSE={link}')
    closed = m.wait_event(f'+CLOSED:{link}', timeout=30)
    check('AT+CLOSE', closed == f'+CLOSED:{link},0', closed)
    check('send on a closed link', errors_with(m, f'AT+SEND={link},00') == 'ERROR:bad link')

    # a peer that never ends its side is closed outright after 5 s
    stuck = peer('serve', 'uart-module-test-stuck', '--half-open', 'yes')
    stuck_did = peer_line(stuck, 'did:mw:').split(' topic=')[0]
    link, _, _, _ = connect(m, stuck_did)
    t = time.time()
    m.command(f'AT+CLOSE={link}')
    closed = m.wait_event(f'+CLOSED:{link}', timeout=15)
    check('AT+CLOSE of a stuck peer', closed == f'+CLOSED:{link},-12', f'{closed} after {time.time() - t:.1f} s')
    stuck.kill()

    # inbound connection
    m.command('AT+LISTEN=1')
    lst = m.wait_event('+LISTENING', timeout=60)
    check('AT+LISTEN=1', lst == '+LISTENING:0')
    dialer = peer('dial', did, 'ping from a peer')
    conn = m.wait_event('+CONN', timeout=60)
    inbound = conn.split(',')
    link = inbound[0].split(':')[1]
    check('inbound connection', inbound[2] == 'IN', conn[:30] + '...')
    d = m.wait_event(f'+DATA:{link},', timeout=30)
    check('inbound data', bytes.fromhex(d.split(',')[2]) == b'ping from a peer')
    m.command(f'AT+SENDT={link},pong from the host MCU')
    reply = peer_line(dialer, 'reply')
    check('peer gets the host reply', reply == 'reply pong from the host MCU', reply or 'none')
    m.wait_event(f'+CLOSED:{link}', timeout=30)

    # allow list
    m.command('AT+ALLOW=' + server_did)
    check('AT+ALLOW?', m.command('AT+ALLOW?') == ['+ALLOW:' + server_did])
    dialer = peer('dial', did, 'should be refused')
    denied = m.wait_event('+DENIED', timeout=60)
    check('peer not on the allow list is denied', 'not allowed' in denied)
    dialer.kill()
    m.command('AT+ALLOW=')
    check('AT+ALLOW= clears', m.command('AT+ALLOW?') == [])

    m.command('AT+LISTEN=0')
    check('AT+LISTEN=0', m.wait_event('+LISTENING', timeout=30) == '+LISTENING:CLOSED')
    server.kill()

    # errors
    check('bad did', errors_with(m, 'AT+CONNECT=did:mw:12') == 'ERROR:bad did')
    check('bad hex', errors_with(m, 'AT+SIGN=abc') == 'ERROR:bad hex or too long')
    check('line too long', errors_with(m, 'AT+SIGN=' + '00' * 1200) == 'ERROR:line too long')

    # persistence: the record comes back after a restart
    m.drain()
    m.command('AT+RESTART')
    boot2 = m.wait_event('+BOOT', timeout=15)
    m.wait_event('+READY', timeout=60)
    put2 = m.wait_event('+PUT', timeout=60)
    check('identity and record survive a restart', boot2 == boot and put2.split(',')[2] == seq, f'{put2}: republished seq {seq}')
    info = m.command('AT+INFO')[0]
    check('AT+INFO after restart', info.split(',')[2:6] == ['1', '1', '0', '0'], 'free heap ' + info.split(',')[-1])

    print(f'\n{sum(results)} of {len(results)} passed')
    return all(results)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    sys.exit(0 if main(sys.argv[1]) else 1)
