#!/usr/bin/env python
"""End-to-end test of examples/uart_module: this computer plays the host MCU
over the serial port, and Node.js peers (tools/host/module-peer.js) play the
network.

Usage: python tools/module_test.py <serial port>
Run with the ESP-IDF python env (pyserial, cryptography) and after
`npm ci` in tools/host.
"""

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, os.path.dirname(__file__))
from module_host import Module, ModuleError  # noqa: E402

HOST = os.path.join(os.path.dirname(__file__), 'host')
results = []
peers = []  # killed on exit, also when a check raises


def check(name, ok, detail=''):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'} {name}{'  ' + detail if detail else ''}")


def skip(name, why):
    print(f'SKIP {name}  {why}')


def peer(*args, script='module-peer.js', stdin=None):
    """Starts a Node.js test peer; returns the process."""
    p = subprocess.Popen(['node', script, *args], cwd=HOST, stdin=subprocess.PIPE if stdin else None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if stdin:
        p.stdin.write(stdin)
        p.stdin.close()
    peers.append(p)
    return p


def peer_line(p, prefix, timeout=60, tag='PEER|'):
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = p.stdout.readline()
        if not line:
            break
        if line.startswith(tag + prefix):
            return line.strip()[len(tag):]
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


def path(m, link):
    """RELAY or DIRECT, from AT+LINKS?"""
    for line in m.command('AT+LINKS?'):
        f = line[6:].split(',')
        if f[0] == str(link):
            return f[4]
    return None


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
    m.command('AT+RELAY=')  # a run that died midway may have left one set
    m.command('AT+RELAYONLY=0')

    # basics
    check('AT', m.command('AT') == [])
    info = m.command('AT+INFO')[0]
    check('AT+INFO', info.startswith('+INFO:hdht-module/') and (',' + did + ',1,1,0,0,') in info, info.split(',')[0][6:] + ', free heap ' + info.split(',')[-1])
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

    # manufacturer credential (docs/credentials.md): issued for this module, kept
    # by it, put in its record by the host, checked by an independent verifier
    def issuer(*args):
        return subprocess.run(['node', 'issuer.js', *args, '--name', 'module-test'], cwd=HOST, capture_output=True, text=True).stdout
    issuer('init', 'Module Test Issuer')
    c = json.loads(issuer('issue', did, 'meter X1').split('CREDENTIAL|')[1])
    fields = f"{c['id']},{c['iss']},{c['iat']},{c['model']},{c['sig']}"
    check('AT+CRED with a tampered model', errors_with(m, 'AT+CRED=' + fields.replace('meter X1', 'meter X9')) == 'ERROR:bad signature')
    m.command('AT+CRED=' + fields)
    kept = m.command('AT+CRED?')[0][6:]
    check('AT+CRED? returns the credential', json.loads(kept) == c)
    seq = m.command('AT+PUTT={"v":1,"svc":"meter/1","name":"test meter","cred":' + kept + '}')[0].split(':')[1]
    m.wait_event('+PUT', timeout=60, match=lambda x: x.endswith(',' + seq))
    verdict = issuer('verify', did).strip()
    check('verifier accepts the module', 'VALID valid' in verdict, verdict.split(' id=')[0])

    # the module checks other devices' credentials (components/hdht_cred):
    # cred-fixture.js publishes a device and issuer for every result
    fixture = subprocess.run(['node', 'cred-fixture.js', 'public'], cwd=HOST, capture_output=True, text=True).stdout
    cases = [line.split('|', 1)[1].split() for line in fixture.splitlines() if line.startswith('FIXTURE|')]
    for name, device_did, issuer_did, expected in cases:
        m.command(f'AT+CHECK={device_did},{issuer_did}')
        got = m.wait_event('+CHECK', timeout=90, match=lambda x: device_did in x)
        result = got.split(',')[1]
        check(f'AT+CHECK {name}', result == expected, got.split(',', 4)[-1])

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
    seen = peer_line(server, 'connection from')
    check('the server sees the module\'s DID', seen == f'connection from {did}', seen)
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
    check('AT+LINKS?', links == [f'+LINK:{link},{server_did},OUT,1,DIRECT'])
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

    # Hyperswarm, which Pear apps use: a swarm dials the module with joinPeer,
    # and the module finds a swarm server by topic and connects to it
    dialer = peer('dial', did, 'ping from hyperswarm', script='swarm-peer.js')
    link = m.wait_event('+CONN', timeout=60).split(',')[0].split(':')[1]
    d = m.wait_event(f'+DATA:{link},', timeout=30)
    m.command(f'AT+SENDT={link},pong to hyperswarm')
    reply = peer_line(dialer, 'round 0')
    check('Hyperswarm joinPeer reaches the module', bytes.fromhex(d.split(',')[2]) == b'ping from hyperswarm' and reply is not None and 'reply "pong to hyperswarm"' in reply and 'key=ok' in reply, reply.split(' rtt=')[0] if reply else 'no reply')
    m.wait_event(f'+CLOSED:{link}', timeout=30)
    server = peer('serve', 'uart-module-test-swarm', script='swarm-peer.js')
    swarm_did, topic = peer_line(server, 'did:mw:').split(' topic=')
    m.command('AT+LOOKUP=' + topic)
    lk = m.wait_event('+LOOKUP', timeout=60, match=lambda x: topic in x)
    check('AT+LOOKUP finds a Hyperswarm server', swarm_did in lk)
    link, _, took, retries = connect(m, swarm_did)
    seen = peer_line(server, 'connection from')
    m.command(f'AT+SENDT={link},hello hyperswarm')
    d = m.wait_event(f'+DATA:{link},', timeout=30)
    check('AT+CONNECT to a Hyperswarm server', bytes.fromhex(d.split(',')[2]) == b'hello hyperswarm' and seen == f'connection from {did} client=false', f'{took:.1f} s, {retries} retries')
    m.command(f'AT+CLOSE={link}')
    m.wait_event(f'+CLOSED:{link}', timeout=30)

    # camera events with proofs (components/zk). The events in its test data
    # were proven days ago, so they are STALE. With t moved to now, the proof
    # no longer fits: INVALID, after the whole check. VALID needs a camera.
    zk = os.path.join(os.path.dirname(__file__), '..', 'components', 'zk', 'test', 'data')
    root = open(os.path.join(zk, 'root.hex')).read().strip()
    event = open(os.path.join(zk, 'events.jsonl')).readline().strip()
    check('AT+ZKROOT refuses a value >= r', errors_with(m, 'AT+ZKROOT=' + 'ff' * 32) is not None)
    m.command('AT+ZKROOT=' + root)
    check('AT+ZKROOT?', m.command('AT+ZKROOT?') == ['+ZKROOT:' + root])
    now = int(m.command('AT+TIME?')[0][6:])
    check('AT+TIME? set by SNTP', abs(now / 1000 - time.time()) < 5, f'{now / 1000 - time.time():+.2f} s from this computer')
    fresh = json.dumps(dict(json.loads(event), t=int(time.time() * 1000)), separators=(',', ':'))
    cases = [('not an event', 'hello', None), ('old event', event, 'STALE'), ('event changed', fresh, 'INVALID'), ('malformed event', event.replace('"conf":', '"conf":-'), 'BAD')]
    sender = peer('send', did, stdin='\n'.join(c[1] for c in cases) + '\n')
    link = m.wait_event('+CONN', timeout=60).split(',')[0].split(':')[1]
    for name, text, want in cases:
        d = m.wait_event(f'+DATA:{link},', timeout=30)
        t = time.time()
        try:
            z = m.wait_event(f'+ZK:{link},', timeout=10 if want else 3)
        except ModuleError:
            z = None
        got = z.split(',')[2] if z else None
        check(f'+ZK {name}', bytes.fromhex(d.split(',')[2]).decode() == text and got == want, f'{z} in {time.time() - t:.2f} s' if z else 'no +ZK')
        m.command(f'AT+SENDT={link},ack')
    check('peer gets every ack', sender.stdout.read().count('PEER|reply ack') == len(cases))
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

    # blind relay: every connection through a relay node, both directions;
    # relay-only, or holepunching alongside could move the links off it
    ip = m.command('AT+WIFI?')[0].split(',')[2]
    relay = peer('public', 'relay', script='relay-test.js')
    relay_did = 'did:mw:' + peer_line(relay, '', tag='RELAY|')
    m.command('AT+RELAY=' + relay_did)
    check('AT+RELAY?', m.command('AT+RELAY?') == ['+RELAY:' + relay_did])
    m.command('AT+RELAYONLY=1')
    check('AT+RELAYONLY?', m.command('AT+RELAYONLY?') == ['+RELAYONLY:1'])
    js = peer('public', 'server', script='relay-test.js')
    js_did = 'did:mw:' + peer_line(js, '', tag='SERVER|')
    link, conn, took, retries = connect(m, js_did)
    over = peer_line(js, 'connection', tag='SERVER|')
    check('outbound through the relay', over is not None and ip not in over and path(m, link) == 'RELAY', f'{took:.1f} s, {retries} retries; server sees {over.split(" over ")[1] if over else None}')
    m.command(f'AT+SENDT={link},via the relay')
    d = m.wait_event(f'+DATA:{link},', timeout=30)
    check('data through the relay', bytes.fromhex(d.split(',')[2]) == b'via the relay')
    m.command(f'AT+CLOSE={link}')
    m.wait_event(f'+CLOSED:{link}', timeout=15)
    js.kill()
    client = peer('public', 'client', did[7:], script='relay-test.js')
    conn = m.wait_event('+CONN', timeout=90)
    link = conn.split(',')[0].split(':')[1]
    d = m.wait_event(f'+DATA:{link},', timeout=30)
    m.command(f'AT+SEND={link},{d.split(",")[2]}')  # echo it back
    opened = peer_line(client, 'open', tag='CLIENT|')
    echo = peer_line(client, 'echo', tag='CLIENT|')
    check('inbound through the relay', opened is not None and ip not in opened and echo == 'echo hello through the relay', f'client sees {opened.split(" over ")[1] if opened else None}')
    m.wait_event(f'+CLOSED:{link}', timeout=30)

    # holepunching alongside the relay: a link that opens through the relay
    # moves to a direct path once holepunching gets through (+DIRECT). If
    # holepunching wins the race, the link opens directly: try again. On a LAN
    # whose router holepunches quickly it may win every time.
    m.command('AT+RELAYONLY=0')
    js = peer('public', 'server', script='relay-test.js')
    js_did = 'did:mw:' + peer_line(js, '', tag='SERVER|')
    for tries in range(1, 6):
        link, conn, took, retries = connect(m, js_did)
        if path(m, link) == 'RELAY' or tries == 5:
            break
        m.command(f'AT+CLOSE={link}')
        m.wait_event(f'+CLOSED:{link}', timeout=15)
    t = time.time()
    if path(m, link) != 'RELAY':
        skip('a relayed link moves to a direct path', f'holepunching beat the relay {tries} times')
    else:
        try:
            direct = m.wait_event(f'+DIRECT:{link}', timeout=45)
        except ModuleError:
            direct = None
        moved = peer_line(js, 'moved', timeout=5, tag='SERVER|') if direct else None
        check('a relayed link moves to a direct path', direct is not None and moved is not None and path(m, link) == 'DIRECT', f'{time.time() - t:.1f} s after opening, server {moved}, {tries} tries')
    m.command(f'AT+SENDT={link},after moving')
    d = m.wait_event(f'+DATA:{link},', timeout=30)
    check('data on the link afterwards', bytes.fromhex(d.split(',')[2]) == b'after moving', path(m, link))
    m.command(f'AT+CLOSE={link}')
    m.wait_event(f'+CLOSED:{link}', timeout=15)
    js.kill()
    m.command('AT+RELAY=')
    check('AT+RELAY= clears', m.command('AT+RELAY?') == [])
    relay.kill()

    # public relays found by topic (tools/host/relay-node.js); --force because
    # this computer is behind NAT and reachable only from the module's LAN
    stores = tempfile.mkdtemp(prefix='relay-nodes-')
    def relay_node(name):
        p = peer('public', '--store', os.path.join(stores, name), '--force', script='relay-node.js')
        line = peer_line(p, 'listening', tag=f'RELAY[{name}]|')
        peer_line(p, 'record published', tag=f'RELAY[{name}]|')
        return p, line.split()[1]
    relay_a, a_did = relay_node('relay-a')
    # relay-only: with holepunching alongside, a dead relay may go unnoticed
    m.command('AT+RELAYONLY=1')
    # public relays are announced on the same topic and picked at random, so
    # look again until the module lands on A, the one this test can kill
    t = time.time()
    for tries in range(1, 9):
        m.command('AT+RELAY=AUTO')
        found = m.wait_event('+RELAYFOUND', timeout=90)
        if found == '+RELAYFOUND:' + a_did:
            break
    check('AT+RELAY=AUTO finds the relay node', found == '+RELAYFOUND:' + a_did, f'{found[:30]}... in {time.time() - t:.1f} s, {tries} tries')
    check('AT+RELAY? in auto mode', m.command('AT+RELAY?') == ['+RELAY:AUTO,' + a_did])
    js = peer('public', 'server', script='relay-test.js')
    js_did = 'did:mw:' + peer_line(js, '', tag='SERVER|')
    link, conn, took, retries = connect(m, js_did)
    over = peer_line(js, 'connection', tag='SERVER|')
    check('outbound through the found relay', over is not None and ip not in over and path(m, link) == 'RELAY', f'{took:.1f} s, {retries} retries')
    m.command(f'AT+CLOSE={link}')
    m.wait_event(f'+CLOSED:{link}', timeout=15)

    # relay A dies without unannouncing; B is up: the next relayed connect
    # fails with -107 and the module moves to B, or to a public relay
    relay_a.kill()
    relay_b, b_did = relay_node('relay-b')
    # only -107 moves the module; a connect can also fail first with -100,
    # as first connects on the public network sometimes do
    evs = []
    for _ in range(3):
        link = m.command('AT+CONNECT=' + js_did)[0].split(':')[1]
        ev = m.wait_event('+C', timeout=90, match=lambda x: x.startswith(f'+CONN:{link},') or x.startswith(f'+CLOSED:{link},'))
        evs.append(ev)
        if ev == f'+CLOSED:{link},-107':
            break
    found = m.wait_event('+RELAYFOUND', timeout=90) if ev.endswith(',-107') else '(no -107)'
    replaced = found.startswith('+RELAYFOUND:did:mw:') and found != '+RELAYFOUND:' + a_did
    check('a dead relay is replaced', replaced, f'{", ".join(evs)}, then {found[:30]}...' + ('' if found == '+RELAYFOUND:' + b_did else ' (a public relay)'))
    link, conn, took, retries = connect(m, js_did)
    over = peer_line(js, 'connection', tag='SERVER|')
    check('outbound through the new relay', over is not None and ip not in over and path(m, link) == 'RELAY', f'{took:.1f} s, {retries} retries')
    m.command(f'AT+CLOSE={link}')
    m.wait_event(f'+CLOSED:{link}', timeout=15)
    m.command('AT+RELAY=')
    check('AT+RELAY= leaves auto mode', m.command('AT+RELAY?') == [])
    m.command('AT+RELAYONLY=0')
    js.kill()
    # stop both cleanly so neither stays announced on the public DHT
    relay_a, _ = relay_node('relay-a')
    for p in (relay_a, relay_b):
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=10)

    # announce under a topic: Node.js finds the module by topic, then by key
    topic = m.command('AT+HASH=uart-module-announce')[0][6:]
    t = time.time()
    m.command('AT+ANNOUNCE=' + topic)
    ann = m.wait_event('+ANNOUNCE', timeout=60)
    check('AT+ANNOUNCE', ann.split(',')[1] == '0' and int(ann.split(',')[2]) > 0, f'{ann.split(",", 1)[1]} in {time.time() - t:.1f} s')
    check('AT+ANNOUNCE?', m.command('AT+ANNOUNCE?') == ['+TOPIC:' + topic])
    def listed():
        found = peer_line(peer('lookup', topic), 'found') or ''
        counts = dict(x.split('=') for x in found[6:].split(',') if '=' in x)
        return int(counts.get(did, 0))
    before = listed()
    check('Node.js lookup finds the module', before > 0, f'listed by {before} nodes')
    m.command('AT+ANNOUNCE=')
    un = m.wait_event('+UNANNOUNCE', timeout=90)
    after = listed()
    # unannounce is best effort, as in hyperdht: a few copies can stay until they expire (20 min)
    check('AT+ANNOUNCE= unannounces', un.split(',')[1] == '0' and after <= max(2, before // 4), f'{un.split(",", 1)[1]}; listed by {before} -> {after} nodes')

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
    check('registry root survives a restart', m.command('AT+ZKROOT?') == ['+ZKROOT:' + root])
    m.command('AT+ZKROOT=')
    check('AT+ZKROOT= clears it', m.command('AT+ZKROOT?') == [])
    info = m.command('AT+INFO')[0]
    check('AT+INFO after restart', info.split(',')[2:6] == ['1', '1', '0', '0'], 'free heap ' + info.split(',')[-1])

    print(f'\n{sum(results)} of {len(results)} passed')
    return all(results)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    try:
        ok = main(sys.argv[1])
    finally:
        for p in peers:
            if p.poll() is None:
                p.kill()
    sys.exit(0 if ok else 1)
