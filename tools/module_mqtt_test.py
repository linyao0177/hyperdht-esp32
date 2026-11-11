#!/usr/bin/env python
"""Tests uart_module's AT+MQTT* commands (docs/module-uart.md) on a board.

Usage: python tools/module_mqtt_test.py <serial port>

Starts an MQTT node (boat-mqtt-node, from a checkout of xid-network next to
this one, or $XID_NETWORK) on this computer under a fresh
network name, and an app on it (tools/host/mqtt-peer.mjs). The module finds
the node by network name over the public HyperDHT, publishes, signs, receives
a command, is refused when it writes under another key, reconnects, and
reconnects after a restart. Run with the ESP-IDF python env (pyserial).
"""

import os
import re
import subprocess
import sys
import tempfile
import time

from module_host import Module, ModuleError

ROOT = os.path.join(os.path.dirname(__file__), '..')
results = []
procs = []


# boat-mqtt-node lives in xid-network (https://github.com/linyao0177/xid-network): a checkout next to this one,
# or wherever XID_NETWORK says
XID = os.environ.get('XID_NETWORK') or os.path.abspath(os.path.join(ROOT, '..', 'xid-network'))

def check(name, ok, detail=''):
    results.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'} {name}{'  ' + detail if detail else ''}")


def spawn(args, cwd):
    p = subprocess.Popen(args, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    procs.append(p)
    return p


def line_from(p, pattern, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = p.stdout.readline()
        if not line:
            break
        m = re.search(pattern, line)
        if m:
            return m
    return None


def msg_event(m, topic_end, timeout=30):
    ev = m.wait_event('+MQTTMSG:', timeout=timeout, match=lambda x: x.endswith(topic_end))
    total, offset, hexdata, topic = ev[len('+MQTTMSG:'):].split(',', 3)
    return topic, bytes.fromhex(hexdata), int(total)


def main(port):
    tmp = tempfile.mkdtemp(prefix='module-mqtt-')
    network = f'boat-mqtt-modtest-{os.getpid()}'
    node = spawn(['node', 'bin/boat-mqtt-node.js', '--key', os.path.join(tmp, 'node.json'), '--network', network], os.path.join(XID, 'packages', 'boat-mqtt-node'))
    node_key = line_from(node, r'node ([0-9a-f]{64})').group(1)
    line_from(node, r'announced')
    print(f'node {node_key[:16]}... on network {network}')

    m = Module(port)
    m.reset()
    ready = m.wait_event('+READY', timeout=60)
    did = ready.split(':', 1)[1].split(',')[0]
    me = did[len('did:mw:'):]
    check('module is 0.7.0', m.command('AT+INFO')[0].startswith('+INFO:hdht-module/0.7.0'))

    peer = spawn(['node', 'host/mqtt-peer.mjs', node_key, me], os.path.dirname(__file__))
    app = line_from(peer, r'PEER\|ready ([0-9a-f]{64})').group(1)

    # a subscription made before connecting is kept and made on connect
    m.command(f'AT+MQTTSUB=d/+/to/{me}/#,1')
    try:
        m.command('AT+MQTTPUBT=~/x,0,0,early')
        check('publishing before connecting is refused', False)
    except ModuleError as e:
        check('publishing before connecting is refused', 'not connected' in str(e))

    t = time.time()
    m.command('AT+MQTTCONN=' + network)
    ev = m.wait_event('+MQTTCONN:', timeout=90)
    node_did, connect_ms, relayed = ev[len('+MQTTCONN:'):].split(',')
    check('AT+MQTTCONN finds the node by network name', node_did == 'did:mw:' + node_key, f'{time.time() - t:.1f} s, connect {connect_ms} ms, relayed {relayed}')
    check('the kept subscription is made on connect', m.wait_event('+MQTTACK:SUB', timeout=20) is not None)
    state = m.command('AT+MQTTCONN?')[0].split(':', 1)[1].split(',')
    check('AT+MQTTCONN? reports the node', state[0] == '1' and state[1] == network and state[2] == 'did:mw:' + node_key and state[6] == '1', ','.join(state[:4]))

    # publish text, hex and signed
    pub = m.command('AT+MQTTPUBT=~/telemetry,1,0,{"kwh":1.25,"note":"a,b"}')[0]
    msg_id = pub.split(':')[1]
    acked = m.wait_event('+MQTTACK:PUB,' + msg_id, timeout=20)
    got = line_from(peer, r'PEER\|msg d/' + me + r'/telemetry ([0-9a-f]+) - ')
    check('AT+MQTTPUBT reaches an app, QoS 1 acked', got and bytes.fromhex(got.group(1)) == b'{"kwh":1.25,"note":"a,b"}' and acked)
    m.command('AT+MQTTPUB=~/raw,0,0,00ff10')
    got = line_from(peer, r'PEER\|msg d/' + me + r'/raw ([0-9a-f]+) ')
    check('AT+MQTTPUB carries bytes', got and got.group(1) == '00ff10')

    times = []
    seqs = []
    for i in range(5):
        f = m.command(f'AT+MQTTPUBS=~/signed,1,0,reading {i}')[0].split(':')[1].split(',')
        seqs.append(int(f[1]))
        times.append(int(f[2]))
        got = line_from(peer, r'PEER\|msg d/' + me + r'/signed ([0-9a-f]+) (\S+) (\S+)')
        if not (got and got.group(2) == 'ok' and bytes.fromhex(got.group(1)) == f'reading {i}'.encode() and int(got.group(3)) == seqs[-1]):
            seqs.append(None)
    times.sort()
    check('AT+MQTTPUBS: the app checks the signature and sequence', None not in seqs and seqs == sorted(seqs), f'sign {times[0]}-{times[-1]} us on the C3, seq {seqs[0] >> 32}:{seqs[0] & 0xffffffff}..')

    # a command from the app into the module's inbox
    peer.stdin.write(f'pub d/{{me}}/to/{me}/cmd relay=on\n')
    topic, data, total = msg_event(m, f'/to/{me}/cmd')
    check('the module gets a command as +MQTTMSG, sender in the topic', topic == f'd/{app}/to/{me}/cmd' and data == b'relay=on' and total == 8)

    # writing under another key: the node closes the connection, esp-mqtt reconnects
    m.command(f'AT+MQTTPUBT=d/{app}/x,0,0,forged')
    disc = m.wait_event('+MQTTDISC', timeout=30)
    back = m.wait_event('+MQTTCONN:', timeout=90)
    check('writing under another key: disconnected, then back', disc and back)
    m.wait_event('+MQTTACK:SUB', timeout=20)

    # by key instead of name; then close
    m.command('AT+MQTTCLOSE')
    m.command('AT+MQTTCONN=did:mw:' + node_key)
    ev = m.wait_event('+MQTTCONN:', timeout=90)
    check('AT+MQTTCONN by the node DID', ev.startswith('+MQTTCONN:did:mw:' + node_key))
    m.command('AT+MQTTUNSUB=d/+/to/' + me + '/#')
    m.command('AT+MQTTCLOSE')
    check('AT+MQTTCLOSE', m.command('AT+MQTTCONN?')[0].startswith('+MQTTSTATE:0,'))

    # after a restart the sequence numbers of signed messages keep rising
    m.reset()
    m.wait_event('+READY', timeout=60)
    m.command('AT+MQTTCONN=did:mw:' + node_key)
    m.wait_event('+MQTTCONN:', timeout=90)
    f = m.command('AT+MQTTPUBS=~/signed,1,0,after restart')[0].split(':')[1].split(',')
    got = line_from(peer, r'PEER\|msg d/' + me + r'/signed ([0-9a-f]+) (\S+) (\S+)')
    check('after a restart, signed messages still go through (higher seq)', got and got.group(2) == 'ok' and int(f[1]) > seqs[-1], f'seq {int(f[1]) >> 32}:{int(f[1]) & 0xffffffff}')
    m.command('AT+MQTTCLOSE')

    print(f'\n{sum(results)} passed, {len(results) - sum(results)} failed')
    return all(results)


if __name__ == '__main__':
    try:
        ok = main(sys.argv[1])
    finally:
        for p in procs:
            p.terminate()
    sys.exit(0 if ok else 1)
