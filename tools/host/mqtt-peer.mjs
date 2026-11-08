// An app on an MQTT node over HyperDHT, for tools/module_mqtt_test.py.
//
// usage: node mqtt-peer.mjs <node key> <module key>
//
// Prints PEER|ready <our key> once subscribed to d/<module key>/#, then
//   PEER|msg <topic> <payload hex> <signed: ok/bad/replayed/-> <seq>
// for each message. Reads "pub <topic> <text>" lines on stdin and publishes
// them (QoS 1), printing PEER|sent.

import readline from 'readline'
import { connect, SignedInbox } from '../../packages/boat-mqtt-node/index.js'

const [nodeKey, moduleKey] = process.argv.slice(2)
const out = (line) => console.log('PEER|' + line)
const client = await connect(nodeKey)
const inbox = new SignedInbox()
await client.subscribeAsync(`d/${moduleKey}/#`, { qos: 1 })
client.on('message', (topic, payload) => {
  const signed = payload[0] === 0x53 && payload[1] === 1 ? inbox.check(topic, payload) : null
  const shown = signed && signed.ok ? signed.payload : payload
  out(`msg ${topic} ${shown.toString('hex')} ${signed ? (signed.ok ? 'ok' : signed.reason.replace(' ', '_')) : '-'} ${signed && signed.seq !== undefined ? signed.seq : '-'}`)
})
out('ready ' + client.publicKey.toString('hex'))

readline.createInterface({ input: process.stdin }).on('line', async (line) => {
  const [cmd, topic, ...rest] = line.split(' ')
  if (cmd === 'pub') {
    await client.publishAsync(topic.replace('{me}', client.publicKey.toString('hex')), rest.join(' '), { qos: 1 })
    out('sent ' + topic)
  }
  if (cmd === 'quit') {
    client.end()
    process.exit(0)
  }
})
