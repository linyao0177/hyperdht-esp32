import { command, flag, summary } from 'paparam'
import { persistent } from 'bare-storage'
import process from 'bare-process'
import os from 'bare-os'
import { isWindows } from 'which-runtime'
import path from 'bare-path'
import pkg from './package.json'
import App from './app.js'

const appName = pkg.productName || pkg.name
const isDev = path.basename(Bare.argv[0]) === (isWindows ? 'bare.exe' : 'bare')

const cmd = command(
  appName,
  summary(pkg.description),
  flag('--storage <dir>', 'custom storage directory'),
  flag('--no-updates', 'disable OTA updates for this run'),
  flag('--dial <did>', 'BoAT MER device to read an attested reading from, every minute'),
  flag('--settle', 'submit each payment to the token from the WDK account (pays gas)'),
  flag('--per-session', 'session settlement: devices sign a running total on one nonce, settled once per session'),
  flag('--batch <seconds>', 'with --settle: settle together every so many seconds, in one transaction (Multicall3)'),
  flag('--rpc <url>', 'chain RPC (default: the Arc testnet)'),
  flag('--chain-id <id>', 'chain id (default 5042002)'),
  flag('--token <address>', 'EIP-3009 token devices pay in (default: USDC on the Arc testnet)'),
  flag('--token-name <name>', "the token's EIP-712 domain name (default USDC)"),
  flag('--token-version <version>', "the token's EIP-712 domain version (default 2)")
)

cmd.parse(Bare.argv.slice(isDev ? 2 : 1))
if (cmd.flags.help) Bare.exit()

const updates = cmd.flags.updates
const storage = cmd.flags.storage || (isDev ? null : path.join(persistent(), appName))
const dir = storage || path.join(os.tmpdir(), 'pear', appName)

console.log(`${appName} v${pkg.version}`)
console.log(`Updates: ${updates === false ? 'disabled' : 'enabled'}`)

const app = new App({
  dir,
  app: isDev ? null : os.execPath(),
  updates,
  version: pkg.version,
  upgrade: pkg.upgrade,
  name: isWindows ? appName + '.exe' : appName,
  dial: cmd.flags.dial,
  chain: {
    settle: !!cmd.flags.settle,
    perSession: !!cmd.flags.perSession,
    batch: Number(cmd.flags.batch || 0),
    rpc: cmd.flags.rpc || 'https://rpc.testnet.arc.network',
    chainId: Number(cmd.flags.chainId || 5042002),
    token: cmd.flags.token || '0x3600000000000000000000000000000000000000',
    tokenName: cmd.flags.tokenName || 'USDC',
    tokenVersion: cmd.flags.tokenVersion || '2'
  }
})

app.on('message', (message) => console.log(message))
app.on('updating', () => console.log('[updater] getting new update'))
app.on('updating-delta', (delta) => console.log('[updater]', delta))
app.on('updated', () => console.log('[updater] update complete... applying'))
app.on('update-applied', () =>
  console.log('[updater] applied update, restart to run latest version')
)
app.on('error', (err) => console.error('[app:error]', err))

process.on('SIGHUP', () => app.exit(129))
process.on('SIGINT', () => app.exit(130))
process.on('SIGQUIT', () => app.exit(131))
process.on('SIGTERM', () => app.exit(143))

try {
  await app.ready()
  console.log('\nSelling power to BoAT MER devices. Press Ctrl+C to stop.\n')
} catch (err) {
  console.error('[app:error]', err)
  await app.close().finally(() => Bare.exit(1))
}
