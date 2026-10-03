/* Behavioral regression tests for the IPC trust gate and backend capability
 * allowlist (SecureAgent engineering fixes B-1/B-2).
 *
 * B-1: the main window loads control-center.html via loadFile, producing a
 *      file:// sender URL. The trust gate previously admitted only the
 *      backend http origin and launch.html, so EVERY control:* call from the
 *      primary Control Center window threw 'Untrusted IPC sender' and the
 *      desktop UI was dead while the backend was perfectly healthy.
 * B-2: the dashboard calls GET/POST /api/v1/mode and GET /api/v1/diagnostics;
 *      both routes must be admitted by the frozen capability pattern.
 *
 * These tests load the REAL register.js and invoke REAL handlers with a
 * controlled event.senderFrame.url — no source greps.
 */
const assert = require('node:assert/strict')
const path = require('node:path')
const {pathToFileURL} = require('node:url')
const test = require('node:test')
const Module = require('node:module')

const registered = new Map()
const electronStub = {
  ipcMain: {
    handle: (channel, action) => registered.set(channel, action),
  },
  shell: {openExternal: async () => {}, openPath: async () => '', showItemInFolder: () => {}},
  BrowserWindow: class BrowserWindow {},
}
const originalModuleLoad = Module._load
Module._load = function (request, parent, isMain) {
  if (request === 'electron') return electronStub
  return originalModuleLoad.call(this, request, parent, isMain)
}

const {BACKEND_CAPABILITY_PATTERN, registerIpc} = require('../ipc/register')

const windowsDir = path.join(__dirname, '..', 'windows')
const controlCenterUrl = pathToFileURL(path.join(windowsDir, 'control-center.html')).href
const launchUrl = pathToFileURL(path.join(windowsDir, 'launch.html')).href
const backendOrigin = 'http://127.0.0.1:8765'

registerIpc({
  backend: {origin: backendOrigin, snapshot: () => ({state: 'STOPPED', ready: false, origin: backendOrigin, port: 8765, restarts: 0, error: null})},
  token: 'test-token',
  logger: {info: () => {}, error: () => {}},
  config: {},
  app: {getVersion: () => '2.0.0'},
  paths: {logs: path.join(__dirname, 'tmp-does-not-exist')},
  window: {},
  configWatcher: {start: () => {}, stop: () => {}},
  dashboardWindow: null,
})

const sendFrom = (url) => ({senderFrame: {url}})

async function assertTrusted(channel, url) {
  // A trusted sender must get PAST the trust gate; the action itself may
  // still fail (no real backend here) but the error must not be the trust
  // rejection.
  try {
    await registered.get(channel)(sendFrom(url), undefined)
    return
  } catch (error) {
    assert.doesNotMatch(error.message, /Untrusted IPC sender/, `${channel} from ${url} must pass the trust gate`)
    return
  }
}

async function assertUntrusted(channel, url) {
  await assert.rejects(
    () => registered.get(channel)(sendFrom(url), undefined),
    /Untrusted IPC sender/,
    `${channel} from ${url} must be rejected by the trust gate`,
  )
}

test('control-center.html file URL passes the IPC trust gate (fixes B-1)', async () => {
  await assertTrusted('control:get-config', controlCenterUrl)
  await assertTrusted('control:get-status', controlCenterUrl)
  await assertTrusted('control:get-tools', controlCenterUrl)
})

test('launch.html file URL still passes the IPC trust gate', async () => {
  await assertTrusted('control:get-config', launchUrl)
})

test('backend origin URL passes the IPC trust gate', async () => {
  await assertTrusted('control:get-config', `${backendOrigin}/`)
})

test('untrusted senders are still rejected', async () => {
  await assertUntrusted('control:get-config', 'https://evil.example/')
  await assertUntrusted('control:get-config', 'file:///etc/passwd')
  await assertUntrusted('control:get-config', 'http://127.0.0.1:9999/')
  await assertUntrusted('control:get-config', controlCenterUrl.replace('control-center.html', 'control-center2.html'))
  await assertUntrusted('control:get-config', `${controlCenterUrl}?injected=1`)
})

test('capability pattern admits mode and diagnostics dashboard routes (fixes B-2)', () => {
  for (const route of ['/api/v1/mode', '/api/v1/diagnostics', '/api/v1/diagnostics/backend']) {
    assert.equal(BACKEND_CAPABILITY_PATTERN.test(route), true, route)
  }
  for (const route of ['/api/v1/mode/../../config', '/api/v1/diagnosticsX', '/api/v2/mode']) {
    assert.equal(BACKEND_CAPABILITY_PATTERN.test(route), false, route)
  }
})
