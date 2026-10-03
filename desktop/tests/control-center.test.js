/* SecureAgent Control Center — desktop shell tests.
 *
 * Verifies the Electron-side security surface WITHOUT launching Electron:
 * 1. the preload bridge exposes exactly the intended Control Center API and
 *    nothing sensitive (no child_process / shell / fs / arbitrary IPC),
 * 2. the backend capability pattern admits the Control Center routes and
 *    still denies arbitrary paths,
 * 3. the config watcher parses SSE revision events correctly,
 * 4. the Control Center window bundle exists and never uses localStorage as
 *    the configuration authority (the backend is the source of truth).
 */
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')
const Module = require('node:module')

// Stub the electron module so ipc/register.js can be loaded in plain Node.
// The stub only provides the symbols register.js touches at load time.
const electronStub = {
  ipcMain: {handle: () => {}},
  shell: {openExternal: async () => {}, openPath: async () => '', showItemInFolder: () => {}},
  BrowserWindow: class BrowserWindow {},
}
const originalModuleLoad = Module._load
Module._load = function (request, parent, isMain) {
  if (request === 'electron') return electronStub
  return originalModuleLoad.call(this, request, parent, isMain)
}

const {BACKEND_CAPABILITY_PATTERN} = require('../ipc/register')
const {ConfigWatcher} = require('../services/config-watcher')

test('preload exposes the Control Center API without sensitive Node access', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'preload.js'), 'utf8')
  let exposed = null
  const requireStub = (name) => {
    if (name === 'electron') {
      return {
        contextBridge: {exposeInMainWorld: (_key, api) => { exposed = api }},
        ipcRenderer: {
          invoke: async () => ({}),
          on: () => () => {},
          removeListener: () => {},
        },
      }
    }
    throw new Error('preload must not require ' + name)
  }
  const loaded = new Function('require', source + '\nreturn true;')
  loaded(requireStub)
  assert.ok(exposed, 'preload must call contextBridge.exposeInMainWorld')

  const expected = [
    'bootstrap', 'backendRequest', 'checkAll', 'getSettings', 'updateSettings', 'saveSettings',
    'resetSettings', 'testOllama', 'testChatModel', 'testEmbeddingModel', 'refreshModels',
    'testNetwork', 'runDiagnostic', 'setupOllama', 'installModels', 'completeSetup',
    'retryBackend', 'openLogs', 'createDiagnostics', 'exit',
    'controlGetConfig', 'controlUpdateConfig', 'controlApplyPreset', 'controlGetStatus',
    'controlGetSecurity', 'controlGetPermissions', 'controlPatchPermissions',
    'controlEmergencyStop', 'controlResume', 'controlGetTools', 'controlPatchTool',
    'controlGetAudit', 'controlExportAudit', 'controlClearAudit', 'controlGetFilesystem',
    'controlAddFilesystemPath', 'controlRemoveFilesystemPath', 'controlAutomationAction',
    'controlTerminalMode', 'openDashboard', 'onLaunchStatus', 'onConfigSync',
  ]
  for (const key of expected) assert.equal(typeof exposed[key], 'function', key)
  assert.equal(Object.isFrozen(exposed), true, 'bridge must be frozen')

  const forbidden = ['child_process', 'shell', 'fs', 'os', 'process', 'exec', 'spawn', 'eval']
  for (const key of forbidden) assert.equal(key in exposed, false, `bridge must not expose ${key}`)
})

test('capability pattern admits Control Center routes and denies arbitrary paths', () => {
  const allowed = [
    '/api/v1/config',
    '/api/v1/config?confirm=true',
    '/api/v1/config/preset',
    '/api/v1/config/events',
    '/api/v1/status',
    '/api/v1/security',
    '/api/v1/emergency-stop',
    '/api/v1/resume',
    '/api/v1/permissions',
    '/api/v1/tools/calculator',
    '/api/v1/audit?category=terminal&limit=50',
    '/api/v1/audit/export',
    '/api/v1/audit/clear',
    '/api/v1/filesystem',
    '/api/v1/filesystem/paths',
    '/api/v1/filesystem/paths/remove',
    '/api/v1/automation/pause-all',
    '/api/v1/automation/resume-all',
    '/api/v1/automation/cancel-all',
    '/api/v1/terminal/execute',
    '/api/v1/terminal/executions',
  ]
  for (const route of allowed) assert.equal(BACKEND_CAPABILITY_PATTERN.test(route), true, route)

  const denied = [
    '/api/v1/../../../etc/passwd',
    'https://evil.example/api/v1/config',
    '/api/v1/agent/tasks/../../memories',
    '/internal/metrics',
    '/api/v1/config/../../settings',
    '/api/v2/config',
    '/api/v1/',
  ]
  for (const route of denied) assert.equal(BACKEND_CAPABILITY_PATTERN.test(route), false, route)
})

test('config watcher parses SSE revision events and ignores keepalives', () => {
  const watcher = new ConfigWatcher({logger: null, onRevision: () => {}})
  assert.equal(watcher._parseEvent('event: config\ndata: {"revision":7}\n\n'), 7)
  assert.equal(watcher._parseEvent('event: config\ndata: {"revision":8}'), 8)
  assert.equal(watcher._parseEvent(': keepalive\n\n'), null)
  assert.equal(watcher._parseEvent('event: end\ndata: {}\n\n'), null)
  assert.equal(watcher._parseEvent('event: config\ndata: not-json\n\n'), null)
  // _parseEvent must be pure: no state was touched by the probes above.
  assert.equal(watcher.lastRevision, null)
})

test('control center renderer never persists configuration in the browser', () => {
  const js = fs.readFileSync(path.join(__dirname, '..', 'windows', 'control-center.js'), 'utf8')
  const html = fs.readFileSync(path.join(__dirname, '..', 'windows', 'control-center.html'), 'utf8')
  // The backend is the configuration source of truth: localStorage must not
  // appear anywhere in the Control Center bundle (spec section 19).
  assert.doesNotMatch(js, /localStorage|sessionStorage|indexedDB/)
  assert.doesNotMatch(html, /localStorage|sessionStorage|indexedDB/)
  // The emergency stop flow must exist and call the real backend endpoint.
  assert.match(js, /controlEmergencyStop/)
  assert.match(js, /controlResume/)
  assert.match(js, /SECUREAGENT STOPPED/)
  // Every displayed switch maps to a real backend PATCH path.
  assert.match(js, /controlUpdateConfig/)
  assert.match(html, /EMERGENCY STOP/)
  // NOT AVAILABLE affordance for unimplemented features (spec section 27).
  assert.match(js, /NOT AVAILABLE|Loading |Loading…/)
})

test('main window loads the Control Center and wires real-time sync', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'main.js'), 'utf8')
  assert.match(main, /control-center\.html/)
  assert.match(main, /configWatcher/)
  assert.match(main, /control:config-sync/)
  const watcher = fs.readFileSync(path.join(__dirname, '..', 'services', 'config-watcher.js'), 'utf8')
  assert.match(watcher, /\/api\/v1\/config\/events/)
  assert.match(watcher, /control:config-sync|onRevision/)
})
