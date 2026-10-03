const crypto = require('node:crypto')
const fs = require('node:fs')
const path = require('node:path')
const {app} = require('electron')
const {createAppPaths} = require('./services/paths')
const {loadConfig} = require('./services/config')
const {FileLogger} = require('./services/logger')
const {BackendManager} = require('./services/backend-manager')
const {ConfigWatcher} = require('./services/config-watcher')
const {createMainWindow} = require('./windows/main-window')
const {registerIpc} = require('./ipc/register')

// Linux distributions without a setuid chrome-sandbox helper, and sessions
// running as root (common on live/Kali environments), cannot start the
// Chromium sandbox. Degrade to --no-sandbox instead of failing to launch.
if (process.platform === 'linux') {
  let requiresNoSandbox = false
  try { requiresNoSandbox = typeof process.getuid === 'function' && process.getuid() === 0 } catch { requiresNoSandbox = false }
  if (!requiresNoSandbox && process.env.SECURE_AGENT_ELECTRON_NO_SANDBOX === '1') requiresNoSandbox = true
  if (!requiresNoSandbox) {
    try {
      const sandboxHelper = path.join(__dirname, '..', 'node_modules', 'electron', 'dist', 'chrome-sandbox')
      const stats = fs.statSync(sandboxHelper)
      if ((stats.mode & 0o4000) === 0) requiresNoSandbox = true
    } catch { /* packaged layouts ship their own sandbox helper */ }
  }
  if (requiresNoSandbox) app.commandLine.appendSwitch('no-sandbox')
}

let context = null
let quitting = false
const singleInstance = app.requestSingleInstanceLock()
if (!singleInstance) app.quit()
app.on('second-instance', () => { if(context?.window){if(context.window.isMinimized())context.window.restore();context.window.focus()} })

async function launchBackend() {
  try {
    const origin = await context.backend.start()
    context.window.__secureAgentOrigin = origin
    // The CONTROL CENTER is the primary desktop experience (spec section 22):
    // the main window loads the local control panel, which drives the real
    // backend through the secure preload bridge. The full dashboard stays one
    // click away via "Open Dashboard".
    await context.window.loadFile(path.join(__dirname, 'windows', 'control-center.html'))
    context.configWatcher.start(origin, context.token)
  } catch (error) {
    context.logger.error('startup.backend_failed', error.message)
    context.window.webContents.send('desktop:launch-status', {
      state: 'ERROR', component: 'Local backend', message: 'Backend failed to start.', error: error.message,
      cause: 'Configuration problem, missing packaged runtime, port/process failure, or local security software blocked startup.',
      action: 'Retry once. If it fails again, create diagnostics and open the logs.', log: context.paths.logs,
    })
  }
}

app.setAppUserModelId('com.secureagent.desktop')
if (singleInstance) app.whenReady().then(async () => {
  const paths = createAppPaths(app.getPath('appData'))
  const logger = new FileLogger(paths.logs)
  const config = loadConfig(paths.configFile)
  if (loadConfig.lastRecovery) {
    logger.error('config.recovered', `reason=${loadConfig.lastRecovery.reason} backup=${loadConfig.lastRecovery.backup || 'none'}`)
    loadConfig.lastRecovery = null
  }
  const token = crypto.randomBytes(32).toString('base64url')
  const window = createMainWindow()
  const configWatcher = new ConfigWatcher({
    logger,
    onRevision: (revision) => {
      // Real-time sync: every renderer (control center + dashboard) refreshes
      // when the backend configuration changes externally (spec section 24).
      if (!window.isDestroyed()) window.webContents.send('control:config-sync', {revision})
      if (context?.dashboardWindow && !context.dashboardWindow.isDestroyed()) {
        context.dashboardWindow.webContents.send('control:config-sync', {revision})
      }
    },
  })
  const backend = new BackendManager({app, paths, config, token, logger, onState: (value) => {
    if (!window.isDestroyed()) window.webContents.send('desktop:launch-status', value)
    if (value.state === 'READY' && value.restarted && value.origin && !window.isDestroyed()) {
      window.__secureAgentOrigin = value.origin
      void window.loadFile(path.join(__dirname, 'windows', 'control-center.html'))
      configWatcher.start(value.origin, token)
    }
  }})
  context = {app, paths, logger, config, token, window, backend, configWatcher, dashboardWindow: null}
  registerIpc(context)
  logger.info('startup.begin', `version=${app.getVersion()}`)
  await window.loadFile(path.join(__dirname, 'windows', 'launch.html'))
  await launchBackend()
})

app.on('before-quit', (event) => {
  if (quitting || !context) return
  event.preventDefault()
  quitting = true
  context.logger.info('shutdown.begin')
  context.configWatcher.stop()
  context.backend.stop().finally(() => {
    context.logger.info('shutdown.complete')
    app.quit()
  })
})

app.on('window-all-closed', () => app.quit())
app.on('activate', () => {
  if (context?.window?.isDestroyed()) context.window = createMainWindow()
})
