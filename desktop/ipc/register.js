const fs = require('node:fs')
const path = require('node:path')
const {pathToFileURL} = require('node:url')
const {ipcMain, shell} = require('electron')
const {runChecks} = require('../services/system-checks')
const {ollamaStatus, pullModel} = require('../services/ollama')
const {DEFAULTS, saveConfig, normalizeConfig} = require('../services/config')
const {validateModelName, isTrustedAppUrl} = require('../services/security')
const {getJson} = require('../services/network')

// Frozen capability surface for the renderer backend broker: read-only
// inventory/health routes, the policy-gated terminal API, workflows, grants,
// notifications, task/memory/schedule/document management, and the Control
// Center live-configuration API (config/status/tools/audit/filesystem/
// permissions/emergency-stop/resume). Exported so tests verify exactly what
// the renderer may call.
const BACKEND_CAPABILITY_PATTERN = /^\/api\/v1\/(?:auth\/status|health|system\/health|system\/info|mode|diagnostics(?:\/[a-z]+)?|orchestrate|agent\/tasks(?:\/[0-9a-f-]+(?:\/(?:cancel|reject|resume))?)?|tools(?:\/[a-z][a-z0-9_]+)?|memories(?:\/[0-9a-f-]+)?|schedules(?:\/[0-9a-f-]+(?:\/(?:approve|cancel))?)?|audit(?:\/export|\/clear)?(?:\?[^#]*)?|settings|documents(?:\/(?:search|paths(?:\/remove)?|[0-9a-f-]+))?|schedule-runs|terminal\/status|terminal\/execute|terminal\/history|terminal\/mode|terminal\/executions(?:\/[0-9a-f-]+(?:\/(?:cancel|stream))?)?|workflows(?:\/[a-z_]+\/run)?|reports(?:\/[0-9a-f-]+)?|permissions(?:\/grants(?:\/[0-9a-f-]+)?)?|notifications|config(?:\/events|\/preset)?|status|security|emergency-stop|resume|filesystem(?:\/paths(?:\/remove)?)?|automation\/(?:pause-all|resume-all|cancel-all))(?:\?[^#]*)?$/

function registerIpc(context) {
  // The trust gate admits exactly three sender origins: the backend origin
  // (dashboard window, loaded over http from 127.0.0.1) and the two local
  // window bundles shipped inside the app (launch splash + Control Center,
  // loaded via loadFile as file:// URLs). Exact-string matches only — no
  // wildcard file:// acceptance. Without the Control Center entry every
  // control:* handler would reject the primary desktop window.
  const localWindowUrls = new Set([
    pathToFileURL(path.join(__dirname, '..', 'windows', 'launch.html')).href,
    pathToFileURL(path.join(__dirname, '..', 'windows', 'control-center.html')).href,
  ])
  const trusted = (event) => {
    const url = event.senderFrame?.url || ''
    return (Boolean(context.backend.origin) && isTrustedAppUrl(url, context.backend.origin)) || localWindowUrls.has(url)
  }
  const handle = (channel, action) => ipcMain.handle(channel, async (event, value) => {
    if (!trusted(event)) throw new Error('Untrusted IPC sender')
    try { return await action(value) }
    catch (error) {
      context.logger.error('ipc.error', `channel=${channel} message=${error instanceof Error ? error.message : 'unknown'}`)
      const errorId=require('node:crypto').randomUUID(); context.logger.error('ipc.failure',`error_id=${errorId}`); throw new Error(`Desktop operation failed [${errorId}]`)
    }
  })

  const checks = () => runChecks(context)
  const backendPost = async (route) => {
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 130_000)
    try {
      const response = await fetch(`${context.backend.origin}${route}`, {method:'POST', headers:{Authorization:`Bearer ${context.token}`}, signal:controller.signal})
      const text = await response.text()
      if (text.length > 2_000_000) throw new Error('Backend response too large')
      let data; try { data = text ? JSON.parse(text) : {} } catch { throw new Error('Backend returned invalid JSON') }
      if (!response.ok) { const failure=data?.error||data; throw new Error(`${failure?.code||'REQUEST_FAILED'}: ${failure?.message||failure?.detail||response.statusText}`) }
      return data
    } finally { clearTimeout(timer) }
  }
  const backendOllamaStatus = async () => {
    const status=await getJson(`${context.backend.origin}/api/v1/ollama/status`,{Authorization:`Bearer ${context.token}`},20_000)
    const failure=status.last_error
    return {installed:Boolean(status.service_available),service:Boolean(status.service_available),version:status.ollama_version||null,models:Array.isArray(status.models)?status.models:[],chatModel:Boolean(status.generative_available),embeddingModel:Boolean(status.embedding_available),code:failure?.code||(status.service_available?'CONNECTED':'OLLAMA_UNAVAILABLE'),error:failure?.message||null}
  }
  const bootstrap = () => ({setupComplete: context.config.setupComplete, version: context.app.getVersion(), origin: context.backend.origin, models: {chat: context.config.chatModel, embedding: context.config.embeddingModel}, backend:context.backend.snapshot()})
  handle('desktop:bootstrap', bootstrap)
  handle('desktop:backend-request', async (request) => {
    if (!request || typeof request !== 'object' || typeof request.path !== 'string') throw new Error('Invalid backend request')
    const method=String(request.method||'GET').toUpperCase(); const allowedMethods=new Set(['GET','POST','PATCH','DELETE'])
    // Frozen capability surface: read-only inventory/health/report routes, the
    // policy-gated terminal API, workflows, grants, notifications, the
    // original task/memory/schedule/document management routes, and the
    // Control Center live-configuration API (config/status/tools/audit/
    // filesystem/permissions/emergency-stop/resume).
    if(!allowedMethods.has(method) || !BACKEND_CAPABILITY_PATTERN.test(request.path)) throw new Error('Backend capability denied')
    // Bounded upstream fetch: without a timeout a wedged backend request
    // would hang the renderer-side broker call indefinitely.
    const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),130_000)
    let response
    try {
      response=await fetch(`${context.backend.origin}${request.path}`,{method,headers:{Authorization:`Bearer ${context.token}`,...(request.body?{'Content-Type':'application/json'}:{})},body:request.body||undefined,signal:controller.signal})
    } finally { clearTimeout(timer) }
    const text=await response.text(); if(text.length>2_000_000) throw new Error('Backend response too large')
    return {status:response.status,headers:{requestId:response.headers.get('x-request-id'),contractVersion:response.headers.get('x-api-contract-version')},body:text}
  })
  handle('desktop:check-all', checks)
  handle('desktop:get-settings', () => ({...context.config}))
  const ollamaDownloadUrl = () => 'https://ollama.com/download/linux'
  handle('desktop:setup-ollama', () => shell.openExternal(ollamaDownloadUrl()))
  handle('desktop:test-ollama', backendOllamaStatus)
  handle('desktop:test-chat-model', () => backendPost('/api/v1/ollama/test-chat'))
  handle('desktop:test-embedding-model', () => backendPost('/api/v1/ollama/test-embedding'))
  handle('desktop:refresh-models', async () => (await backendOllamaStatus()).models)
  handle('desktop:test-network', async () => {
    if (!context.config.networkEnabled) throw new Error('NETWORK_DISABLED: Network tools are disabled by policy')
    return getJson(`${context.backend.origin}/api/v1/network/test`, {Authorization: `Bearer ${context.token}`}, 20_000)
  })
  handle('desktop:run-diagnostic', (component) => {
    if (!['backend','agent','tools','permissions','search'].includes(component)) throw new Error('Unsupported diagnostic component')
    return getJson(`${context.backend.origin}/api/v1/diagnostics/${component}`, {Authorization:`Bearer ${context.token}`}, 130_000)
  })
  handle('desktop:update-settings', async (patch) => {
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) throw new Error('Invalid settings update')
    const allowed = new Set(Object.keys(DEFAULTS).filter((key) => !['setupComplete','preferredPort'].includes(key)))
    if (Object.keys(patch).some((key) => !allowed.has(key))) throw new Error('Unsupported settings field')
    const previous = {...context.config}
    const next = normalizeConfig({...previous, ...patch})
    context.logger.info('settings.update', `fields=${Object.keys(patch).join(',')}`)
    await context.backend.stop()
    context.config = next; context.backend.config = next
    try {
      const origin = await context.backend.start()
      const ollama = await backendOllamaStatus()
      context.config = saveConfig(context.paths.configFile, next); context.backend.config = context.config
      context.window.__secureAgentOrigin = origin
      await context.window.loadURL(origin)
      return {ok: true, saved: true, restarted: true, applied: true, settings: {...context.config}, ollama, origin, message:'Settings Saved · Backend Restarted · Configuration Applied'}
    } catch (error) {
      context.config = previous; context.backend.config = previous
      try { await context.backend.start() } catch (rollbackError) { context.logger.error('settings.rollback_failed', rollbackError.message) }
      throw new Error(`Settings were not saved because backend restart failed: ${error.message}`)
    }
  })
  handle('desktop:save-settings', (patch) => {
    if (!patch || typeof patch !== 'object' || Array.isArray(patch)) throw new Error('Invalid settings update')
    const allowed = new Set(Object.keys(DEFAULTS).filter((key) => !['setupComplete','preferredPort'].includes(key)))
    if (Object.keys(patch).some((key) => !allowed.has(key))) throw new Error('Unsupported settings field')
    const next = normalizeConfig({...context.config, ...patch})
    saveConfig(context.paths.configFile, next)
    return {ok:true, settings:next, restartRequired:true, message:'Settings Saved · Restart required to apply'}
  })
  handle('desktop:reset-settings', () => ({...normalizeConfig({...DEFAULTS, setupComplete:context.config.setupComplete, preferredPort:context.config.preferredPort})}))
  handle('desktop:install-models', async (models) => {
    if (!Array.isArray(models) || models.length < 1 || models.length > 2) throw new Error('Invalid model request')
    const configured = new Set([context.config.chatModel, context.config.embeddingModel])
    if (models.some((model) => !configured.has(model))) throw new Error('Only configured models may be installed')
    for (const model of models) {
      validateModelName(model); context.logger.info('ollama.pull_start', `model=${model}`)
      await pullModel(context.config, model, (line) => context.logger.info('ollama.pull', line))
      context.logger.info('ollama.pull_complete', `model=${model}`)
    }
    return checks()
  })
  handle('desktop:complete-setup', async () => {
    const status = await checks(); const required = ['windows', 'architecture', 'ram', 'disk', 'localCore', 'backend', 'database', 'security']
    if (!required.every((name) => status[name]?.ok)) throw new Error('Complete all required health checks before finishing setup')
    context.config = saveConfig(context.paths.configFile, {...context.config, setupComplete: true}); context.backend.config = context.config
    context.logger.info('setup.complete'); return {ok: true}
  })
  handle('desktop:retry-backend', async () => {
    await context.backend.stop(); const origin = await context.backend.start(); context.window.__secureAgentOrigin = origin; await context.window.loadURL(origin); return {ok: true, origin}
  })
  handle('desktop:open-logs', () => shell.openPath(context.paths.logs))
  handle('desktop:create-diagnostics', async () => {
    const headers={Authorization:`Bearer ${context.token}`}
    const components={}
    for(const name of ['backend','tools','permissions']){try{components[name]=await getJson(`${context.backend.origin}/api/v1/diagnostics/${name}`,headers,20_000)}catch(error){components[name]={status:'FAIL',error:error.message,rootCause:'Component diagnostic request failed',fix:'Open logs, verify backend health, and retry.'}}}
    const report = {generatedAt: new Date().toISOString(), version: context.app.getVersion(), platform: process.platform, architecture: process.arch, origin: context.backend.origin, checks: await checks(), components, ollama: await ollamaStatus(context.config), settings: {...context.config, searxngBaseUrl: context.config.searxngBaseUrl ? 'configured' : ''}}
    const jsonFile = path.join(context.paths.logs, 'diagnostics-report.json')
    const mdFile = path.join(context.paths.logs, 'DIAGNOSTICS_REPORT.md')
    fs.writeFileSync(jsonFile, `${JSON.stringify(report, null, 2)}\n`, {encoding: 'utf8', mode: 0o600})
    const rows = Object.entries(report.checks).map(([name, item]) => `| ${name} | ${item.ok ? 'PASS' : item.optional ? 'NOT_CONFIGURED' : 'FAIL'} | ${String(item.value).replaceAll('|','/')} | ${item.ok ? '' : 'Review Settings and component logs'} |`).join('\n')
    const componentRows=Object.entries(components).map(([name,item])=>`| ${name} | ${String(item.status||'PASS').replaceAll('|','/')} | ${String(item.error||'').replaceAll('|','/')} | ${String(item.fix||item.rootCause||'').replaceAll('|','/')} |`).join('\n')
    fs.writeFileSync(mdFile, `# SecureAgent Diagnostics\n\nGenerated: ${report.generatedAt}\n\n| Component | Status | Error / evidence | Fix |\n|---|---|---|---|\n${rows}\n${componentRows}\n`, {encoding:'utf8', mode:0o600})
    context.logger.info('diagnostics.created', `path=${jsonFile}`); await shell.showItemInFolder(jsonFile); return {jsonPath: jsonFile, markdownPath: mdFile}
  })
  handle('desktop:exit', () => { context.app.quit(); return {ok: true} })

  // ----------------------------------------------------------------------- //
  // Control Center IPC — thin, token-injecting proxies to the backend.      //
  // All authorization/validation happens in the BACKEND; these handlers     //
  // never make security decisions themselves.                               //
  // ----------------------------------------------------------------------- //
  const backendJson = async (route, {method='GET', body, timeout=130_000} = {}) => {
    const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(), timeout)
    try {
      const response = await fetch(`${context.backend.origin}${route}`, {
        method,
        headers: {Authorization: `Bearer ${context.token}`, ...(body !== undefined ? {'Content-Type': 'application/json'} : {})},
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      })
      const text = await response.text()
      if (text.length > 4_000_000) throw new Error('Backend response too large')
      let data; try { data = text ? JSON.parse(text) : {} } catch { throw new Error('Backend returned invalid JSON') }
      if (!response.ok) {
        const failure = data?.error || data
        const error = new Error(`${failure?.code || 'REQUEST_FAILED'}: ${failure?.message || failure?.detail || response.statusText}`)
        error.code = failure?.code || 'REQUEST_FAILED'
        error.status = response.status
        throw error
      }
      return data
    } finally { clearTimeout(timer) }
  }
  handle('control:get-config', () => backendJson('/api/v1/config'))
  handle('control:update-config', (value) => {
    if (!value || typeof value.patch !== 'object' || Array.isArray(value.patch)) throw new Error('Invalid configuration patch')
    const query = value.confirm === true ? '?confirm=true' : ''
    return backendJson(`/api/v1/config${query}`, {method: 'PATCH', body: value.patch})
  })
  handle('control:apply-preset', (value) => {
    if (!value || !['safe', 'development', 'security_lab', 'full_control'].includes(value.name)) throw new Error('Unknown preset')
    return backendJson('/api/v1/config/preset', {method: 'POST', body: {name: value.name, confirm: value.confirm === true}})
  })
  handle('control:get-status', () => backendJson('/api/v1/status', {timeout: 20_000}))
  handle('control:get-security', () => backendJson('/api/v1/security', {timeout: 20_000}))
  handle('control:get-permissions', () => backendJson('/api/v1/permissions', {timeout: 20_000}))
  handle('control:patch-permissions', (value) => {
    if (!value || !['grant', 'revoke'].includes(value.action)) throw new Error('Invalid permission action')
    return backendJson('/api/v1/permissions', {method: 'PATCH', body: value})
  })
  handle('control:emergency-stop', () => backendJson('/api/v1/emergency-stop', {method: 'POST'}))
  handle('control:resume', () => backendJson('/api/v1/resume', {method: 'POST'}))
  handle('control:get-tools', () => backendJson('/api/v1/tools', {timeout: 20_000}))
  handle('control:patch-tool', (value) => {
    if (!value || typeof value.name !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(value.name)) throw new Error('Invalid tool name')
    return backendJson(`/api/v1/tools/${value.name}`, {method: 'PATCH', body: {enabled: value.enabled === true}})
  })
  handle('control:get-audit', (value) => {
    const category = value && ['all', 'agent', 'terminal', 'network', 'security', 'permission', 'errors'].includes(value.category) ? value.category : 'all'
    const limit = Math.min(Math.max((value && Number(value.limit)) || 100, 1), 500)
    return backendJson(`/api/v1/audit?category=${category}&limit=${limit}`, {timeout: 20_000})
  })
  handle('control:export-audit', () => backendJson('/api/v1/audit/export', {method: 'POST'}))
  handle('control:clear-audit', (value) => backendJson('/api/v1/audit/clear', {method: 'POST', body: {confirm: value?.confirm === true}}))
  handle('control:get-filesystem', () => backendJson('/api/v1/filesystem', {timeout: 20_000}))
  handle('control:add-filesystem-path', (value) => {
    if (!value || typeof value.path !== 'string' || !value.path.trim()) throw new Error('Invalid path')
    return backendJson('/api/v1/filesystem/paths', {method: 'POST', body: {path: value.path, confirm: value.confirm === true}})
  })
  handle('control:remove-filesystem-path', (value) => {
    if (!value || typeof value.path !== 'string' || !value.path.trim()) throw new Error('Invalid path')
    return backendJson('/api/v1/filesystem/paths/remove', {method: 'POST', body: {path: value.path}})
  })
  handle('control:automation-action', (value) => {
    if (!value || !['pause_all', 'resume_all', 'cancel_all'].includes(value.action)) throw new Error('Invalid automation action')
    return backendJson(`/api/v1/automation/${value.action}`, {method: 'POST'})
  })
  handle('control:terminal-mode', (value) => {
    if (!value || !['restricted_agent', 'host_control'].includes(value.mode)) throw new Error('Invalid terminal mode')
    return backendJson('/api/v1/terminal/mode', {method: 'POST', body: {mode: value.mode, confirm: value.confirm === true}})
  })
  handle('control:open-dashboard', async () => {
    const {BrowserWindow} = require('electron')
    if (context.dashboardWindow && !context.dashboardWindow.isDestroyed()) {
      context.dashboardWindow.focus(); return {ok: true}
    }
    const path = require('node:path')
    const {pathToFileURL} = require('node:url')
    const window = new BrowserWindow({
      width: 1360, height: 900, minWidth: 980, minHeight: 680,
      title: 'SecureAgent Dashboard', autoHideMenuBar: true,
      backgroundColor: '#f9f8f7',
      webPreferences: {
        preload: path.join(__dirname, '..', 'preload.js'),
        contextIsolation: true, nodeIntegration: false, sandbox: true,
        webSecurity: true, allowRunningInsecureContent: false,
        devTools: !context.app.isPackaged,
      },
    })
    const launchFile = pathToFileURL(path.join(__dirname, '..', 'windows', 'launch.html')).href
    window.webContents.setWindowOpenHandler(() => ({action: 'deny'}))
    window.webContents.on('will-navigate', (event, url) => {
      const origin = context.backend.origin || ''
      if (!isTrustedAppUrl(url, origin) && url !== launchFile) event.preventDefault()
    })
    context.dashboardWindow = window
    window.on('closed', () => { context.dashboardWindow = null })
    await window.loadURL(context.backend.origin)
    return {ok: true}
  })
}

module.exports = {registerIpc, BACKEND_CAPABILITY_PATTERN}
