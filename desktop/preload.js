const {contextBridge, ipcRenderer} = require('electron')

const invoke = (channel, value) => ipcRenderer.invoke(channel, value)
contextBridge.exposeInMainWorld('secureAgent', Object.freeze({
  bootstrap: () => invoke('desktop:bootstrap'),
  backendRequest: (request) => invoke('desktop:backend-request', request),
  checkAll: () => invoke('desktop:check-all'),
  getSettings: () => invoke('desktop:get-settings'),
  updateSettings: (settings) => invoke('desktop:update-settings', settings),
  saveSettings: (settings) => invoke('desktop:save-settings', settings),
  resetSettings: () => invoke('desktop:reset-settings'),
  testOllama: () => invoke('desktop:test-ollama'),
  testChatModel: () => invoke('desktop:test-chat-model'),
  testEmbeddingModel: () => invoke('desktop:test-embedding-model'),
  refreshModels: () => invoke('desktop:refresh-models'),
  testNetwork: () => invoke('desktop:test-network'),
  runDiagnostic: (component) => invoke('desktop:run-diagnostic', component),
  setupOllama: () => invoke('desktop:setup-ollama'),
  installModels: (models) => invoke('desktop:install-models', models),
  completeSetup: () => invoke('desktop:complete-setup'),
  retryBackend: () => invoke('desktop:retry-backend'),
  openLogs: () => invoke('desktop:open-logs'),
  createDiagnostics: () => invoke('desktop:create-diagnostics'),
  exit: () => invoke('desktop:exit'),
  // --- Control Center API (backend remains the security authority) --- ---
  // Every call is proxied by the main process with the backend token; the
  // renderer never sees the token and never talks to anything but the
  // capability-checked backend origin.
  controlGetConfig: () => invoke('control:get-config'),
  controlUpdateConfig: (patch, confirm) => invoke('control:update-config', {patch, confirm: confirm === true}),
  controlApplyPreset: (name, confirm) => invoke('control:apply-preset', {name, confirm: confirm === true}),
  controlGetStatus: () => invoke('control:get-status'),
  controlGetSecurity: () => invoke('control:get-security'),
  controlGetPermissions: () => invoke('control:get-permissions'),
  controlPatchPermissions: (action) => invoke('control:patch-permissions', action),
  controlEmergencyStop: () => invoke('control:emergency-stop'),
  controlResume: () => invoke('control:resume'),
  controlGetTools: () => invoke('control:get-tools'),
  controlPatchTool: (name, enabled) => invoke('control:patch-tool', {name, enabled: enabled === true}),
  controlGetAudit: (category, limit) => invoke('control:get-audit', {category: category || 'all', limit: Number(limit) || 100}),
  controlExportAudit: () => invoke('control:export-audit'),
  controlClearAudit: (confirm) => invoke('control:clear-audit', {confirm: confirm === true}),
  controlGetFilesystem: () => invoke('control:get-filesystem'),
  controlAddFilesystemPath: (path, confirm) => invoke('control:add-filesystem-path', {path, confirm: confirm === true}),
  controlRemoveFilesystemPath: (path) => invoke('control:remove-filesystem-path', {path}),
  controlAutomationAction: (action) => invoke('control:automation-action', {action}),
  controlTerminalMode: (mode, confirm) => invoke('control:terminal-mode', {mode, confirm: confirm === true}),
  openDashboard: () => invoke('control:open-dashboard'),
  onLaunchStatus: (callback) => {
    const listener = (_event, value) => callback(value)
    ipcRenderer.on('desktop:launch-status', listener)
    return () => ipcRenderer.removeListener('desktop:launch-status', listener)
  },
  // Real-time configuration sync: the main process holds the SSE connection
  // to the backend and broadcasts revision changes to all renderers.
  onConfigSync: (callback) => {
    const listener = (_event, value) => callback(value)
    ipcRenderer.on('control:config-sync', listener)
    return () => ipcRenderer.removeListener('control:config-sync', listener)
  },
}))
