const fs = require('node:fs')
const {validateModelName} = require('./security')

const DEFAULTS = Object.freeze({
  setupComplete: false,
  preferredPort: 8765,
  ollamaBaseUrl: 'http://127.0.0.1:11434',
  ollamaEnabled: true,
  allowRemoteOllama: false,
  chatModel: 'llama3.2',
  embeddingModel: 'nomic-embed-text',
  maxCompletionTokens: 16384,
  networkEnabled: true,
  networkMode: 'full',
  searxngBaseUrl: '',
  networkTrustedPrivateEndpoint: false,
  webSearchEnabled: false,
  httpRequestsEnabled: true,
  dnsEnabled: true,
  allowLocalNetwork: false,
  allowPrivateNetwork: false,
  allowExternalNetwork: true,
  requireApprovalForExternalNetwork: true,
  agentEnabled: true,
  autonomousMode: false,
  maxAgentSteps: 8,
  toolsEnabled: true,
  filesystemToolsEnabled: true,
  codingToolsEnabled: true,
  terminalToolsEnabled: true,
  terminalBackend: 'linux',
  terminalSudoEnabled: false,
  securityWorkflowsEnabled: true,
  pluginsEnabled: false,
  terminalSandboxImage: '',
  memoryEnabled: true,
  knowledgeEnabled: true,
  approvalMode: 'high-risk',
  requireApprovalForHighRisk: true,
  automationEnabled: false,
  automationRequireApproval: true,
  automationMaxConcurrentJobs: 2,
  automationMaxRuntimeSeconds: 300,
  pythonExecutionBackend: 'disabled',
  pythonSandboxImage: '',
})

function validateHttpUrl(value, {allowEmpty = false, loopbackOnly = false} = {}) {
  if (allowEmpty && !value) return ''
  let url
  try { url = new URL(String(value)) } catch { throw new Error('Invalid HTTP URL') }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('URL must be an HTTP(S) origin without credentials, query, or fragment')
  if (loopbackOnly && !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) throw new Error('Ollama URL must use a loopback host')
  return url.toString().replace(/\/$/, '')
}

function normalizeConfig(value = {}) {
  value = {...DEFAULTS, ...value}
  const image = (name) => { const text=String(value[name] || ''); if(text && !/^[^\s]+@sha256:[0-9a-f]{64}$/.test(text)) throw new Error(`${name} must use an immutable @sha256 digest`); return text }
  const terminalSandboxImage = image('terminalSandboxImage')
  const pythonSandboxImage = image('pythonSandboxImage')
  const terminalBackend = ['docker', 'linux'].includes(value.terminalBackend) ? value.terminalBackend : DEFAULTS.terminalBackend
  // Only the Docker sandbox backend needs a pinned image; the Linux-native
  // terminal executes under the command policy engine instead.
  if (value.terminalToolsEnabled === true && terminalBackend === 'docker' && !terminalSandboxImage) throw new Error('Terminal tools require a pinned Docker image')
  if (value.pythonExecutionBackend === 'docker' && !pythonSandboxImage) throw new Error('Python execution requires a pinned Docker image')
  const requestedMode = value.networkMode === 'configured' ? 'full' : value.networkMode
  const networkMode = ['disabled', 'local', 'full'].includes(requestedMode) ? requestedMode : DEFAULTS.networkMode
  const networkEnabled = value.networkEnabled === true && networkMode !== 'disabled'
  const searxngBaseUrl = validateHttpUrl(value.searxngBaseUrl || '', {allowEmpty: true})
  const webSearchEnabled = networkEnabled && value.webSearchEnabled === true
  const httpRequestsEnabled = networkEnabled && value.httpRequestsEnabled === true
  if (webSearchEnabled && !searxngBaseUrl) throw new Error('SearXNG URL is required when web search is enabled')
  const allowLocalNetwork = networkEnabled && value.allowLocalNetwork === true
  const allowPrivateNetwork = networkEnabled && value.allowPrivateNetwork === true
  const allowExternalNetwork = networkEnabled && networkMode === 'full' && value.allowExternalNetwork === true
  if (networkEnabled && networkMode === 'local' && !(allowLocalNetwork || allowPrivateNetwork)) throw new Error('Local mode requires localhost or private LAN access')
  if (networkEnabled && networkMode === 'full' && !allowExternalNetwork) throw new Error('Full mode requires external network access')
  return {
    setupComplete: value.setupComplete === true,
    preferredPort: Number.isInteger(Number(value.preferredPort)) && Number(value.preferredPort) >= 0 && Number(value.preferredPort) <= 65535 ? Number(value.preferredPort) : DEFAULTS.preferredPort,
    ollamaBaseUrl: (()=>{ const u=new URL(validateHttpUrl(value.ollamaBaseUrl || DEFAULTS.ollamaBaseUrl)); const local=['127.0.0.1','localhost','[::1]'].includes(u.hostname); if(!local && value.allowRemoteOllama!==true) throw new Error('Remote Ollama requires explicit data-egress approval'); if(!local && u.protocol!=='https:') throw new Error('Remote Ollama requires HTTPS'); return u.toString().replace(/\/$/,'') })(),
    allowRemoteOllama: value.allowRemoteOllama === true,
    ollamaEnabled: value.ollamaEnabled !== false,
    chatModel: validateModelName(String(value.chatModel || DEFAULTS.chatModel)),
    embeddingModel: validateModelName(String(value.embeddingModel || DEFAULTS.embeddingModel)),
    maxCompletionTokens: Math.min(131072, Math.max(128, Number.isInteger(Number(value.maxCompletionTokens)) ? Number(value.maxCompletionTokens) : DEFAULTS.maxCompletionTokens)),
    networkEnabled,
    networkMode: networkEnabled ? networkMode : 'disabled',
    searxngBaseUrl,
    networkTrustedPrivateEndpoint: allowLocalNetwork || allowPrivateNetwork,
    webSearchEnabled,
    httpRequestsEnabled,
    dnsEnabled: networkEnabled && value.dnsEnabled !== false,
    allowLocalNetwork,
    allowPrivateNetwork,
    allowExternalNetwork,
    requireApprovalForExternalNetwork: value.requireApprovalForExternalNetwork !== false,
    agentEnabled: value.agentEnabled !== false,
    autonomousMode: value.autonomousMode === true,
    maxAgentSteps: Math.min(20, Math.max(1, Number(value.maxAgentSteps) || DEFAULTS.maxAgentSteps)),
    toolsEnabled: value.toolsEnabled !== false,
    filesystemToolsEnabled: value.filesystemToolsEnabled !== false,
    codingToolsEnabled: value.codingToolsEnabled !== false,
    terminalToolsEnabled: value.terminalToolsEnabled === true,
    terminalBackend,
    terminalSudoEnabled: value.terminalSudoEnabled !== false,
    securityWorkflowsEnabled: value.securityWorkflowsEnabled !== false,
    pluginsEnabled: value.pluginsEnabled === true,
    terminalSandboxImage,
    memoryEnabled: value.memoryEnabled !== false,
    knowledgeEnabled: value.knowledgeEnabled !== false,
    approvalMode: value.approvalMode === 'all' ? 'all' : 'high-risk',
    requireApprovalForHighRisk: true,
    automationEnabled: value.automationEnabled === true,
    automationRequireApproval: value.automationRequireApproval !== false,
    automationMaxConcurrentJobs: Math.min(16, Math.max(1, Number(value.automationMaxConcurrentJobs) || DEFAULTS.automationMaxConcurrentJobs)),
    automationMaxRuntimeSeconds: Math.min(3600, Math.max(10, Number(value.automationMaxRuntimeSeconds) || DEFAULTS.automationMaxRuntimeSeconds)),
    pythonExecutionBackend: value.pythonExecutionBackend === 'docker' ? 'docker' : 'disabled',
    pythonSandboxImage,
  }
}

function loadConfig(file) {
  try { return normalizeConfig({...DEFAULTS, ...JSON.parse(fs.readFileSync(file, 'utf8'))}) }
  catch (error) {
    if (error.code === 'ENOENT') return {...DEFAULTS}
    // A malformed desktop.json (or values rejected by normalizeConfig) must
    // not brick startup inside app.whenReady(). Park the unusable file for
    // inspection and continue with defaults instead of crashing the app.
    try {
      const backup = `${file}.corrupt-${Date.now()}`
      fs.renameSync(file, backup)
      // Expose the backup path for the caller's logger without failing.
      loadConfig.lastRecovery = {reason: error instanceof Error ? error.message : String(error), backup}
    } catch { loadConfig.lastRecovery = {reason: error instanceof Error ? error.message : String(error), backup: null} }
    return {...DEFAULTS}
  }
}

function saveConfig(file, config) {
  const safe = normalizeConfig({...DEFAULTS, ...config})
  const temporary = `${file}.tmp`
  fs.writeFileSync(temporary, `${JSON.stringify(safe, null, 2)}\n`, {encoding: 'utf8', mode: 0o600})
  fs.renameSync(temporary, file)
  return safe
}

module.exports = {DEFAULTS, loadConfig, saveConfig, normalizeConfig, validateHttpUrl}
