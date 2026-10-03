const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')
const {redact, validateModelName, isTrustedAppUrl} = require('../services/security')
const {createAppPaths} = require('../services/paths')
const {loadConfig, saveConfig, normalizeConfig} = require('../services/config')
const {selectPort} = require('../services/network')
const {BackendManager} = require('../services/backend-manager')

test('desktop secrets are redacted and model arguments are validated', () => {
  assert.doesNotMatch(redact('Authorization: Bearer hidden-value'), /hidden-value/)
  assert.doesNotMatch(redact('{\"token\":\"json-secret-value\"}'), /json-secret-value/)
  assert.equal(validateModelName('llama3.2:latest'), 'llama3.2:latest')
  assert.throws(() => validateModelName('../bad'))
  assert.throws(() => validateModelName('model & calc'))
})

test('navigation allows only the exact local application origin', () => {
  assert.equal(isTrustedAppUrl('http://127.0.0.1:8765/settings', 'http://127.0.0.1:8765'), true)
  assert.equal(isTrustedAppUrl('http://127.0.0.1:9999/', 'http://127.0.0.1:8765'), false)
  assert.equal(isTrustedAppUrl('https://evil.example/', 'http://127.0.0.1:8765'), false)
})

test('persistent config never contains an authentication token', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureagent-config-'))
  const paths = createAppPaths(temp)
  saveConfig(paths.configFile, {setupComplete: true, preferredPort: 8765, apiToken: 'must-not-persist'})
  const text = fs.readFileSync(paths.configFile, 'utf8')
  assert.doesNotMatch(text, /must-not-persist/)
  const saved = JSON.parse(text)
  assert.equal(Object.hasOwn(saved, 'apiToken'), false)
  assert.equal(Object.hasOwn(saved, 'token'), false)
  assert.equal(loadConfig(paths.configFile).setupComplete, true)
})

test('dynamic port selection returns a bindable loopback port', async () => {
  const port = await selectPort(0)
  assert.ok(port >= 1024 && port <= 65535)
})

test('network defaults permit approved public egress only and remain validated', () => {
  const direct = normalizeConfig()
  assert.equal(direct.networkEnabled, true)
  assert.equal(direct.networkMode, 'full')
  assert.equal(direct.allowExternalNetwork, true)
  assert.equal(direct.terminalToolsEnabled, true)
  assert.equal(direct.terminalSudoEnabled, false)
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureagent-defaults-'))
  const defaults = loadConfig(path.join(temp, 'not-created.json'))
  assert.equal(defaults.networkEnabled, true)
  assert.equal(defaults.networkMode, 'full')
  assert.equal(defaults.httpRequestsEnabled, true)
  assert.equal(defaults.webSearchEnabled, false) // Requires explicit enablement and SearXNG.
  assert.equal(defaults.allowExternalNetwork, true)
  assert.equal(defaults.allowLocalNetwork, false)
  assert.equal(defaults.allowPrivateNetwork, false)
  assert.equal(defaults.requireApprovalForExternalNetwork, true)
  assert.equal(defaults.terminalToolsEnabled, true)
  assert.equal(defaults.terminalSudoEnabled, false)
  const disabled = normalizeConfig({...defaults, networkEnabled:false})
  assert.equal(disabled.networkEnabled, false)
  assert.equal(disabled.networkMode, 'disabled')
  assert.throws(() => normalizeConfig({networkEnabled: true, networkMode: 'full', allowExternalNetwork:false}), /external network/)
  assert.throws(() => normalizeConfig({networkEnabled: true, networkMode: 'local'}), /localhost or private LAN/)
  const configured = normalizeConfig({networkEnabled: true, networkMode: 'full', allowExternalNetwork:true, webSearchEnabled:true, searxngBaseUrl: 'https://search.example.com'})
  assert.equal(configured.networkEnabled, true)
  assert.equal(configured.searxngBaseUrl, 'https://search.example.com')
})

test('backend environment propagates network and Ollama configuration', () => {
  const manager = new BackendManager({app: {isPackaged:false}, paths:{database:'d',workspace:'w'}, token:'x'.repeat(43), logger:{info(){},error(){}}, config:{ollamaBaseUrl:'http://127.0.0.1:11434',chatModel:'chat',embeddingModel:'embed',networkEnabled:true,networkMode:'full',webSearchEnabled:true,allowExternalNetwork:true,searxngBaseUrl:'https://search.example.com'}})
  manager.port = 8765
  const env = manager.environment()
  assert.equal(env.SECURE_AGENT_ENABLE_NETWORK_TOOLS, 'true')
  assert.equal(env.SECURE_AGENT_NETWORK_MODE, 'full')
  assert.equal(env.SECURE_AGENT_SEARXNG_BASE_URL, 'https://search.example.com')
  assert.equal(env.SECURE_AGENT_OLLAMA_MODEL, 'chat')
  assert.equal(env.SECURE_AGENT_MAX_LLM_COMPLETION_TOKENS, '16384')
})

test('central settings persist and propagate feature policy', () => {
  const digest = 'a'.repeat(64)
  const configured = normalizeConfig({
    agentEnabled:false, autonomousMode:true, maxAgentSteps:17,
    ollamaEnabled:false, maxCompletionTokens:4096, toolsEnabled:true, filesystemToolsEnabled:false,
    codingToolsEnabled:false, terminalToolsEnabled:true,
    terminalSandboxImage:`sandbox@sha256:${digest}`,
    memoryEnabled:false, knowledgeEnabled:false,
    networkEnabled:true, networkMode:'full', httpRequestsEnabled:true,
    allowExternalNetwork:true, requireApprovalForExternalNetwork:true,
    approvalMode:'all', automationEnabled:true, automationRequireApproval:true,
    automationMaxConcurrentJobs:3, automationMaxRuntimeSeconds:180,
    pythonExecutionBackend:'docker', pythonSandboxImage:`python@sha256:${digest}`,
  })
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureagent-policy-'))
  const file = path.join(temp, 'config.json')
  saveConfig(file, configured)
  const loaded = loadConfig(file)
  assert.equal(loaded.agentEnabled, false)
  assert.equal(loaded.terminalToolsEnabled, true)
  assert.equal(loaded.approvalMode, 'all')
  const manager = new BackendManager({app:{isPackaged:false},paths:{database:'d',workspace:'w'},config:loaded,token:'x'.repeat(43),logger:{info(){},error(){}}})
  manager.port=9000
  const env=manager.environment()
  assert.equal(env.SECURE_AGENT_AGENT_ENABLED,'false')
  assert.equal(env.SECURE_AGENT_FILESYSTEM_TOOLS_ENABLED,'false')
  assert.equal(env.SECURE_AGENT_TERMINAL_TOOLS_ENABLED,'true')
  assert.equal(env.SECURE_AGENT_HTTP_REQUESTS_ENABLED,'true')
  assert.equal(env.SECURE_AGENT_ENABLE_AUTOMATION,'true')
  assert.equal(env.SECURE_AGENT_APPROVAL_MODE,'all')
  assert.equal(env.SECURE_AGENT_PYTHON_EXECUTION_BACKEND,'docker')
  assert.equal(env.SECURE_AGENT_MAX_LLM_COMPLETION_TOKENS,'4096')
})

test('completion token setting is bounded and persists', () => {
  assert.equal(normalizeConfig({networkEnabled:false, maxCompletionTokens: 4096}).maxCompletionTokens, 4096)
  assert.equal(normalizeConfig({networkEnabled:false, maxCompletionTokens: 1}).maxCompletionTokens, 128)
  assert.equal(normalizeConfig({networkEnabled:false, maxCompletionTokens: 999999}).maxCompletionTokens, 131072)
})

test('sandboxed execution settings reject mutable or missing images', () => {
  // The Docker terminal backend requires a pinned image; the Linux-native
  // terminal backend does not need Docker at all.
  assert.throws(() => normalizeConfig({terminalToolsEnabled:true, terminalBackend:'docker'}), /pinned Docker image/)
  assert.equal(normalizeConfig({networkEnabled:false, terminalToolsEnabled:true}).terminalBackend, 'linux')
  assert.throws(() => normalizeConfig({pythonExecutionBackend:'docker',pythonSandboxImage:'python:latest'}), /immutable/)
})

test('terminal backend selection maps to backend environment policy', () => {
  const digest = 'a'.repeat(64)
  const configured = normalizeConfig({networkEnabled:false, terminalToolsEnabled:true, terminalBackend:'linux', terminalSudoEnabled:false, securityWorkflowsEnabled:false, pluginsEnabled:true})
  const manager = new BackendManager({app:{isPackaged:false},paths:{database:'d',workspace:'w'},config:configured,token:'x'.repeat(43),logger:{info(){},error(){}}})
  manager.port=9001
  const env=manager.environment()
  assert.equal(env.SECURE_AGENT_TERMINAL_BACKEND,'linux')
  assert.equal(env.SECURE_AGENT_TERMINAL_TOOLS_ENABLED,'true')
  assert.equal(env.SECURE_AGENT_TERMINAL_ALLOW_SUDO,'false')
  assert.equal(env.SECURE_AGENT_SECURITY_WORKFLOWS_ENABLED,'false')
  assert.equal(env.SECURE_AGENT_PLUGINS_ENABLED,'true')
  // the docker test sandbox is not enabled for the linux terminal backend
  assert.equal(env.SECURE_AGENT_TEST_SANDBOX_ENABLED,'false')
  const dockerConfig = normalizeConfig({networkEnabled:false, terminalToolsEnabled:true, terminalBackend:'docker', terminalSandboxImage:`sandbox@sha256:${digest}`})
  const dockerManager = new BackendManager({app:{isPackaged:false},paths:{database:'d',workspace:'w'},config:dockerConfig,token:'x'.repeat(43),logger:{info(){},error(){}}})
  dockerManager.port=9002
  assert.equal(dockerManager.environment().SECURE_AGENT_TEST_SANDBOX_ENABLED,'true')
})

test('Electron and child-process security flags are present', () => {
  const mainWindow = fs.readFileSync(path.join(__dirname, '..', 'windows', 'main-window.js'), 'utf8')
  const manager = fs.readFileSync(path.join(__dirname, '..', 'services', 'backend-manager.js'), 'utf8')
  assert.match(mainWindow, /contextIsolation:\s*true/)
  assert.match(mainWindow, /nodeIntegration:\s*false/)
  assert.match(mainWindow, /sandbox:\s*true/)
  assert.match(manager, /shell:\s*false/)
  assert.match(manager, /127\.0\.0\.1/)
  assert.match(manager, /restarts\s*>=\s*3/)
})

test('backend manager does not overlap restarts during initial startup failure', async () => {
  const logger = {info() {}, error() {}}
  const manager = new BackendManager({
    app: {isPackaged: false}, paths: {}, config: {}, token: 'x'.repeat(43), logger,
  })
  const child = {}
  let restartCalls = 0
  manager.child = child
  manager.ready = false
  manager.start = async () => { restartCalls += 1 }

  await manager.handleExit(child, 1, null)

  assert.equal(manager.child, null)
  assert.equal(manager.ready, false)
  assert.equal(restartCalls, 0)
})

test('backend manager waits for health and shuts down its child', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureagent-backend-'))
  const paths = createAppPaths(temp)
  const logger = {info() {}, error() {}}
  const manager = new BackendManager({
    app: {isPackaged: false}, paths,
    config: {preferredPort: 0, ollamaBaseUrl: 'http://127.0.0.1:11434', chatModel: 'm', embeddingModel: 'e'},
    token: 'x'.repeat(43), logger,
  })
  manager.command = () => ({executable: process.execPath, args: [path.join(__dirname, 'fake-backend.js')]})
  const origin = await manager.start()
  assert.match(origin, /^http:\/\/127\.0\.0\.1:\d+$/)
  assert.ok(manager.child && manager.child.pid)
  await manager.stop()
  assert.equal(manager.child, null)
})

test('readiness validates version, health schema, and token', async()=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'secureagent-ready-'));const paths=createAppPaths(temp);const logger={info(){},error(){}};
 const manager=new BackendManager({app:{isPackaged:false,getVersion:()=> '2.0.0'},paths,config:{preferredPort:0,ollamaBaseUrl:'http://127.0.0.1:11434',chatModel:'m',embeddingModel:'e'},token:'x'.repeat(43),logger});
 manager.command=()=>({executable:process.execPath,args:[path.join(__dirname,'fake-backend.js')]});await manager.start();assert.equal(manager.snapshot().state,'READY');await manager.stop();assert.equal(manager.snapshot().state,'STOPPED')
})
test('logger rotates oversized desktop logs',()=>{const {FileLogger}=require('../services/logger');const temp=fs.mkdtempSync(path.join(os.tmpdir(),'secureagent-log-'));const logger=new FileLogger(temp);fs.writeFileSync(logger.file,'x'.repeat(5*1024*1024+1));logger.info('rotation.test','safe');assert.ok(fs.existsSync(logger.file+'.1'));assert.doesNotMatch(fs.readFileSync(logger.file,'utf8'),/secret-value/)})

test('renderer never receives backend bearer token and child env is allowlisted',()=>{const ipc=fs.readFileSync(path.join(__dirname,'..','ipc','register.js'),'utf8');assert.doesNotMatch(ipc,/bootstrap = .*token:/);const preload=fs.readFileSync(path.join(__dirname,'..','preload.js'),'utf8');assert.match(preload,/backendRequest/);process.env.SENTINEL_PARENT_SECRET='do-not-inherit';const m=new BackendManager({app:{isPackaged:false},paths:{database:'d',workspace:'w'},config:{},token:'x'.repeat(43),logger:{info(){},error(){}}});m.port=1;assert.equal(m.environment().SENTINEL_PARENT_SECRET,undefined)})
test('remote Ollama requires explicit HTTPS egress approval',()=>{assert.throws(()=>normalizeConfig({networkEnabled:false,ollamaBaseUrl:'http://example.com:11434'}),/explicit data-egress/);assert.throws(()=>normalizeConfig({networkEnabled:false,ollamaBaseUrl:'http://example.com:11434',allowRemoteOllama:true}),/HTTPS/);assert.equal(normalizeConfig({networkEnabled:false,ollamaBaseUrl:'https://example.com',allowRemoteOllama:true}).allowRemoteOllama,true)})

test('IPC allowlist includes the new terminal mode and SSE stream routes', () => {
  const ipc = fs.readFileSync(path.join(__dirname, '..', 'ipc', 'register.js'), 'utf8')
  // The new /terminal/mode endpoint must be in the capability allowlist.
  // The regex literal in the source escapes the slash, so we look for the
  // escaped form.
  assert.ok(ipc.includes('terminal\\/mode'), 'IPC allowlist must include terminal/mode')
  // The SSE stream route must be in the allowlist (the regex includes 'stream'
  // as an alternative next to 'cancel').
  assert.ok(ipc.includes('stream'), 'IPC allowlist must include the stream alternative')
})

test('preload exposes only the frozen capability surface (no mode switch)', () => {
  const preload = fs.readFileSync(path.join(__dirname, '..', 'preload.js'), 'utf8')
  // The renderer can call backendRequest (which goes through the IPC
  // allowlist), but there is no direct 'switchMode' or 'activateHostControl'
  // exposed on the preload bridge.
  assert.doesNotMatch(preload, /switchMode|activateHostControl|setMode/)
  assert.match(preload, /backendRequest/)
})

test('main window blocks navigation to untrusted origins', () => {
  const mainWindow = fs.readFileSync(path.join(__dirname, '..', 'windows', 'main-window.js'), 'utf8')
  assert.match(mainWindow, /will-navigate/)
  assert.match(mainWindow, /isTrustedAppUrl/)
  assert.match(mainWindow, /setWindowOpenHandler/)
  assert.match(mainWindow, /action: 'deny'/)
})

test('backend manager binds to 127.0.0.1 only (no LAN exposure)', () => {
  const manager = fs.readFileSync(path.join(__dirname, '..', 'services', 'backend-manager.js'), 'utf8')
  assert.match(manager, /'--host', '127\.0\.0\.1'/)
  assert.doesNotMatch(manager, /'--host', '0\.0\.0\.0'/)
  assert.doesNotMatch(manager, /'--host', '::'/)
})
