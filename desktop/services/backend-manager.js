const fs = require('node:fs')
const path = require('node:path')
const {spawn} = require('node:child_process')
const {selectPort, waitForHealth} = require('./network')

class BackendManager {
  constructor({app, paths, config, token, logger, onState}) {
    this.app = app
    this.paths = paths
    this.config = config
    this.token = token
    this.logger = logger
    this.onState = onState || (() => {})
    this.child = null
    this.stopping = false
    this.ready = false
    this.restarts = 0
    this.port = 0
    this.origin = ''
    this.state = 'STOPPED'
    this.lastError = null
    this.stderrTail = []
  }

  command() {
    if (this.app.isPackaged) {
      const executable = path.join(process.resourcesPath, 'backend', 'SecureAgentBackend')
      if (!fs.existsSync(executable)) throw new Error('Packaged backend executable is missing')
      try { fs.chmodSync(executable, 0o755) } catch {}
      return {executable, args: []}
    }
    const root = path.resolve(__dirname, '..', '..')
    const configured = process.env.SECURE_AGENT_DEV_PYTHON
    if (configured) return {executable: configured, args: ['-m', 'uvicorn', 'app.main:app', '--app-dir', path.join(root, 'backend'), '--host', '127.0.0.1', '--port', String(this.port), '--no-server-header']}
    const candidates = [path.join(root, '.venv', 'bin', 'python'), 'python3']
    const python = candidates.find((candidate) => candidate.includes(path.sep) && fs.existsSync(candidate)) || candidates[candidates.length - 1]
    return {executable: python, args: ['-m', 'uvicorn', 'app.main:app', '--app-dir', path.join(root, 'backend'), '--host', '127.0.0.1', '--port', String(this.port), '--no-server-header']}
  }

  environment() {
    const env = {
      PATH: process.env.PATH || '',
      SystemRoot: process.env.SystemRoot || '',
      TEMP: process.env.TEMP || process.env.TMP || '',
      TMP: process.env.TMP || process.env.TEMP || '',
      SECURE_AGENT_HOST: '127.0.0.1',
      SECURE_AGENT_PORT: String(this.port),
      SECURE_AGENT_ENVIRONMENT: 'production',
      SECURE_AGENT_AUTH_REQUIRED: 'true',
      SECURE_AGENT_API_TOKEN: this.token,
      SECURE_AGENT_ALLOW_UNAUTHENTICATED_LOCALHOST: 'false',
      SECURE_AGENT_DATABASE_PATH: this.paths.database,
      SECURE_AGENT_WORKSPACE_ROOT: this.paths.workspace,
      SECURE_AGENT_OLLAMA_BASE_URL: this.config.ollamaBaseUrl,
      SECURE_AGENT_OLLAMA_ENABLED: String(this.config.ollamaEnabled !== false),
      SECURE_AGENT_ALLOW_REMOTE_OLLAMA: String(this.config.allowRemoteOllama === true),
      SECURE_AGENT_OLLAMA_MODEL: this.config.chatModel,
      SECURE_AGENT_EMBEDDING_MODEL: this.config.embeddingModel,
      SECURE_AGENT_MAX_LLM_COMPLETION_TOKENS: String(this.config.maxCompletionTokens || 16384),
      SECURE_AGENT_ENABLE_NETWORK_TOOLS: String(this.config.networkEnabled === true),
      SECURE_AGENT_NETWORK_MODE: this.config.networkMode || 'disabled',
      SECURE_AGENT_SEARXNG_BASE_URL: this.config.searxngBaseUrl || '',
      // networkTrustedPrivateEndpoint is a desktop-only derived display field;
      // the backend has no such setting and silently ignored the old export.
      SECURE_AGENT_WEB_SEARCH_ENABLED: String(this.config.webSearchEnabled === true),
      SECURE_AGENT_HTTP_REQUESTS_ENABLED: String(this.config.httpRequestsEnabled === true),
      SECURE_AGENT_DNS_ENABLED: String(this.config.dnsEnabled !== false),
      SECURE_AGENT_ALLOW_LOCAL_NETWORK: String(this.config.allowLocalNetwork === true),
      SECURE_AGENT_ALLOW_PRIVATE_NETWORK: String(this.config.allowPrivateNetwork === true),
      SECURE_AGENT_ALLOW_EXTERNAL_NETWORK: String(this.config.allowExternalNetwork === true),
      SECURE_AGENT_REQUIRE_APPROVAL_FOR_EXTERNAL_NETWORK: String(this.config.requireApprovalForExternalNetwork !== false),
      SECURE_AGENT_AGENT_ENABLED: String(this.config.agentEnabled !== false),
      SECURE_AGENT_AUTONOMOUS_MODE: String(this.config.autonomousMode === true),
      SECURE_AGENT_MAX_AGENT_STEPS: String(this.config.maxAgentSteps || 8),
      SECURE_AGENT_TOOLS_ENABLED: String(this.config.toolsEnabled !== false),
      SECURE_AGENT_FILESYSTEM_TOOLS_ENABLED: String(this.config.filesystemToolsEnabled !== false),
      SECURE_AGENT_CODING_TOOLS_ENABLED: String(this.config.codingToolsEnabled !== false),
      SECURE_AGENT_TERMINAL_TOOLS_ENABLED: String(this.config.terminalToolsEnabled === true),
      SECURE_AGENT_TERMINAL_BACKEND: this.config.terminalBackend === 'docker' ? 'docker' : 'linux',
      SECURE_AGENT_TERMINAL_ALLOW_SUDO: String(this.config.terminalSudoEnabled !== false),
      SECURE_AGENT_SECURITY_WORKFLOWS_ENABLED: String(this.config.securityWorkflowsEnabled !== false),
      SECURE_AGENT_PLUGINS_ENABLED: String(this.config.pluginsEnabled === true),
      // The Docker test sandbox only powers the Docker terminal backend and the
      // sandboxed test runner; the Linux terminal backend does not need Docker.
      SECURE_AGENT_TEST_SANDBOX_ENABLED: String(this.config.terminalToolsEnabled === true && this.config.terminalBackend === 'docker'),
      SECURE_AGENT_TEST_SANDBOX_IMAGE: this.config.terminalSandboxImage || '',
      SECURE_AGENT_MEMORY_ENABLED: String(this.config.memoryEnabled !== false),
      SECURE_AGENT_KNOWLEDGE_ENABLED: String(this.config.knowledgeEnabled !== false),
      SECURE_AGENT_APPROVAL_MODE: this.config.approvalMode || 'high-risk',
      SECURE_AGENT_REQUIRE_APPROVAL_FOR_HIGH_RISK: 'true',
      SECURE_AGENT_ENABLE_AUTOMATION: String(this.config.automationEnabled === true),
      SECURE_AGENT_AUTOMATION_REQUIRE_APPROVAL: String(this.config.automationRequireApproval !== false),
      SECURE_AGENT_AUTOMATION_MAX_CONCURRENT_JOBS: String(this.config.automationMaxConcurrentJobs || 2),
      SECURE_AGENT_AUTOMATION_MAX_RUNTIME_SECONDS: String(this.config.automationMaxRuntimeSeconds || 300),
      SECURE_AGENT_PYTHON_EXECUTION_BACKEND: this.config.pythonExecutionBackend || 'disabled',
      SECURE_AGENT_PYTHON_SANDBOX_IMAGE: this.config.pythonSandboxImage || '',
    }
    // An explicitly empty SECURE_AGENT_SEARXNG_BASE_URL would fail backend
    // validation (AnyHttpUrl | None rejects ''); omit it when unconfigured.
    if (!env.SECURE_AGENT_SEARXNG_BASE_URL) delete env.SECURE_AGENT_SEARXNG_BASE_URL
    return env
  }

  snapshot() { return {state:this.state, ready:this.ready, origin:this.origin, port:this.port, restarts:this.restarts, error:this.lastError} }

  emit(state, details = {}) { this.state = state; this.onState({state, ...details}) }

  // -----------------------------------------------------------------------
  // Orphaned-backend recovery: if the Electron main process dies hard, the
  // uvicorn child survives and the next launch would silently pick another
  // port, leaving the orphan serving its loopback port with the previous
  // token until reboot. We persist the child pid in a pidfile and, on the
  // next start(), terminate the orphan ONLY after verifying — via its
  // process command line — that it really is a SecureAgent backend. Any
  // verification failure leaves the process untouched.
  // -----------------------------------------------------------------------
  pidFile() {
    const directory = this.paths && this.paths.data
    if (!directory) return null
    try { fs.mkdirSync(directory, {recursive: true}) } catch { return null }
    return path.join(directory, 'backend.pid')
  }

  verifyBackendProcess(pid) {
    if (!Number.isInteger(pid) || pid <= 0 || pid === process.pid) return false
    try { process.kill(pid, 0) } catch { return false }
    if (process.platform === 'linux') {
      try {
        const cmdline = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ')
        return /uvicorn[\s\S]*app\.main:app/.test(cmdline) || cmdline.includes('SecureAgentBackend')
      } catch { return false }
    }
    if (process.platform === 'darwin') {
      try {
        const {execFileSync} = require('node:child_process')
        const command = execFileSync('ps', ['-p', String(pid), '-o', 'command='], {encoding: 'utf8', timeout: 2000})
        return /uvicorn[\s\S]*app\.main:app/.test(command) || command.includes('SecureAgentBackend')
      } catch { return false }
    }
    // Other platforms: no safe way to verify the command line — never kill.
    return false
  }

  async reapOrphanedBackend() {
    const file = this.pidFile()
    if (!file) return
    let record = null
    try { record = JSON.parse(fs.readFileSync(file, 'utf8')) } catch { try { fs.unlinkSync(file) } catch {} ; return }
    const pid = Number(record && record.pid)
    if (this.verifyBackendProcess(pid)) {
      this.logger.info('backend.orphan_reap', `pid=${pid} port=${record.port || 'unknown'}`)
      try { process.kill(pid, 'SIGTERM') } catch {}
      for (let waited = 0; waited < 3000; waited += 150) {
        let alive = false
        try { process.kill(pid, 0); alive = true } catch { alive = false }
        if (!alive) break
        await new Promise((resolve) => setTimeout(resolve, 150))
      }
      try { process.kill(pid, 0); process.kill(pid, 'SIGKILL') } catch {}
    }
    try { fs.unlinkSync(file) } catch {}
  }

  writePidFile(pid, port) {
    const file = this.pidFile()
    if (!file) return
    try { fs.writeFileSync(file, `${JSON.stringify({pid, port, started_at: new Date().toISOString()})}\n`, {encoding: 'utf8', mode: 0o600}) } catch {}
  }

  clearPidFile(pid) {
    const file = this.pidFile()
    if (!file) return
    try {
      const record = JSON.parse(fs.readFileSync(file, 'utf8'))
      if (Number(record.pid) === Number(pid)) fs.unlinkSync(file)
    } catch { try { fs.unlinkSync(file) } catch {} }
  }

  async start() {
    if (this.child) return this.origin
    this.stopping = false
    this.ready = false
    await this.reapOrphanedBackend()
    this.port = await selectPort(this.config.preferredPort)
    this.origin = `http://127.0.0.1:${this.port}`
    const {executable, args} = this.command()
    this.logger.info('backend.start', `port=${this.port}`)
    this.lastError = null; this.stderrTail = []
    this.emit('STARTING', {message: 'Starting secure local services…', origin:this.origin, port:this.port})
    this.child = spawn(executable, args, {cwd: this.paths.root, env: this.environment(), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], shell: false})
    const child = this.child
    this.writePidFile(child.pid, this.port)
    child.stdout.on('data', (data) => this.logger.info('backend.stdout', data.toString('utf8').slice(0, 4000)))
    child.stderr.on('data', (data) => { const line=data.toString('utf8').slice(0,4000); this.stderrTail.push(line); this.stderrTail=this.stderrTail.slice(-8); this.logger.error('backend.stderr',line) })
    child.once('error', (error) => this.logger.error('backend.spawn_error', error.message))
    child.once('exit', (code, signal) => this.handleExit(child, code, signal))
    try {
      await waitForHealth(this.origin, 60, 250, this.app.getVersion?.() || null, this.token)
      const restarted = this.restarts > 0
      setTimeout(() => { if (this.child === child) this.restarts = 0 }, 60_000).unref()
      this.ready = true
      this.logger.info('backend.ready', `port=${this.port}`)
      this.emit('READY', {message: 'Backend ready', origin: this.origin, port:this.port, restarted})
      return this.origin
    } catch (error) {
      const errorId=require('node:crypto').randomUUID()
      this.logger.error('backend.start_failed', `error_id=${errorId} detail=${error.message} stderr=${this.stderrTail.join(' ').slice(-1200)}`)
      this.lastError = `Backend startup failed [${errorId}]`
      await this.stop()
      this.emit('ERROR', {message:'Backend failed to start', error:this.lastError, origin:this.origin, port:this.port})
      throw new Error(`Backend failed to start. ${this.lastError}`)
    }
  }

  async handleExit(child, code, signal) {
    if (this.child !== child) return
    const wasReady = this.ready
    this.child = null
    this.ready = false
    this.logger.error('backend.exit', `code=${code} signal=${signal || 'none'}`)
    // A process that exits during initial startup is still owned by start().
    // Let its health check fail and report the real startup error instead of
    // launching overlapping restart attempts that can kill one another.
    if (this.stopping || !wasReady || this.restarts >= 3) {
      if (wasReady && !this.stopping) this.emit('ERROR', {message: 'Backend stopped. Use Retry to run diagnostics.', error:`exit=${code} signal=${signal || 'none'}`})
      return
    }
    this.restarts += 1
    this.emit('STARTING', {message: `Backend restart ${this.restarts}/3…`, restarted:true})
    await new Promise((resolve) => setTimeout(resolve, 500 * this.restarts))
    try { await this.start() }
    catch (error) { this.logger.error('backend.restart_failed', error.message) }
  }

  async stop() {
    this.stopping = true
    this.ready = false
    this.state = 'STOPPED'
    const child = this.child
    this.child = null
    if (!child || child.exitCode !== null) { if (child) this.clearPidFile(child.pid); this.emit('STOPPED',{message:'Backend stopped'}); return }
    this.logger.info('backend.stop', `pid=${child.pid}`)
    child.kill('SIGTERM')
    await new Promise((resolve) => {
      const timer = setTimeout(() => { if (child.exitCode === null) child.kill('SIGKILL'); resolve() }, 3000)
      child.once('exit', () => { clearTimeout(timer); resolve() })
    })
    this.clearPidFile(child.pid)
    this.emit('STOPPED',{message:'Backend stopped'})
  }
}

module.exports = {BackendManager}
