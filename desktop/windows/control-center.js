/* SecureAgent Control Center — renderer logic.
 *
 * The backend is the security authority. This panel only renders backend
 * state and sends validated requests; every rejection reverts the local
 * view to the authoritative backend snapshot (UI can never diverge).
 */
;(function () {
  'use strict'

  const bridge = window.secureAgent
  if (!bridge) {
    document.body.innerHTML = '<div style="padding:40px;font-family:sans-serif;color:#e5484d">Secure preload bridge unavailable — this window must run inside SecureAgent Desktop.</div>'
    return
  }

  // ------------------------------------------------------------------ state
  const state = {
    config: null,          // authoritative snapshot from GET /config
    staged: {},            // pending advanced-settings patch {section: {field: value}}
    status: null,
    tools: [],
    filesystem: null,
    security: null,
    auditRows: [],
    auditCategory: 'all',
    lastNetworkOnMode: null,
    advancedOpen: false,
    pollTimer: null,
    syncFlashTimer: null,
  }

  // ------------------------------------------------------------- utilities
  const $ = (id) => document.getElementById(id)
  const el = (tag, className, text) => {
    const node = document.createElement(tag)
    if (className) node.className = className
    if (text !== undefined) node.textContent = text
    return node
  }

  let toastTimer = null
  function toast(message, kind) {
    const node = $('toast')
    node.textContent = message
    node.className = 'toast' + (kind ? ' ' + kind : '')
    node.hidden = false
    clearTimeout(toastTimer)
    toastTimer = setTimeout(() => { node.hidden = true }, 4200)
  }

  function errorMessage(error) {
    return (error && error.message) ? String(error.message) : String(error)
  }

  function isNotAvailable(error) {
    const text = errorMessage(error).toUpperCase()
    return text.includes('TERMINAL_UNAVAILABLE') || text.includes('OFFLINE')
  }

  function getSection(path) {
    // "agent.enabled" -> state.config.state.agent.enabled
    const parts = path.split('.')
    let node = state.config && state.config.state
    for (const part of parts) {
      if (node == null) return undefined
      node = node[part]
    }
    return node
  }

  // ----------------------------------------------------------- api wrapper
  async function api(call, fallback) {
    try {
      return { ok: true, value: await call() }
    } catch (error) {
      return { ok: false, error, value: fallback }
    }
  }

  // ------------------------------------------------------------ master grid
  // Each master switch is backed by a real backend field.
  const MASTER_DEFS = [
    { key: 'agent',      label: 'AI AGENT',    path: 'agent.enabled',      toggle: 'boolean',
      onText: () => 'autonomous execution available', offText: () => 'no autonomous task execution' },
    { key: 'terminal',   label: 'TERMINAL',    path: 'terminal.enabled',   toggle: 'boolean',
      onText: () => 'controlled bash execution enabled', offText: () => 'terminal execution requests are rejected' },
    { key: 'network',    label: 'NETWORK',     path: 'network.mode',       toggle: 'network' },
    { key: 'sudo',       label: 'SUDO',        path: 'sudo.mode',          toggle: 'sudo' },
    { key: 'automation', label: 'AUTOMATION',  path: 'automation.enabled', toggle: 'boolean',
      onText: () => 'schedules may run', offText: () => 'no scheduled execution' },
    { key: 'ai',         label: 'AI ENGINE',   path: 'ai.enabled',         toggle: 'boolean',
      onText: () => 'generative calls enabled', offText: () => 'AI calls are rejected' },
    { key: 'ollama',     label: 'OLLAMA',      path: 'ai.ollama_enabled',  toggle: 'boolean',
      onText: () => 'ollama provider enabled', offText: () => 'OFFLINE — deterministic local core only' },
    { key: 'memory',     label: 'MEMORY',      path: 'memory.enabled',     toggle: 'boolean',
      onText: () => 'memory store active', offText: () => 'memory requests rejected' },
    { key: 'rag',        label: 'RAG',         path: 'rag.enabled',        toggle: 'boolean',
      onText: () => 'document retrieval active', offText: () => 'knowledge requests rejected' },
    { key: 'workflows',  label: 'WORKFLOWS',   path: 'workflows.enabled',  toggle: 'boolean',
      onText: () => 'security workflows runnable', offText: () => 'workflow runs rejected' },
  ]

  function networkOn(state) { return state && state !== 'disabled' }

  function renderMasterGrid() {
    const grid = $('master-grid')
    grid.textContent = ''
    for (const def of MASTER_DEFS) {
      const row = el('div', 'switch-row')
      const labels = el('div', 'switch-labels')
      labels.appendChild(el('div', 'switch-name', def.label))
      const stateLine = el('div', 'switch-state')
      const value = getSection(def.path)
      if (def.toggle === 'boolean') {
        stateLine.textContent = value ? def.onText() : def.offText()
      } else if (def.toggle === 'network') {
        const mode = value || 'disabled'
        stateLine.append('Network: ')
        const strong = el('strong', null, networkOn(mode) ? mode.toUpperCase() : 'BLOCKED')
        stateLine.appendChild(strong)
        stateLine.append(' · mode ' + mode.toUpperCase())
      } else if (def.toggle === 'sudo') {
        stateLine.append('Sudo: ')
        const strong = el('strong', null, (value === 'disabled' ? 'OFF' : value.replace('_', ' ').toUpperCase()))
        stateLine.appendChild(strong)
      }
      labels.appendChild(stateLine)
      row.appendChild(labels)

      if (def.toggle === 'boolean') {
        row.appendChild(buildToggle(def.path, Boolean(value), (next) => {
          const [section, field] = def.path.split('.')
          applyPatch({ [section]: { [field]: next } })
        }))
      } else if (def.toggle === 'network') {
        const select = el('select', 'select-inline')
        for (const mode of ['disabled', 'localhost', 'private', 'external', 'full']) {
          const option = el('option', null, mode.toUpperCase())
          option.value = mode
          if ((value || 'disabled') === mode) option.selected = true
          select.appendChild(option)
        }
        select.addEventListener('change', () => {
          applyPatch({ network: { mode: select.value } })
        })
        row.appendChild(select)
      } else if (def.toggle === 'sudo') {
        const select = el('select', 'select-inline')
        const modes = [['disabled', 'OFF'], ['approval_required', 'APPROVAL REQUIRED'], ['host_control_only', 'HOST CONTROL ONLY']]
        for (const [mode, label] of modes) {
          const option = el('option', null, label)
          option.value = mode
          if ((value || 'disabled') === mode) option.selected = true
          select.appendChild(option)
        }
        select.addEventListener('change', () => {
          applyPatch({ sudo: { mode: select.value } })
        })
        row.appendChild(select)
      }
      grid.appendChild(row)
    }
  }

  function buildToggle(path, isOn, onChange, extraClass) {
    const toggle = el('button', 'toggle' + (isOn ? ' on' : '') + (extraClass ? ' ' + extraClass : ''))
    toggle.type = 'button'
    toggle.setAttribute('role', 'switch')
    toggle.setAttribute('aria-checked', String(isOn))
    toggle.setAttribute('aria-label', path)
    toggle.addEventListener('click', async () => {
      if (toggle.classList.contains('toggle-busy')) return
      toggle.classList.add('toggle-busy')
      onChange(!toggle.classList.contains('on'))
    })
    return toggle
  }

  // -------------------------------------------------- config apply pipeline
  async function applyPatch(patch, { confirm = false, silent = false } = {}) {
    const result = await api(() => bridge.controlUpdateConfig(patch, confirm))
    if (!result.ok) {
      if (!silent) toast('Change rejected by backend — ' + errorMessage(result.error), 'error')
      await refreshConfig() // revert UI to the authoritative state
      return { ok: false, error: result.error }
    }
    state.config = result.value
    renderAll()
    if (!silent) toast('Applied — backend configuration updated', 'ok')
    return { ok: true, value: result.value }
  }

  async function refreshConfig() {
    const result = await api(() => bridge.controlGetConfig())
    if (!result.ok) {
      setBackendPill(false)
      return
    }
    state.config = result.value
    if (state.config.state.network.mode !== 'disabled') {
      state.lastNetworkOnMode = state.config.state.network.mode
    }
    renderAll()
  }

  // --------------------------------------------------------------- presets
  async function applyPreset(name) {
    if (name === 'full_control') {
      const confirmed = await modal(
        'FULL CONTROL MODE',
        'This preset enables autonomous execution, external network access, ' +
        'approval-gated sudo, and automation. It is NOT unrestricted: the command ' +
        'policy engine, approval system, sandbox, audit logging and secret ' +
        'redaction stay mandatory. Continue?',
        { confirmLabel: 'Apply FULL CONTROL' })
      if (!confirmed) return
    } else {
      const labels = { safe: 'SAFE MODE', development: 'DEVELOPMENT MODE', security_lab: 'SECURITY LAB MODE' }
      const confirmed = await modal(
        labels[name] || name,
        'Apply this preset to the live backend configuration? The current settings are replaced.',
        { confirmLabel: 'Apply preset' })
      if (!confirmed) return
    }
    const result = await api(() => bridge.controlApplyPreset(name, true))
    if (!result.ok) { toast('Preset rejected — ' + errorMessage(result.error), 'error'); return }
    state.config = result.value
    renderAll()
    toast('Preset applied — backend configuration updated', 'ok')
  }

  // -------------------------------------------------------- emergency stop
  async function emergencyStop() {
    const confirmed = await modal(
      'EMERGENCY STOP',
      'This will immediately:\n' +
      '• stop running agent tasks\n' +
      '• cancel and kill terminal process groups\n' +
      '• disable autonomous execution and network tool access\n' +
      '• turn Host Control OFF\n' +
      '• preserve audit logs\n\n' +
      'You can press RESUME afterwards to restore the configured settings.',
      { confirmLabel: 'STOP EVERYTHING' })
    if (!confirmed) return
    const result = await api(() => bridge.controlEmergencyStop())
    if (!result.ok) { toast('Emergency stop failed — ' + errorMessage(result.error), 'error'); return }
    state.config = result.value
    renderAll()
    $('stopped-overlay').hidden = false
    toast('SECUREAGENT STOPPED — running processes were killed; press RESUME to restore.', 'error')
  }

  async function resume() {
    const result = await api(() => bridge.controlResume())
    if (!result.ok) { toast('Resume failed — ' + errorMessage(result.error), 'error'); return }
    state.config = result.value
    renderAll()
    toast('SecureAgent resumed — configured settings restored', 'ok')
  }

  // -------------------------------------------------------------- advanced
  function stage(section, field, value) {
    if (!state.staged[section]) state.staged[section] = {}
    state.staged[section][field] = value
    renderAdvanced()
    renderApplyBar()
  }

  function stagedValue(section, field, fallback) {
    if (state.staged[section] && field in state.staged[section]) return state.staged[section][field]
    return fallback
  }

  function isStaged(section, field) {
    return Boolean(state.staged[section] && field in state.staged[section])
  }

  function renderApplyBar() {
    const sections = Object.keys(state.staged)
    const count = sections.reduce((total, section) => total + Object.keys(state.staged[section]).length, 0)
    $('btn-apply').disabled = count === 0
    $('btn-discard').disabled = count === 0
    $('staged-note').textContent = count > 0 ? `${count} change${count > 1 ? 's' : ''} staged` : ''
  }

  async function applyStaged() {
    if (!Object.keys(state.staged).length) return
    const patch = state.staged
    const applyState = $('apply-state')
    applyState.textContent = 'Applying…'
    applyState.className = 'apply-state applying'
    $('btn-apply').disabled = true
    const hostControlEnable = patch.host_control && patch.host_control.enabled === true
    const result = await api(() => bridge.controlUpdateConfig(patch, hostControlEnable))
    if (!result.ok) {
      applyState.textContent = 'Failed'
      applyState.className = 'apply-state failed'
      const needsConfirm = String(result.error.message || '').includes('HOST_CONTROL_REQUIRES_CONFIRMATION')
      toast(needsConfirm
        ? 'Host Control needs explicit confirmation — repeat the Apply step and confirm the dialog.'
        : ('Apply failed — ' + errorMessage(result.error)), 'error')
      await refreshConfig()
      state.staged = {}
      renderApplyBar()
      setTimeout(() => { applyState.textContent = '' }, 3000)
      return
    }
    state.config = result.value
    state.staged = {}
    applyState.textContent = 'Applied'
    applyState.className = 'apply-state applied'
    renderAll()
    setTimeout(() => { applyState.textContent = '' }, 2600)
  }

  function discardStaged() {
    state.staged = {}
    renderAdvanced()
    renderApplyBar()
  }

  // A generic advanced row: label + control + hint
  function advRow(parent, label, hint) {
    const row = el('div', 'adv-row')
    row.appendChild(el('div', 'adv-label', label))
    const control = el('div', 'adv-control')
    control.style.display = 'flex'
    control.style.alignItems = 'center'
    control.style.gap = '10px'
    row.appendChild(control)
    if (hint) row.appendChild(el('div', 'adv-hint', hint))
    parent.appendChild(row)
    return control
  }

  function advToggleRow(parent, section, field, label, hint, { onChange } = {}) {
    const control = advRow(parent, label, hint)
    const current = stagedValue(section, field, getSection(section + '.' + field))
    const toggle = el('button', 'toggle' + (current ? ' on' : '') + (isStaged(section, field) ? ' dirty' : ''))
    toggle.type = 'button'
    toggle.setAttribute('role', 'switch')
    toggle.setAttribute('aria-checked', String(Boolean(current)))
    toggle.addEventListener('click', () => {
      const next = !toggle.classList.contains('on')
      toggle.classList.toggle('on', next)
      stage(section, field, next)
      if (onChange) onChange(next)
    })
    control.appendChild(toggle)
    control.appendChild(el('span', 'switch-state', current ? 'ON' : 'OFF'))
  }

  function advNumberRow(parent, section, field, label, hint, { min, max, step = 1 } = {}) {
    const control = advRow(parent, label, hint)
    const current = stagedValue(section, field, getSection(section + '.' + field))
    const input = el('input')
    input.type = 'number'
    if (min !== undefined) input.min = String(min)
    if (max !== undefined) input.max = String(max)
    input.step = String(step)
    input.value = String(current)
    if (isStaged(section, field)) input.classList.add('dirty')
    input.addEventListener('change', () => {
      const value = Number(input.value)
      if (Number.isFinite(value)) stage(section, field, value)
    })
    control.appendChild(input)
  }

  function advTextRow(parent, section, field, label, hint) {
    const control = advRow(parent, label, hint)
    const current = stagedValue(section, field, getSection(section + '.' + field))
    const input = el('input')
    input.type = 'text'
    input.spellcheck = false
    input.placeholder = '(backend default)'
    input.value = current == null ? '' : String(current)
    if (isStaged(section, field)) input.classList.add('dirty')
    input.addEventListener('change', () => {
      const text = input.value.trim()
      stage(section, field, text === '' ? null : text)
    })
    control.appendChild(input)
  }

  function advSelectRow(parent, section, field, label, hint, options) {
    const control = advRow(parent, label, hint)
    const current = stagedValue(section, field, getSection(section + '.' + field))
    const select = el('select', 'select-inline' + (isStaged(section, field) ? ' dirty' : ''))
    for (const [value, text] of options) {
      const option = el('option', null, text)
      option.value = value
      if ((current || options[0][0]) === value) option.selected = true
      select.appendChild(option)
    }
    select.addEventListener('change', () => stage(section, field, select.value))
    control.appendChild(select)
  }

  function renderAdvanced() {
    if (!state.config) return

    // ---- TERMINAL ----
    const terminal = $('adv-terminal')
    terminal.textContent = ''
    advToggleRow(terminal, 'terminal', 'restricted_mode', 'Restricted Mode',
      'Commands run inside the namespace sandbox. Mandatory while Secure Mode is ON.')
    advToggleRow(terminal, 'terminal', 'command_approval', 'Command Approval',
      'High-risk commands require explicit confirmation.')
    advToggleRow(terminal, 'terminal', 'allow_sudo', 'Allow Sudo',
      'Non-interactive sudo only (sudo -n). Requires the SUDO master switch; passwords are never requested.')
    advToggleRow(terminal, 'terminal', 'allow_network', 'Allow Network in commands',
      'Whether terminal commands may touch the network (policy engine still governs).')
    advNumberRow(terminal, 'terminal', 'max_command_time_seconds', 'Maximum Command Time (s)',
      'Hard wall-clock timeout per command.', { min: 1, max: 600 })
    advNumberRow(terminal, 'terminal', 'max_commands_per_task', 'Maximum Commands / Task',
      'Terminal tool invocations allowed per agent task.', { min: 1, max: 50 })
    advNumberRow(terminal, 'terminal', 'max_output_bytes', 'Maximum Output Size (bytes)',
      'Captured output cap per execution.', { min: 1000, max: 5000000, step: 1000 })
    const modeControl = advRow($('adv-terminal'), 'Terminal Mode',
      'RESTRICTED_AGENT sandboxes commands; HOST_CONTROL runs them on the host (explicit confirmation required).')
    const currentMode = getSection('host_control.enabled')
      ? 'host_control' : 'restricted_agent'
    const modeButton = el('button', 'btn' + (currentMode === 'host_control' ? ' btn-danger' : ''))
    modeButton.type = 'button'
    modeButton.textContent = currentMode === 'host_control' ? 'HOST_CONTROL — switch back to restricted' : 'Switch to HOST_CONTROL'
    modeButton.addEventListener('click', async () => {
      if (currentMode === 'host_control') {
        await api(async () => {
          const value = await bridge.controlTerminalMode('restricted_agent', false)
          await refreshConfig()
          return value
        })
        toast('Returned to RESTRICTED_AGENT mode', 'ok')
        return
      }
      if (!getSection('host_control.enabled')) {
        toast('Enable Host Control below first — it requires explicit confirmation.', 'error')
        return
      }
      const confirmed = await modal('HOST_CONTROL',
        'HOST_CONTROL runs commands on the host outside the namespace sandbox. ' +
        'The command policy engine still classifies everything and BLOCKED commands remain blocked. Continue?',
        { confirmLabel: 'Activate HOST_CONTROL' })
      if (!confirmed) return
      const result = await api(() => bridge.controlTerminalMode('host_control', true))
      if (!result.ok) { toast(errorMessage(result.error), 'error'); return }
      await refreshConfig()
    })
    modeControl.appendChild(modeButton)

    // ---- HOST CONTROL ----
    const host = $('adv-hostcontrol')
    host.textContent = ''
    const hostControl = advRow(host, 'Host Control',
      'Allows approved operations to affect the Linux host. NEVER enabled automatically; the AI cannot enable it. Turns OFF on exit, emergency stop, or unsafe state.')
    const hostOn = stagedValue('host_control', 'enabled', getSection('host_control.enabled'))
    const hostToggle = buildToggle('host_control.enabled', Boolean(hostOn), async (next) => {
      if (!next) {
        stage('host_control', 'enabled', false)
        return
      }
      const confirmed = await modal(
        'HOST CONTROL',
        'Host Control allows approved operations to affect the Linux host.\n' +
        'Review permissions before enabling.\n\n' +
        'It turns OFF automatically when the application exits, when you press ' +
        'EMERGENCY STOP, or when the security policy detects an unsafe state.',
        { confirmLabel: 'Enable Host Control' })
      if (!confirmed) return
      // Host Control enabling is applied immediately with confirm=true.
      const result = await applyPatch({ host_control: { enabled: true } }, { confirm: true })
      if (result.ok && state.staged.host_control) delete state.staged.host_control.enabled
      renderAdvanced(); renderApplyBar()
    })
    hostToggle.setAttribute('aria-label', 'Host Control master')
    hostControl.appendChild(hostToggle)
    hostControl.appendChild(el('span', 'switch-state', hostOn ? 'ON — host operations possible' : 'OFF'))
    advToggleRow(host, 'host_control', 'auto_off_on_exit', 'Auto-OFF on application exit',
      'Host Control automatically disables when SecureAgent exits.')

    // ---- AI ----
    const ai = $('adv-ai')
    ai.textContent = ''
    advToggleRow(ai, 'ai', 'tool_calling', 'Tool Calling', 'AI plans may invoke registered tools.')
    advToggleRow(ai, 'ai', 'planning', 'Planning', 'AI may compose autonomous multi-step plans.')
    advTextRow(ai, 'ai', 'model', 'Model', 'Ollama model override (empty = backend default).')
    advNumberRow(ai, 'ai', 'temperature', 'Temperature', 'Default sampling temperature for chat.', { min: 0, max: 2, step: 0.05 })
    advNumberRow(ai, 'ai', 'context_size', 'Context Size (num_ctx)', 'Ollama context window.', { min: 512, max: 262144, step: 512 })
    advNumberRow(ai, 'ai', 'max_tokens', 'Max Tokens (num_predict)', 'Completion cap per request.', { min: 128, max: 131072, step: 128 })

    // ---- MEMORY / RAG ----
    const memory = $('adv-memory')
    memory.textContent = ''
    advToggleRow(memory, 'memory', 'ingestion', 'Memory Ingestion', 'New memories may be written.')
    advToggleRow(memory, 'memory', 'retrieval', 'Memory Retrieval', 'Memories may be read for context.')
    advToggleRow(memory, 'memory', 'sensitive_filtering', 'Sensitive Data Filtering', 'Secret-shaped content is redacted before storage.')
    advNumberRow(memory, 'memory', 'max_context_items', 'Maximum Context Items', 'Upper bound on listed memories.', { min: 1, max: 500 })
    advNumberRow(memory, 'memory', 'max_documents', 'Maximum Documents', 'RAG document limit.', { min: 1, max: 100000, step: 10 })
    advToggleRow(memory, 'rag', 'ingestion_enabled', 'Document Ingestion', 'New documents may be embedded into the RAG store.')
    advToggleRow(memory, 'rag', 'retrieval_enabled', 'Retrieval', 'RAG search may be queried.')

    // ---- AUTOMATION ----
    const automation = $('adv-automation')
    automation.textContent = ''
    advToggleRow(automation, 'automation', 'scheduled_tasks', 'Scheduled Tasks', 'Due schedules may execute.')
    advToggleRow(automation, 'automation', 'automatic_workflows', 'Automatic Workflows', 'Schedules may run security workflows.')
    advToggleRow(automation, 'automation', 'auto_retry', 'Auto Retry', 'Failed schedule runs may retry.')
    advToggleRow(automation, 'automation', 'background_tasks', 'Background Tasks', 'Automation engine may claim work in the background.')
    const jobControl = advRow(automation, 'Job Control', 'Pause or cancel everything the automation engine is doing.')
    const jobButtons = el('div')
    jobButtons.style.display = 'flex'
    jobButtons.style.gap = '8px'
    jobButtons.style.flexWrap = 'wrap'
    for (const [action, label] of [['pause_all', 'Pause All'], ['resume_all', 'Resume All'], ['cancel_all', 'Cancel All']]) {
      const button = el('button', 'btn', label)
      button.type = 'button'
      if (action === 'cancel_all') button.classList.add('btn-danger')
      button.addEventListener('click', async () => {
        if (action === 'cancel_all') {
          const confirmed = await modal('Cancel All', 'Cancel every running and queued automation job?', { confirmLabel: 'Cancel All' })
          if (!confirmed) return
        }
        const result = await api(() => bridge.controlAutomationAction(action))
        if (!result.ok) { toast(errorMessage(result.error), 'error'); return }
        await Promise.all([refreshConfig(), refreshStatus()])
        toast('Automation: ' + label + ' — done', 'ok')
      })
      jobButtons.appendChild(button)
    }
    jobControl.appendChild(jobButtons)

    // ---- FILESYSTEM ----
    renderFilesystem()

    // ---- TOOLS ----
    renderTools()

    // ---- SECURITY ----
    renderSecurity()

    // ---- AUDIT ----
    renderAuditShell()
  }

  function renderFilesystem() {
    const wrap = $('adv-filesystem')
    wrap.textContent = ''
    if (!state.filesystem) {
      wrap.appendChild(el('div', 'switch-state', 'Loading filesystem policy…'))
      return
    }
    const info = el('div', 'adv-row')
    info.style.flexDirection = 'column'
    info.style.alignItems = 'stretch'
    info.appendChild(el('div', null, 'Workspace: ' + state.filesystem.workspace))
    const paths = el('div')
    for (const path of state.filesystem.allowed_paths || []) {
      const row = el('div', 'path-row')
      row.appendChild(el('span', 'path', path))
      const remove = el('button', 'btn path-remove', 'Remove')
      remove.type = 'button'
      remove.addEventListener('click', async () => {
        const result = await api(() => bridge.controlRemoveFilesystemPath(path))
        if (!result.ok) { toast(errorMessage(result.error), 'error'); return }
        await Promise.all([refreshFilesystem(), refreshConfig()])
        toast('Allowed path removed', 'ok')
      })
      row.appendChild(remove)
      paths.appendChild(row)
    }
    info.appendChild(paths)
    wrap.appendChild(info)
    const addControl = advRow(wrap, 'Add Allowed Path',
      'Backend canonical-path validation. Protected locations are refused; sensitive locations need confirmation.')
    const input = el('input', 'wide')
    input.type = 'text'
    input.placeholder = '/absolute/directory'
    input.spellcheck = false
    const add = el('button', 'btn btn-primary', 'Add Path')
    add.type = 'button'
    add.addEventListener('click', async () => {
      const path = input.value.trim()
      if (!path) return
      let result = await api(() => bridge.controlAddFilesystemPath(path, false))
      if (!result.ok && String(result.error.message || '').includes('SENSITIVE_PATH_REQUIRES_CONFIRMATION')) {
        const confirmed = await modal('Sensitive location',
          `"${path}" looks like a sensitive location.\nAllow it as a workspace root anyway?`,
          { confirmLabel: 'Allow path' })
        if (!confirmed) return
        result = await api(() => bridge.controlAddFilesystemPath(path, true))
      }
      if (!result.ok) { toast(errorMessage(result.error), 'error'); return }
      input.value = ''
      await Promise.all([refreshFilesystem(), refreshConfig()])
      toast('Allowed path added — terminal jail extended at runtime', 'ok')
    })
    addControl.appendChild(input)
    addControl.appendChild(add)
    const protectedList = el('div', 'adv-hint')
    protectedList.textContent = 'Protected: ' + (state.filesystem.protected_paths || []).join(' · ')
    wrap.appendChild(protectedList)
  }

  function renderTools() {
    const wrap = $('adv-tools')
    wrap.textContent = ''
    if (!state.tools.length) {
      wrap.appendChild(el('div', 'switch-state', 'Loading registered tools…'))
      return
    }
    for (const tool of state.tools) {
      const row = el('div', 'tool-row')
      row.appendChild(el('span', 'tool-name', tool.name))
      row.appendChild(el('span', 'tool-desc', tool.description || ''))
      row.appendChild(el('span', 'risk risk-' + (tool.risk_level || 'low'), tool.risk_level || 'low'))
      row.appendChild(el('span', 'tool-desc', tool.required_permissions ? 'permissions: ' + tool.required_permissions.join(', ') : ''))
      if (tool.network_required) row.appendChild(el('span', 'risk', 'network'))
      const enabled = tool.enabled
      const toggle = buildToggle('tool:' + tool.name, enabled, async (next) => {
        const result = await api(() => bridge.controlPatchTool(tool.name, next))
        if (!result.ok) { toast(errorMessage(result.error), 'error'); return }
        tool.enabled = next
        tool.disabled_reason = next ? null : 'Disabled via Control Center'
        renderTools()
        toast(`${tool.name} ${next ? 'enabled' : 'disabled'} — enforced by the tool registry`, 'ok')
      })
      toggle.setAttribute('aria-label', 'tool ' + tool.name)
      row.appendChild(toggle)
      wrap.appendChild(row)
    }
  }

  function renderSecurity() {
    const wrap = $('adv-security')
    wrap.textContent = ''
    if (!state.security) {
      wrap.appendChild(el('div', 'switch-state', 'Loading security policy…'))
      return
    }
    if (state.security.status === 'DEGRADED' && (state.security.degraded || []).length) {
      const banner = el('div', 'degraded-banner', 'SECURITY DEGRADED — ' +
        state.security.degraded.map((item) => `${item.component}: ${item.reason}`).join(' | '))
      wrap.appendChild(banner)
    }
    for (const protection of state.security.protections || []) {
      const row = el('div', 'sec-row')
      row.appendChild(el('span', 'sec-name', protection.name.replace(/_/g, ' ').toUpperCase()))
      row.appendChild(el('span', 'sec-src', protection.source || ''))
      row.appendChild(el('span', 'sec-badge ' + (protection.enabled ? 'sec-on' : 'sec-degraded'),
        protection.enabled ? 'ENFORCED' : 'NOT ENFORCED'))
      wrap.appendChild(row)
    }
    const modeRow = el('div', 'sec-row')
    modeRow.appendChild(el('span', 'sec-name', 'SECURE MODE'))
    modeRow.appendChild(el('span', 'sec-src', 'Master flag — forces restricted terminal, sudo off, approvals on.'))
    modeRow.appendChild(el('span', 'sec-badge ' + (state.security.secure_mode ? 'sec-on' : 'sec-degraded'),
      state.security.secure_mode ? 'ON' : 'OFF'))
    wrap.appendChild(modeRow)
  }

  function renderAuditShell() {
    const wrap = $('adv-audit')
    if (wrap.dataset.ready !== '1') {
      wrap.textContent = ''
      const filters = el('div', 'audit-filters')
      const select = el('select')
      for (const category of ['all', 'agent', 'terminal', 'network', 'security', 'permission', 'errors']) {
        const option = el('option', null, category.toUpperCase())
        option.value = category
        select.appendChild(option)
      }
      select.value = state.auditCategory
      select.addEventListener('change', async () => {
        state.auditCategory = select.value
        await refreshAudit()
      })
      filters.appendChild(select)
      const exportButton = el('button', 'btn', 'Export Audit')
      exportButton.type = 'button'
      exportButton.addEventListener('click', async () => {
        const result = await api(() => bridge.controlExportAudit())
        if (!result.ok) { toast(errorMessage(result.error), 'error'); return }
        toast(`Audit exported (${result.value.entries} entries) → ${result.value.path}`, 'ok')
      })
      filters.appendChild(exportButton)
      const clearButton = el('button', 'btn btn-danger', 'Clear Audit')
      clearButton.type = 'button'
      clearButton.addEventListener('click', async () => {
        const confirmed = await modal('Clear Audit',
          'Delete ALL audit entries? This is destructive and cannot be undone (the clear action itself is recorded).',
          { confirmLabel: 'Clear audit trail' })
        if (!confirmed) return
        const result = await api(() => bridge.controlClearAudit(true))
        if (!result.ok) { toast(errorMessage(result.error), 'error'); return }
        await refreshAudit()
        toast(`Audit cleared (${result.value.cleared_entries} entries removed)`, 'ok')
      })
      filters.appendChild(clearButton)
      wrap.appendChild(filters)
      const tableWrap = el('div', 'audit-table-wrap')
      const table = el('table', 'audit')
      const thead = el('thead')
      const headRow = el('tr')
      for (const column of ['timestamp', 'actor', 'action', 'tool', 'command', 'risk', 'permission', 'result', 'exit code']) {
        headRow.appendChild(el('th', null, column))
      }
      thead.appendChild(headRow)
      table.appendChild(thead)
      const tbody = el('tbody')
      tbody.id = 'audit-tbody'
      table.appendChild(tbody)
      tableWrap.appendChild(table)
      wrap.appendChild(tableWrap)
      wrap.dataset.ready = '1'
    }
    const tbody = $('audit-tbody')
    if (!tbody) return
    tbody.textContent = ''
    for (const row of state.auditRows) {
      const details = row.details || {}
      const tr = el('tr')
      const cells = [
        row.created_at || '',
        row.actor || '',
        row.event || '',
        details.tool || details.agent || '',
        typeof details.command === 'string' ? details.command : '',
        details.risk || '',
        Array.isArray(details.permission) ? details.permission.join(',') : (details.permission || ''),
        details.result || details.status || (details.error ? 'error' : ''),
        details.exit_code === undefined || details.exit_code === null ? '' : String(details.exit_code),
      ]
      cells.forEach((value, index) => {
        const td = el('td', index === 4 || index === 7 ? 'wrap' : undefined, String(value).slice(0, 160))
        if (index === 7) {
          const text = String(value).toLowerCase()
          if (['ok', 'success', 'completed', 'connected'].includes(text)) td.className += ' result-ok'
          else if (text && ['error', 'failed', 'blocked', 'timeout', 'cancelled'].includes(text)) td.className += ' result-fail'
        }
        tr.appendChild(td)
      })
      tbody.appendChild(tr)
    }
  }

  async function refreshAudit() {
    const result = await api(() => bridge.controlGetAudit(state.auditCategory, 100))
    if (result.ok) {
      state.auditRows = Array.isArray(result.value) ? result.value : []
      renderAuditShell()
    }
  }

  async function refreshFilesystem() {
    const result = await api(() => bridge.controlGetFilesystem())
    if (result.ok) state.filesystem = result.value
  }

  async function refreshTools() {
    const result = await api(() => bridge.controlGetTools())
    if (result.ok) state.tools = Array.isArray(result.value) ? result.value : []
  }

  async function refreshSecurity() {
    const result = await api(() => bridge.controlGetSecurity())
    if (result.ok) state.security = result.value
  }

  // ----------------------------------------------------------------- status
  function setBackendPill(ok) {
    const pill = $('pill-backend')
    pill.textContent = ok ? 'BACKEND ONLINE' : 'BACKEND OFFLINE'
    pill.className = 'pill ' + (ok ? 'pill-ok' : 'pill-bad')
  }

  function renderStatus() {
    if (!state.config) return
    const secure = state.config.state.secure_mode
    const emergency = state.config.emergency_stopped
    const securePill = $('pill-secure')
    if (emergency) {
      securePill.textContent = 'EMERGENCY STOP'
      securePill.className = 'pill pill-bad'
    } else {
      securePill.textContent = secure ? 'SECURE MODE ON' : 'SECURE MODE OFF'
      securePill.className = 'pill ' + (secure ? 'pill-ok' : 'pill-warn')
    }
    $('stopped-overlay').hidden = !emergency

    if (!state.status) return
    setBackendPill(true)
    const grid = $('status-grid')
    grid.textContent = ''
    for (const [name, card] of Object.entries(state.status.cards || {})) {
      const cell = el('div', 'status-card')
      cell.appendChild(el('div', 'name', name))
      cell.appendChild(el('div', 'value st-' + card.status, card.status))
      if (card.detail) cell.appendChild(el('div', 'detail', String(card.detail)))
      grid.appendChild(cell)
    }
    const jobs = state.status.automation_jobs
    if (jobs) {
      $('automation-jobs').textContent =
        `automation jobs — active: ${jobs.active} · queued: ${jobs.queued} · failed: ${jobs.failed} · completed: ${jobs.completed}`
    }
    const telemetry = state.status.network_telemetry
    if (telemetry) {
      $('network-info').textContent =
        `network requests — allowed: ${telemetry.request_count} · blocked: ${telemetry.blocked_count}` +
        (telemetry.last_destination ? ` · last: ${telemetry.last_destination} (${telemetry.last_result})` : '')
    }
    $('revision-line').textContent =
      `configuration revision ${state.config.revision} · updated ${state.config.updated_at} by ${state.config.updated_by}`
  }

  function renderAll() {
    renderMasterGrid()
    renderAdvanced()
    renderStatus()
  }

  async function refreshStatus() {
    const result = await api(() => bridge.controlGetStatus())
    if (result.ok) {
      state.status = result.value
      setBackendPill(true)
      renderStatus()
    } else {
      setBackendPill(false)
    }
  }

  // ------------------------------------------------------------------ modal
  let modalResolve = null
  function modal(title, body, { confirmLabel = 'Confirm', withInput = false } = {}) {
    return new Promise((resolve) => {
      modalResolve = resolve
      $('modal-title').textContent = title
      $('modal-body').textContent = body
      $('modal-input-row').hidden = !withInput
      $('modal-ok').textContent = confirmLabel
      $('modal').hidden = false
      if (withInput) $('modal-input').focus()
    })
  }
  function closeModal(result) {
    $('modal').hidden = true
    const resolve = modalResolve
    modalResolve = null
    if (resolve) resolve(result)
  }

  // ------------------------------------------------------------------- boot
  function startPolling() {
    clearInterval(state.pollTimer)
    state.pollTimer = setInterval(() => { void refreshStatus() }, 5000)
  }

  async function init() {
    $('btn-emergency').addEventListener('click', () => { void emergencyStop() })
    $('btn-resume').addEventListener('click', () => { void resume() })
    $('btn-apply').addEventListener('click', () => { void applyStaged() })
    $('btn-discard').addEventListener('click', discardStaged)
    $('btn-dashboard').addEventListener('click', async () => {
      const result = await api(() => bridge.openDashboard())
      if (!result.ok) toast('Could not open the dashboard — ' + errorMessage(result.error), 'error')
    })
    $('btn-advanced').addEventListener('click', () => {
      state.advancedOpen = !state.advancedOpen
      $('advanced-screen').hidden = !state.advancedOpen
      $('btn-advanced').setAttribute('aria-expanded', String(state.advancedOpen))
      if (state.advancedOpen) {
        void Promise.all([refreshTools(), refreshFilesystem(), refreshSecurity(), refreshAudit()])
      }
    })
    $('modal-cancel').addEventListener('click', () => closeModal(false))
    $('modal-ok').addEventListener('click', () => {
      const input = $('modal-input-row').hidden ? undefined : $('modal-input').value.trim()
      closeModal(input === undefined ? true : input)
    })
    for (const button of document.querySelectorAll('[data-preset]')) {
      button.addEventListener('click', () => { void applyPreset(button.dataset.preset) })
    }
    // Real-time sync: the main process pushes backend revision changes.
    bridge.onConfigSync(async () => {
      await refreshConfig()
      const pill = $('pill-sync')
      pill.textContent = 'CONFIGURATION SYNCHRONIZED'
      pill.className = 'pill pill-ok'
      pill.hidden = false
      clearTimeout(state.syncFlashTimer)
      state.syncFlashTimer = setTimeout(() => { pill.hidden = true }, 3500)
    })

    await Promise.all([refreshConfig(), refreshStatus()])
    startPolling()
  }

  void init()
})()
