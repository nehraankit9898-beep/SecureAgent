import {FormEvent, ReactNode, useCallback, useEffect, useMemo, useState} from 'react'
import {api, publicHealth, setToken} from './api'
import type {Audit, AuthStatus, AgentMode, DiagnosticsReport, DocumentRecord, ExecutionResponse as Orchestration, Grant, Health, MemoryItem as Memory, ModeResponse, Notification, Permission, Schedule, ScheduleRun, SearchHit, SecurityReport, Settings, SystemHealth, SystemInfo, Task, TerminalStatus, ToolDef as Tool} from './contracts'
import SetupWizard from './SetupWizard'
import {ReportsPanel, TerminalPanel, WorkflowsPanel} from './panels'

type Tab = 'Dashboard' | 'Chat' | 'Tasks' | 'Agents' | 'Tools' | 'Memory' | 'Knowledge' | 'Automation' | 'Security' | 'Permissions' | 'Approvals' | 'Audit Logs' | 'Health' | 'Diagnostics' | 'Settings' | 'Terminal' | 'Workflows' | 'Reports'

const tabs: Tab[] = ['Dashboard', 'Chat', 'Workflows', 'Terminal', 'Tasks', 'Reports', 'Agents', 'Tools', 'Memory', 'Knowledge', 'Automation', 'Security', 'Permissions', 'Approvals', 'Audit Logs', 'Health', 'Diagnostics', 'Settings']
const simpleTabs: Tab[] = ['Dashboard', 'Chat', 'Workflows', 'Terminal', 'Tasks', 'Reports', 'Health', 'Diagnostics']
const glyph: Record<Tab, string> = {Dashboard: 'D', Chat: 'C', Tasks: 'T', Agents: 'A', Tools: 'X', Memory: 'M', Knowledge: 'K', Automation: 'U', Security: 'S', Permissions: 'R', Approvals: 'P', 'Audit Logs': 'L', Health: 'H', Diagnostics: '⌕', Settings: 'G', Terminal: '›', Workflows: 'W', Reports: 'R'}
const roles = [
  ['Manager', 'Delegates once and owns completion'],
  ['Planner', 'Creates bounded low-risk plans'],
  ['Research', 'Uses approved network search'],
  ['Coding', 'Inspects and edits an approved workspace'],
  ['File', 'Uses confined file operations'],
  ['Reviewer', 'Checks execution evidence'],
  ['Security', 'Checks permissions and trust boundaries'],
]

function Status({value}: {value: string}) { return <span className={`status ${value}`}>{value.replaceAll('_', ' ')}</span> }
function Empty({children}: {children: string}) { return <div className="empty"><span>✦</span><p>{children}</p></div> }
function Panel({title, children}: {title: string; children: ReactNode}) { return <article className="panel"><p className="eyebrow">{title}</p>{children}</article> }
function Toggle({label,value,set,disabled=false}:{label:string;value:boolean;set:(value:boolean)=>void;disabled?:boolean}) { return <label className="toggle-setting"><span>{label}</span><input type="checkbox" checked={value} disabled={disabled} onChange={(event)=>set(event.target.checked)}/></label> }
function NumberSetting({label,value,min,max,set}:{label:string;value:number;min:number;max:number;set:(value:number)=>void}) { return <label>{label}<input type="number" value={value} min={min} max={max} onChange={(event)=>set(Number(event.target.value))}/></label> }

export default function App() {
  const [tab, setTab] = useState<Tab>('Dashboard')
  const [tasks, setTasks] = useState<Task[]>([])
  const [tools, setTools] = useState<Tool[]>([])
  const [memories, setMemories] = useState<Memory[]>([])
  const [schedules, setSchedules] = useState<Schedule[]>([])
  const [audits, setAudits] = useState<Audit[]>([])
  const [documents, setDocuments] = useState<DocumentRecord[]>([])
  const [scheduleRuns, setScheduleRuns] = useState<ScheduleRun[]>([])
  const [systemHealth, setSystemHealth] = useState<SystemHealth | null>(null)
  const [settings, setSettings] = useState<Settings | null>(null)
  const [health, setHealth] = useState<Health | null>(null)
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null)
  const [message, setMessage] = useState('')
  const [memoryText, setMemoryText] = useState('')
  const [docPath, setDocPath] = useState('')
  const [docTitle, setDocTitle] = useState('')
  const [docReindex, setDocReindex] = useState(false)
  const [search, setSearch] = useState('')
  const [scheduleName,setScheduleName]=useState('')
  const [schedulePrompt,setSchedulePrompt]=useState('')
  const [scheduleRunAt,setScheduleRunAt]=useState('')
  const [scheduleKind,setScheduleKind]=useState<'once'|'interval'>('once')
  const [scheduleIntervalMinutes,setScheduleIntervalMinutes]=useState(60)
  const [hits, setHits] = useState<SearchHit[]>([])
  const [tokenDraft, setTokenDraft] = useState('')
  const [permissions, setPermissions] = useState<Permission[]>(['read'])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [desktopSetup, setDesktopSetup] = useState(false)
  const [desktopConfig, setDesktopConfig] = useState<DesktopSettings | null>(null)
  const [ollamaState, setOllamaState] = useState<OllamaStatus | null>(null)
  const [availableModels, setAvailableModels] = useState<string[]>([])
  const [settingsNotice, setSettingsNotice] = useState('')
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<string | null>(null)
  const [offline, setOffline] = useState(false)
  const [conversationId, setConversationId] = useState<string | undefined>()
  const [requestController, setRequestController] = useState<AbortController | null>(null)
  const [memoryQuery, setMemoryQuery] = useState('')
  const [auditQuery, setAuditQuery] = useState('')
  const [auditLimit, setAuditLimit] = useState(100)
  const [desktopBackend, setDesktopBackend] = useState<DesktopBackendState | null>(null)
  const [mode, setMode] = useState<'simple' | 'advanced'>(() => (localStorage.getItem('secureagent-mode') === 'advanced' ? 'advanced' : 'simple'))
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [showNotifications, setShowNotifications] = useState(false)
  const [terminalStatus, setTerminalStatus] = useState<TerminalStatus | null>(null)
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null)
  const [grants, setGrants] = useState<Grant[]>([])
  const [grantDraft, setGrantDraft] = useState<Permission>('read')
  // --- SecureAgent 2.0 additions ---
  const [agentMode, setAgentMode] = useState<AgentMode | null>(null)
  const [emergencyActive, setEmergencyActive] = useState(false)
  const [diagnosticsReport, setDiagnosticsReport] = useState<DiagnosticsReport | null>(null)
  const [diagnosticsRunning, setDiagnosticsRunning] = useState(false)
  const visibleTabs = mode === 'simple' ? simpleTabs : tabs

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const publicStatus = await publicHealth()
      setHealth(publicStatus); setOffline(false)
      const [taskRows, toolRows, memoryRows, scheduleRows, auditRows, runtime, documentRows, runRows, detailedHealth] = await Promise.all([
        api<Task[]>('/agent/tasks' + '?limit=200'), api<Tool[]>('/tools'), api<Memory[]>('/memories' + '?limit=200'),
        api<Schedule[]>('/schedules'), api<Audit[]>(`/audit?limit=${auditLimit}`), api<Settings>('/settings'),
        api<DocumentRecord[]>('/documents'), api<ScheduleRun[]>('/schedule-runs' + '?limit=200'), api<SystemHealth>('/system/health'),
      ])
      setTasks(taskRows); setTools(toolRows); setMemories(memoryRows); setSchedules(scheduleRows); setAudits(auditRows); setSettings(runtime)
      setDocuments(documentRows); setScheduleRuns(runRows); setSystemHealth(detailedHealth); setLastUpdated(new Date().toISOString())
      const [notificationRows, terminal, info, grantRows, modeResp] = await Promise.all([
        api<Notification[]>('/notifications').catch(() => [] as Notification[]),
        api<TerminalStatus>('/terminal/status').catch(() => null),
        api<SystemInfo>('/system/info').catch(() => null),
        api<Grant[]>('/permissions/grants').catch(() => [] as Grant[]),
        api<ModeResponse>('/mode').catch(() => null),
      ])
      setNotifications(notificationRows); setTerminalStatus(terminal); setSystemInfo(info); setGrants(grantRows)
      if (modeResp) { setAgentMode(modeResp.mode); setEmergencyActive(modeResp.emergency_stopped) }
      else { setEmergencyActive(false) }
    } catch (reason) {
      setOffline(reason instanceof Error && /BACKEND_UNAVAILABLE|timed out/i.test(reason.message))
      throw reason
    } finally { setLoading(false) }
  }, [auditLimit])

  useEffect(() => {
    void (async () => {
      try {
        if (window.secureAgent) {
          const bootstrap = await window.secureAgent.bootstrap()
          setDesktopBackend(bootstrap.backend)
          setDesktopConfig(await window.secureAgent.getSettings())
          if (!bootstrap.setupComplete) {
            setHealth(await publicHealth())
            setDesktopSetup(true)
            return
          }
        }
        const [publicStatus, authentication] = await Promise.all([
          publicHealth(),
          api<AuthStatus>('/auth/status'),
        ])
        setHealth(publicStatus)
        setAuthStatus(authentication)
        // Inside the desktop shell the IPC broker injects the ephemeral token
        // into every request, so a required-token report does NOT block data
        // loading — showing "enter the local API token" would be false. The
        // explicit token prompt only makes sense in standalone browser mode.
        if (!authentication.required || authentication.local_bypass || window.secureAgent) await refresh()
        else setError('Authentication is required. Open Settings and enter the local API token.')
      } catch (reason: unknown) {
        setError(reason instanceof Error ? reason.message : 'Unable to load dashboard')
      }
    })()
  }, [refresh])
  useEffect(() => {
    if (!window.secureAgent) return
    return window.secureAgent.onLaunchStatus((status)=>{setDesktopBackend(status);if(status.state==='READY')void refresh().catch(()=>undefined);if(status.state==='ERROR'||status.state==='STOPPED')setOffline(true)})
  }, [refresh])
  // SecureAgent 2.0: subscribe to live config-sync events so the dashboard
  // refreshes immediately when the Control Center toggles a switch, instead
  // of waiting up to 15s for the polling timer (spec section 28).
  useEffect(() => {
    if (!window.secureAgent?.onConfigSync) return
    return window.secureAgent.onConfigSync(() => { void refresh().catch(() => undefined) })
  }, [refresh])
  useEffect(() => {
    const timer = window.setInterval(() => { if (document.visibilityState === 'visible' && !busy) void refresh().catch(() => undefined) }, 15_000)
    return () => window.clearInterval(timer)
  }, [refresh, busy])
  const waiting = useMemo(() => tasks.filter((task) => task.status === 'waiting_confirmation'), [tasks])
  const latest = tasks[0]
  const toggle = (permission: Permission) => setPermissions((current) => current.includes(permission) ? current.filter((item) => item !== permission) : [...current, permission])
  const run = async (operation: () => Promise<void>) => {
    setBusy(true); setError('')
    try { await operation() }
    catch (reason: unknown) { setError(reason instanceof Error ? reason.message : 'Operation failed') }
    finally { setBusy(false) }
  }

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!message.trim()) return
    void run(async () => {
      const controller = new AbortController(); setRequestController(controller)
      try {
        const result = await api<Orchestration>('/orchestrate', {method: 'POST', body: JSON.stringify({message, conversation_id: conversationId, approved_permissions: permissions}), timeoutMs: 130_000, signal: controller.signal})
        if (!result || !result.task || typeof result.task.id !== 'string') throw new Error('Backend returned an invalid agent response')
        setConversationId(result.task.conversation_id); setMessage(''); setTasks((current) => [result.task, ...current.filter((task) => task.id !== result.task.id)]); await refresh()
      } finally { setRequestController(null) }
    })
  }
  const cancelTask = (taskId: string) => void run(async () => { await api<Task>(`/agent/tasks/${taskId}/cancel`, {method:'POST'}); await refresh() })
  const switchMode = (next: 'simple' | 'advanced') => {
    setMode(next); localStorage.setItem('secureagent-mode', next)
    if (next === 'simple' && !simpleTabs.includes(tab)) setTab('Dashboard')
  }
  const openReport = (report: SecurityReport) => { void refresh(); setTab('Reports') }
  const addGrant = () => void run(async () => {
    await api('/permissions/grants', {method: 'POST', body: JSON.stringify({permission: grantDraft, scope: 'always', note: 'granted from Permission Center'})})
    setGrants(await api<Grant[]>('/permissions/grants')); await refresh()
  })
  const removeGrant = (id: string) => void run(async () => {
    await api(`/permissions/grants/${id}`, {method: 'DELETE'})
    setGrants(await api<Grant[]>('/permissions/grants')); await refresh()
  })
  const retryTask = (task: Task) => { setTab('Chat'); setMessage(task.goal); setConversationId(task.conversation_id) }
  // SecureAgent 2.0: Stop button now also cancels the backend task (spec section 31).
  // The previous behaviour only aborted the client HTTP request, leaving the
  // backend running — misleading. We now: (1) abort the client request,
  // (2) call POST /agent/tasks/{id}/cancel for the latest task,
  // (3) refresh so the task status reflects the real backend state.
  const stopRequest = () => {
    requestController?.abort()
    setSettingsNotice('Generation request cancelled. Refresh Tasks to see any backend result already committed.')
    const latestTask = tasks[0]
    if (latestTask && ['planning', 'running', 'waiting_confirmation'].includes(latestTask.status)) {
      void api<Task>(`/agent/tasks/${latestTask.id}/cancel`, {method: 'POST'})
        .then(() => void refresh())
        .catch(() => undefined)
    }
  }
  // SecureAgent 2.0: EMERGENCY STOP — globally accessible from the Dashboard
  // header (spec section 31). Cancels agent tasks, kills terminal process
  // groups, pauses automation, preserves audit logs. The backend is the
  // authority; this button just calls POST /emergency-stop.
  const emergencyStop = () => {
    if (!window.confirm('EMERGENCY STOP will cancel all running agent tasks, kill all terminal processes, and pause automation. Audit logs are preserved. Continue?')) return
    void run(async () => {
      await api('/emergency-stop', {method: 'POST', timeoutMs: 15_000})
      setEmergencyActive(true)
      setSettingsNotice('EMERGENCY STOP applied. All running tasks cancelled, terminal processes killed, automation paused. Click RESUME to restore.')
      await refresh()
    })
  }
  const resumeFromEmergency = () => void run(async () => {
    await api('/resume', {method: 'POST', timeoutMs: 15_000})
    setEmergencyActive(false)
    setSettingsNotice('Resumed from EMERGENCY STOP. Pre-emergency configuration restored.')
    await refresh()
  })
  // SecureAgent 2.0: SAFE / ASSIST / CONTROL mode surface (spec section 4).
  const applyMode = (next: 'SAFE' | 'ASSIST' | 'CONTROL') => void run(async () => {
    if (next === 'CONTROL' && !window.confirm('CONTROL mode enables advanced local control: sudo (approval-required), full network, automatic workflows. Destructive/irreversible actions still require confirmation. Continue?')) return
    await api('/mode', {method: 'POST', body: JSON.stringify({mode: next})})
    setSettingsNotice(`Mode set to ${next}.`)
    await refresh()
  })
  // SecureAgent 2.0: run the full feature self-test (spec section 11).
  const runDiagnostics = () => {
    setDiagnosticsRunning(true)
    void run(async () => {
      const report = await api<DiagnosticsReport>('/diagnostics', {timeoutMs: 60_000})
      setDiagnosticsReport(report)
      setSettingsNotice(`Diagnostics complete: ${report.summary.pass} PASS, ${report.summary.warning} WARNING, ${report.summary.fail} FAIL, ${report.summary.not_available} NOT_AVAILABLE.`)
    }).finally(() => setDiagnosticsRunning(false))
  }
  const searchMemories = () => void run(async () => setMemories(await api<Memory[]>(`/memories?query=${encodeURIComponent(memoryQuery)}&limit=200`)))
  const editMemory = (memory: Memory) => { const value=window.prompt('Update memory', memory.content); if(value?.trim()) void run(async()=>{await api<Memory>(`/memories/${memory.id}`,{method:'PATCH',body:JSON.stringify({content:value.trim()})});await refresh()}) }
  const deleteMemory = (id:string) => { if(window.confirm('Delete this memory?')) void run(async()=>{await api(`/memories/${id}`,{method:'DELETE'});await refresh()}) }
  const deleteDocument = (id:string) => { if(window.confirm('Delete this indexed document?')) void run(async()=>{await api(`/documents/${id}`,{method:'DELETE'});await refresh()}) }
  const updateSchedule = (id:string, enabled:boolean) => void run(async()=>{await api(`/schedules/${id}`,{method:'PATCH',body:JSON.stringify({enabled})});await refresh()})
  const deleteSchedule = (id:string) => { if(window.confirm('Delete this automation and its schedule?')) void run(async()=>{await api(`/schedules/${id}`,{method:'DELETE'});await refresh()}) }

  const saveMemory = (event: FormEvent) => {
    event.preventDefault()
    if (!memoryText.trim()) return
    void run(async () => { await api<Memory>('/memories', {method: 'POST', body: JSON.stringify({content: memoryText, category: 'preference'})}); setMemoryText(''); await refresh() })
  }
  const ingest = (event: FormEvent) => {
    event.preventDefault()
    if (!docPath.trim()) return
    void run(async () => { await api('/documents', {method: 'POST', body: JSON.stringify({path: docPath.trim(), title: docTitle.trim() || null, reindex: docReindex}), timeoutMs: 120_000}); setDocPath(''); setDocTitle(''); setDocReindex(false); await refresh() })
  }
  const searchDocs = (event: FormEvent) => {
    event.preventDefault()
    if (!search.trim()) return
    void run(async () => setHits(await api<SearchHit[]>('/documents/search', {method: 'POST', body: JSON.stringify({query: search, limit: 6}), timeoutMs: 60_000})))
  }
  const approve = (task: Task, scope: 'once'|'session') => void run(async () => { const step=task.steps.find((item)=>item.status==='waiting_confirmation'); const tool=tools.find((item)=>item.name===step?.tool); await api<Task>(`/agent/tasks/${task.id}/resume`, {method: 'POST', body: JSON.stringify({approved_permissions: tool?.permissions || [], scope})}); await refresh() })
  const reject = (taskId: string) => void run(async () => { await api<Task>(`/agent/tasks/${taskId}/reject`, {method: 'POST'}); await refresh() })
  const cancelSchedule = (scheduleId: string) => void run(async () => { await api(`/schedules/${scheduleId}/cancel`, {method: 'POST'}); await refresh() })
  const approveSchedule = (scheduleId:string) => void run(async()=>{await api(`/schedules/${scheduleId}/approve`,{method:'POST'});await refresh()})
  const createSchedule = (event:FormEvent) => {
    event.preventDefault()
    if(!scheduleName.trim()||!schedulePrompt.trim()) return
    if(scheduleKind==='once'&&!scheduleRunAt) return setError('Choose a future run date and time.')
    if(scheduleKind==='interval'&&(!Number.isInteger(scheduleIntervalMinutes)||scheduleIntervalMinutes<1||scheduleIntervalMinutes>525600)) return setError('Interval must be between 1 and 525600 minutes.')
    const allowed=['calculator','date_time','text_processing',...(permissions.includes('read')?['list_files','read_file']:[]),...(permissions.includes('write')?['write_file']:[]),...(permissions.includes('network')?['web_search']:[])]
    const payload={name:scheduleName.trim(),prompt:schedulePrompt.trim(),kind:scheduleKind,run_at:scheduleKind==='once'?new Date(scheduleRunAt).toISOString():null,interval_seconds:scheduleKind==='interval'?scheduleIntervalMinutes*60:null,approved_permissions:permissions,allowed_tools:allowed,max_runtime:desktopConfig?.automationMaxRuntimeSeconds||300,network_policy:permissions.includes('network')?'allow':'deny'}
    void run(async()=>{await api('/schedules',{method:'POST',body:JSON.stringify(payload)});setScheduleName('');setSchedulePrompt('');setScheduleRunAt('');setScheduleIntervalMinutes(60);await refresh()})
  }
  const changeDesktop = <K extends keyof DesktopSettings>(key: K, value: DesktopSettings[K]) => setDesktopConfig((current) => current ? {...current, [key]: value} : current)
  const saveDesktop = () => void run(async () => {
    if (!window.secureAgent || !desktopConfig) return
    const result = await window.secureAgent.updateSettings(desktopConfig)
    setDesktopConfig(result.settings); setOllamaState(result.ollama); setSettingsNotice('✓ Settings Saved · ✓ Backend Restarted · ✓ Configuration Applied'); await refresh()
  })
  const saveSettingsOnly = () => void run(async () => { if(window.secureAgent && desktopConfig){const result=await window.secureAgent.saveSettings(desktopConfig);setDesktopConfig(result.settings);setSettingsNotice(`✓ ${result.message}`)}})
  const resetSettings = () => void run(async () => {if(window.secureAgent){setDesktopConfig(await window.secureAgent.resetSettings());setSettingsNotice('Defaults loaded. Select Apply to restart with these values.')}})
  const testOllama = () => void run(async () => {
    if (!window.secureAgent) return
    const result = await window.secureAgent.testOllama(); setOllamaState(result); setAvailableModels(result.models)
  })
  const refreshModels = () => void run(async () => { if (window.secureAgent) setAvailableModels(await window.secureAgent.refreshModels()) })
  const testChatModel = () => void run(async () => { if (window.secureAgent) { const result = await window.secureAgent.testChatModel(); setSettingsNotice(`✓ ${result.status}: ${result.model} — ${result.response}`) } })
  const testEmbeddingModel = () => void run(async () => { if (window.secureAgent) { const result = await window.secureAgent.testEmbeddingModel(); setSettingsNotice(`✓ ${result.status}: ${result.model} — ${result.dimension} dimensions`) } })
  const pullModels = (models: string[]) => void run(async () => { if (window.secureAgent) { await window.secureAgent.installModels(models); await testOllama() } })
  const testNetwork = () => void run(async () => { if (window.secureAgent) { const result = await window.secureAgent.testNetwork(); setSettingsNotice(`✓ ${result.status}: ${result.provider}, ${result.result_count} results, ${result.duration_ms} ms`) } })
  const diagnostics = () => void run(async () => { if (window.secureAgent) { const result = await window.secureAgent.createDiagnostics(); setSettingsNotice(`✓ Diagnostics created: ${result.markdownPath}`) } })
  const runDiagnostic = (component:'backend'|'agent'|'tools'|'permissions'|'search') => void run(async()=>{if(window.secureAgent){const result=await window.secureAgent.runDiagnostic(component);setSettingsNotice(`${component}: ${String(result.status || 'completed')}`)}})

  if (desktopSetup && window.secureAgent) return <SetupWizard onComplete={() => {
    setDesktopSetup(false)
    void run(refresh)
  }}/>

  return <div className="app-shell">
    <aside><div className="brand"><div className="mark">A</div><div><strong>SecureAgent</strong><small>Local workspace</small></div></div>
      <nav>{visibleTabs.map((item) => <button className={tab === item ? 'active' : ''} onClick={() => setTab(item)} key={item}><span>{glyph[item]}</span>{item}</button>)}</nav>
      <div className="aside-foot"><div className="system-dot"/><div><strong>{desktopBackend?.state || (offline ? 'ERROR' : health?.status === 'ok' ? 'READY' : 'STOPPED')}</strong><small>{settings?.active_provider || 'LOCAL CORE'}</small></div></div>
    </aside>
    <main><header><div><p className="eyebrow">SECURE AGENT 2.0 / {tab.toUpperCase()}</p><h1>{tab}</h1></div><div className="header-actions">
      {/* SecureAgent 2.0: SAFE / ASSIST / CONTROL mode selector (spec section 4) */}
      <div className="mode-switch" role="group" aria-label="Agent mode" title="Agent operating mode — applies a curated policy preset to the backend ControlState">
        <button className={agentMode === 'SAFE' ? 'active mode-safe' : ''} onClick={() => void applyMode('SAFE')} disabled={busy}>SAFE</button>
        <button className={agentMode === 'ASSIST' ? 'active mode-assist' : ''} onClick={() => void applyMode('ASSIST')} disabled={busy}>ASSIST</button>
        <button className={agentMode === 'CONTROL' ? 'active mode-control' : ''} onClick={() => void applyMode('CONTROL')} disabled={busy}>CONTROL</button>
      </div>
      <div className="mode-switch" role="group" aria-label="Interface mode"><button className={mode === 'simple' ? 'active' : ''} onClick={() => switchMode('simple')}>Simple</button><button className={mode === 'advanced' ? 'active' : ''} onClick={() => switchMode('advanced')}>Advanced</button></div>
      {/* SecureAgent 2.0: globally accessible EMERGENCY STOP / RESUME (spec section 31) */}
      {emergencyActive
        ? <button className="danger emergency-stop" onClick={resumeFromEmergency} disabled={busy} title="Restore the pre-emergency configured state">RESUME</button>
        : <button className="danger emergency-stop" onClick={emergencyStop} disabled={busy} title="Cancel all running tasks, kill terminal processes, pause automation">STOP ALL</button>}
      <div className="bell-wrap"><button className="quiet" aria-label="Notifications" onClick={() => setShowNotifications((current) => !current)}>Notifications{notifications.length > 0 ? ` (${notifications.length})` : ''}</button>{showNotifications && <div className="notification-pop">{notifications.length ? notifications.map((item) => <div key={item.id} className={`notification sev-${item.severity}`}><p>{item.message}</p><small>{item.kind.replaceAll('_', ' ')}</small></div>) : <div className="notification"><p>No notifications. Everything looks calm.</p></div>}</div>}</div>
      {lastUpdated&&<small>Updated {new Date(lastUpdated).toLocaleTimeString()}</small>}
      <button className="quiet" disabled={busy||loading} onClick={() => void run(refresh)}>{loading?'Refreshing…':'Refresh'}</button>
    </div></header>
      {emergencyActive && <div className="alert emergency-banner"><b>EMERGENCY STOP ACTIVE</b><span>All running tasks cancelled, terminal processes killed, automation paused. Audit logs preserved.</span><button onClick={resumeFromEmergency}>Resume now</button></div>}
      {settingsNotice && <div className="alert info-banner">{settingsNotice}<button onClick={() => setSettingsNotice('')}>×</button></div>}
      {offline && <div className="offline"><b>Backend unavailable</b><span>The application shell remains available. Data shown may be stale.</span><button onClick={()=>void run(refresh)}>Retry connection</button></div>}
      {error && <div className="alert">{error}<button onClick={() => setError('')}>×</button></div>}
      {tab === 'Dashboard' && <section className="grid-list dashboard"><Panel title="SYSTEM"><h2>{offline?'DISCONNECTED':systemHealth?.status?.toUpperCase()||'UNKNOWN'}</h2><p>Backend {systemHealth?.backend||'unknown'} · Database {systemHealth?.database||'unknown'} · Agent {systemHealth?.agent||'unknown'}</p></Panel><Panel title="TASKS"><h2>{tasks.filter(t=>['planning','running'].includes(t.status)).length} active</h2><p>{tasks.filter(t=>t.status==='completed').length} completed · {tasks.filter(t=>t.status==='failed').length} failed · {waiting.length} approvals</p></Panel><Panel title="OLLAMA / NETWORK"><h2>{systemHealth?.ollama||'unknown'}</h2><p>Chat model {systemHealth?.chat_model||'unknown'} · Network {systemHealth?.network||'unknown'}</p></Panel><Panel title="TOOLS / PERMISSIONS"><h2>{tools.filter(t=>t.enabled).length} / {tools.length} enabled</h2><p>Permission subsystem {systemHealth?.permissions||'unknown'} · {tools.filter(t=>t.requires_approval).length} approval-gated</p></Panel><Panel title="MEMORY / KNOWLEDGE"><h2>{memories.length} memories</h2><p>{documents.length} indexed documents · {documents.reduce((sum,d)=>sum+(d.chunk_count||0),0)} chunks</p></Panel><Panel title="TERMINAL"><h2>{terminalStatus?.available ? 'AVAILABLE' : 'RESTRICTED'}</h2><p>{terminalStatus?.backend || 'unknown'} backend · policy-classified commands · full audit trail</p></Panel><Panel title="LINUX HOST"><h2>{systemInfo?.distro?.name || systemInfo?.platform || 'detecting…'}</h2><p>Kernel {systemInfo?.kernel || '?'} · {systemInfo?.architecture || '?'} · shell {systemInfo?.shell?.path || '?'}{systemInfo?.missing_optional_tools?.length ? ` · ${systemInfo.missing_optional_tools.length} optional security tools missing` : ''}</p></Panel><Panel title="AUTOMATION / AUDIT"><h2>{schedules.filter(s=>s.enabled&&!s.cancelled).length} active</h2><p>{scheduleRuns.length} recorded runs · {audits.length} recent audit events</p></Panel></section>}
      {tab === 'Chat' && <section className="chat-layout"><div className="conversation"><div className="chat-toolbar"><button className="quiet" onClick={()=>{setConversationId(undefined);setMessage('')}}>New conversation</button><span>{conversationId?'Conversation active':'New conversation'}</span></div><div className="hero"><span className="hero-mark">{settings?.generative_available ? 'AI' : 'LC'}</span><h2>What should we work on?</h2><p>Provider: {settings?.active_provider || 'LOCAL CORE'} · {settings?.generative_available ? `Model: ${settings.model}` : 'Generative AI unavailable. Local Core never fabricates AI answers; Ollama is required for open-ended reasoning.'}</p></div>{latest && <article className="result"><div className="result-head"><span>Latest task</span><Status value={latest.status}/></div><h3>{latest.goal}</h3>{latest.answer && <p>{latest.answer}</p>}{latest.steps.map((step) => <p key={step.id}><b>{step.tool}</b> — {step.status}</p>)}</article>}<form className="composer" onSubmit={submit}><textarea aria-label="Message" value={message} onChange={(event) => setMessage(event.target.value)} placeholder="Ask the agent to plan or complete a task…"/><div className="composer-row"><div className="permissions">{(['read', 'write', 'execute', 'network'] as Permission[]).map((permission) => <button type="button" className={permissions.includes(permission) ? 'selected' : ''} onClick={() => toggle(permission)} key={permission}>{permission}</button>)}</div>{requestController&&<button type="button" className="danger compact" onClick={stopRequest}>Stop</button>}<button className="send" disabled={busy}>{busy ? 'Working…' : 'Run task →'}</button></div></form></div><aside className="context"><p className="eyebrow">APPROVAL BOUNDARY</p><p>Only selected request permissions are forwarded. Role policy can narrow them further.</p></aside></section>}
      {tab === 'Tasks' && <section className="grid-list">{tasks.length ? tasks.map((task) => <article className="card" key={task.id}><div><Status value={task.status}/><time>{new Date(task.updated_at).toLocaleString()}</time></div><h3>{task.goal}</h3><p>{task.answer || task.errors[0] || `${task.steps.length} planned steps`}</p><details><summary>Execution details</summary>{task.steps.map(step=><div className="step-detail" key={step.id}><b>{step.tool}</b><Status value={step.status}/>{step.result&&<pre>{JSON.stringify(step.result,null,2)}</pre>}</div>)}</details><div className="button-row">{!['completed','cancelled'].includes(task.status)&&<button className="danger" disabled={busy} onClick={()=>cancelTask(task.id)}>Cancel</button>}{['failed','cancelled'].includes(task.status)&&<button onClick={()=>retryTask(task)}>Retry in Chat</button>}</div></article>) : <Empty>No task history yet.</Empty>}</section>}
      {tab === 'Agents' && <section className="grid-list">{roles.map(([name, description]) => <article className="card" key={name}><span className="label">scoped role</span><h3>{name}</h3><p>{description}</p></article>)}</section>}
      {tab === 'Tools' && <section className="tool-grid">{tools.map((tool) => <article className="tool" key={tool.name}><div className="tool-icon" aria-hidden="true">◆</div><div><h3>{tool.name}</h3><p>{tool.description}</p>{!tool.enabled&&<p>{tool.disabled_reason}</p>}<div><span className="label">{tool.risk_level}</span><span className="label">approval: {tool.requires_approval?'required':'not required'}</span>{tool.permissions.map((permission) => <span className="label" key={permission}>{permission}</span>)}</div></div><span className={`availability ${tool.enabled ? 'on' : ''}`}>{tool.enabled ? 'enabled' : 'disabled'}</span></article>)}</section>}
      {tab === 'Memory' && <section><form className="inline-form" onSubmit={saveMemory}><input value={memoryText} onChange={(event) => setMemoryText(event.target.value)} placeholder="Save a non-sensitive preference…"/><button disabled={busy}>Save memory</button></form><div className="inline-form"><input value={memoryQuery} onChange={e=>setMemoryQuery(e.target.value)} placeholder="Search memories"/><button type="button" onClick={searchMemories}>Search</button><button type="button" className="quiet" onClick={()=>{setMemoryQuery('');void run(refresh)}}>Clear</button></div><div className="grid-list">{memories.length?memories.map((memory) => <article className="card" key={memory.id}><span className="label">{memory.category}</span><h3>{memory.content}</h3><time>{new Date(memory.updated_at).toLocaleString()}</time><div className="button-row"><button onClick={()=>editMemory(memory)}>Edit</button><button className="danger" onClick={()=>deleteMemory(memory.id)}>Delete</button></div></article>):<Empty>No matching memories.</Empty>}</div></section>}
      {tab === 'Knowledge' && <section className="knowledge"><Panel title="INGEST"><h2>Add a workspace document</h2><p>PDF, DOCX, Markdown, text, source, JSON, CSV, HTML, and CSS are supported.</p><form className="stack-form" onSubmit={ingest}><label>Workspace path<input value={docPath} onChange={(event) => setDocPath(event.target.value)} placeholder="notes/project-brief.pdf" required/></label><label>Display title (optional)<input value={docTitle} onChange={(event) => setDocTitle(event.target.value)} maxLength={300}/></label><Toggle label="Replace duplicate document" value={docReindex} set={setDocReindex}/><button disabled={busy||!docPath.trim()}>Index document</button></form></Panel><Panel title="SEMANTIC SEARCH"><h2>Search indexed knowledge</h2><form className="inline-form" onSubmit={searchDocs}><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search query"/><button disabled={busy}>Search</button></form>{hits.map((hit) => <article className="hit" key={`${hit.path}-${hit.score}`}><div><b>{hit.title}</b><span>{Math.round(hit.score * 100)}% match</span></div><p>{hit.content}</p></article>)}</Panel><Panel title="INDEXED DOCUMENTS"><h2>{documents.length} ready</h2>{documents.length?documents.map(doc=><article className="document-row" key={doc.id}><div><b>{doc.title}</b><small>{doc.path} · {doc.chunk_count} chunks · v{doc.version}</small></div><button className="danger compact" onClick={()=>deleteDocument(doc.id)}>Delete</button></article>):<Empty>No indexed documents.</Empty>}</Panel></section>}
      {tab === 'Automation' && <section><form className="schedule-form card" onSubmit={createSchedule}><p className="eyebrow">CREATE AUTOMATION</p><input value={scheduleName} onChange={(e)=>setScheduleName(e.target.value)} placeholder="Schedule name" required/><textarea value={schedulePrompt} onChange={(e)=>setSchedulePrompt(e.target.value)} placeholder="Task prompt" required/><label>Schedule type<select value={scheduleKind} onChange={e=>setScheduleKind(e.target.value as 'once'|'interval')}><option value="once">One time</option><option value="interval">Recurring interval</option></select></label>{scheduleKind==='once'?<label>Run at<input type="datetime-local" value={scheduleRunAt} onChange={(e)=>setScheduleRunAt(e.target.value)} required/></label>:<label>Repeat every (minutes)<input type="number" min={1} max={525600} value={scheduleIntervalMinutes} onChange={e=>setScheduleIntervalMinutes(Number(e.target.value))} required/></label>}<p>Requested permissions: {permissions.join(', ')||'none'}. Protected schedules remain disabled until separately approved.</p><button disabled={busy||!settings?.automation}>Create Schedule</button></form><div className="grid-list">{schedules.length ? schedules.map((schedule) => {const pending=Boolean(schedule.policy?.approval_required)&&!Boolean(schedule.policy?.approval_granted);return <article className="card" key={schedule.id}><div><Status value={schedule.cancelled ? 'cancelled' : pending?'waiting_confirmation':schedule.enabled ? 'running' : 'disabled'}/><time>{new Date(schedule.next_run).toLocaleString()}</time></div><h3>{schedule.name}</h3><p>{schedule.kind}{schedule.interval_seconds?` every ${Math.round(schedule.interval_seconds/60)} minutes`:''} · permissions: {schedule.permissions.join(', ') || 'none'}</p><div className="button-row">{pending&&<button disabled={busy} onClick={()=>approveSchedule(schedule.id)}>Approve Schedule</button>}{!schedule.cancelled&&<button disabled={busy} onClick={()=>updateSchedule(schedule.id,!schedule.enabled)}>{schedule.enabled?'Disable':'Enable'}</button>}{!schedule.cancelled&&<button className="quiet" disabled={busy} onClick={() => cancelSchedule(schedule.id)}>Cancel</button>}<button className="danger" disabled={busy} onClick={()=>deleteSchedule(schedule.id)}>Delete</button></div></article>}) : <Empty>No automation schedules.</Empty>}</div><h2 className="section-title">Execution history</h2><div className="grid-list">{scheduleRuns.length?scheduleRuns.map(item=><article className="card" key={item.id}><div><Status value={item.status}/><time>{new Date(item.created_at).toLocaleString()}</time></div><h3>{schedules.find(s=>s.id===item.schedule_id)?.name||item.schedule_id}</h3><p>{item.answer||item.errors.join('; ')||'No output recorded'}</p></article>):<Empty>No automation runs.</Empty>}</div></section>}
      {tab === 'Security' && <section className="settings"><Panel title="RUNTIME POLICY"><h2>{settings?.environment || 'Unknown'}</h2><p>Authentication: {settings?.authentication ? 'required' : 'development bypass'}</p><p>Host Python: {settings?.python_execution || 'unknown'}</p></Panel><Panel title="TOOL POLICY"><h2>{tools.filter((tool) => tool.risk_level === 'high').length} high-risk tools</h2><p>{tools.filter((tool) => tool.sandbox_required).length} sandbox-required · {tools.filter((tool) => tool.network_required).length} network-required</p></Panel></section>}
      {tab === 'Permissions' && <section className="settings"><Panel title="EFFECTIVE POLICY"><h2>{settings?.approval_mode||'unknown'}</h2><p>High-risk approval is enforced by the backend. Permission grants are request-scoped; the frontend never bypasses tool authorization.</p>{(['read','write','execute','network','schedule','automation','admin'] as Permission[]).map(name=><div className="setting" key={name}><span>{name}</span><b>{tools.filter(t=>t.permissions.includes(name)).length} tools</b></div>)}</Panel><Panel title="PERSISTENT GRANTS (ALWAYS ALLOW)"><p>'Always allow' grants persist across conversations and are loaded by the agent on every task. High-risk tools still show the exact command for approval; BLOCKED commands can never be approved.</p>{grants.length ? grants.map((grant) => <div className="setting" key={grant.id}><span>{grant.permission}</span><div className="grant-row"><small>{grant.note || 'always allow'}</small><button className="quiet compact danger" onClick={() => removeGrant(grant.id)}>Revoke</button></div></div>) : <p className="history-empty">No persistent grants. Every permission grant expires with its session by default.</p>}<div className="inline-form compact-form"><select value={grantDraft} onChange={(event) => setGrantDraft(event.target.value as Permission)} aria-label="Grant permission">{(['read','write','execute','network','schedule','automation'] as Permission[]).map((name) => <option key={name} value={name}>{name}</option>)}</select><button className="send" onClick={addGrant}>Always allow</button></div></Panel><Panel title="BACKEND-CONFIRMED CONTROLS"><Toggle label="Filesystem tools" value={Boolean(desktopConfig?.filesystemToolsEnabled)} disabled={!desktopConfig} set={v=>desktopConfig&&changeDesktop('filesystemToolsEnabled',v)}/><Toggle label="Network tools" value={Boolean(desktopConfig?.networkEnabled)} disabled={!desktopConfig} set={v=>desktopConfig&&changeDesktop('networkEnabled',v)}/><Toggle label="Automation" value={Boolean(desktopConfig?.automationEnabled)} disabled={!desktopConfig} set={v=>desktopConfig&&changeDesktop('automationEnabled',v)}/><p>Changes are drafts until Save or Apply & Restart in Settings confirms persistence.</p><button onClick={()=>setTab('Settings')}>Open Settings</button></Panel></section>}
      {tab === 'Approvals' && <section className="grid-list">{waiting.length ? waiting.map((task) => {const step=task.steps.find((item)=>item.status==='waiting_confirmation');const tool=tools.find((item)=>item.name===step?.tool);return <article className="card approval-card" key={task.id}><p className="eyebrow">SECUREAGENT APPROVAL REQUIRED</p><Status value={task.status}/><h3>{step?.title || task.goal}</h3><p><b>Tool:</b> {step?.tool}<br/><b>Risk:</b> {tool?.risk_level || 'unknown'}<br/><b>Permissions:</b> {tool?.permissions.join(', ') || 'none'}<br/><b>Network:</b> {tool?.network_required ? 'required' : 'not required'}</p><pre>{JSON.stringify(step?.arguments || {},null,2)}</pre><p>Allow only if the target and expected effect match your intent.</p><div className="button-row"><button className="danger" disabled={busy} onClick={()=>reject(task.id)}>Deny</button><button disabled={busy} onClick={()=>approve(task,'once')}>Allow Once</button><button disabled={busy} onClick={()=>approve(task,'session')}>Allow for Session</button></div></article>}) : <Empty>No tasks require approval.</Empty>}</section>}
      {tab === 'Terminal' && <TerminalPanel status={terminalStatus} onError={(message) => setError(message)}/>}
      {tab === 'Workflows' && <WorkflowsPanel onReport={openReport}/>}
      {tab === 'Reports' && <ReportsPanel/>}
      {tab === 'Audit Logs' && <section><div className="inline-form"><input value={auditQuery} onChange={e=>setAuditQuery(e.target.value)} placeholder="Filter loaded events"/><select value={auditLimit} onChange={e=>setAuditLimit(Number(e.target.value))}><option value={50}>50 events</option><option value={100}>100 events</option><option value={250}>250 events</option><option value={500}>500 events</option></select><button onClick={()=>void run(refresh)}>Load</button></div><div className="grid-list">{audits.filter(entry=>!auditQuery||`${entry.event} ${entry.actor} ${JSON.stringify(entry.details)}`.toLowerCase().includes(auditQuery.toLowerCase())).length ? audits.filter(entry=>!auditQuery||`${entry.event} ${entry.actor} ${JSON.stringify(entry.details)}`.toLowerCase().includes(auditQuery.toLowerCase())).map((entry) => <article className="card" key={entry.id}><div><span className="label">{entry.event}</span><time>{new Date(entry.created_at).toLocaleString()}</time></div><h3>{entry.actor}</h3><p>{JSON.stringify(entry.details)}</p></article>) : <Empty>No audit records.</Empty>}</div></section>}
      {tab === 'Health' && <section className="settings"><Panel title="SYSTEM HEALTH"><h2>{systemHealth?.status || health?.status || 'Unknown'}</h2><p>Version {systemHealth?.version || health?.version || 'unavailable'}</p>{systemHealth && Object.entries(systemHealth).filter(([key]) => !['status','version'].includes(key)).map(([key,value]) => <div className="setting" key={key}><span>{key.replaceAll('_',' ')}</span><b>{String(value)}</b></div>)}<button className="quiet" disabled={busy || !window.secureAgent} onClick={diagnostics}>Run Full Diagnostics</button></Panel><Panel title="PROVIDER"><h2>{settings?.active_provider || 'LOCAL CORE'}</h2><p>{settings?.generative_available ? `Ollama ready: ${settings.model}` : 'AI_REASONING_UNAVAILABLE: Ollama and the configured chat model are required.'}</p></Panel></section>}
      {tab === 'Diagnostics' && <section className="settings">
        <Panel title="FEATURE SELF-TEST (SPEC §11)">
          <h2>{diagnosticsReport ? `Overall: ${diagnosticsReport.overall}` : 'Click Run to execute every feature self-test.'}</h2>
          <p>Every test exercises the real feature. Verdicts: <b>PASS</b> (works), <b>WARNING</b> (works with reduced capability), <b>FAIL</b> (should work but did not), <b>NOT_AVAILABLE</b> (optional dependency missing). Never reports ENABLED when the feature is broken.</p>
          <div className="button-row">
            <button onClick={runDiagnostics} disabled={busy || diagnosticsRunning}>{diagnosticsRunning ? 'Running…' : 'Run self-tests'}</button>
          </div>
          {diagnosticsReport && <div className="diagnostics-summary">
            <span className="diag-pass">PASS {diagnosticsReport.summary.pass}</span>
            <span className="diag-warning">WARNING {diagnosticsReport.summary.warning}</span>
            <span className="diag-fail">FAIL {diagnosticsReport.summary.fail}</span>
            <span className="diag-na">NOT_AVAILABLE {diagnosticsReport.summary.not_available}</span>
            <small>· {diagnosticsReport.duration_ms} ms total · {new Date(diagnosticsReport.generated_at).toLocaleString()}</small>
          </div>}
        </Panel>
        {diagnosticsReport && diagnosticsReport.tests.map((test) => <article className={`card diag-card diag-${test.status.toLowerCase()}`} key={test.component}>
          <div className="diag-head">
            <span className={`diag-verdict diag-${test.status.toLowerCase()}`}>{test.status}</span>
            <h3>{test.component}</h3>
            <small>{test.duration_ms} ms</small>
          </div>
          <p><b>Reason:</b> {test.reason}</p>
          <p><b>Diagnostic:</b> {test.diagnostic}</p>
          {test.suggested_fix && test.suggested_fix !== 'No action required.' && <p className="diag-fix"><b>Suggested fix:</b> {test.suggested_fix}</p>}
          {Object.keys(test.evidence).length > 0 && <details><summary>Evidence</summary><pre>{JSON.stringify(test.evidence, null, 2)}</pre></details>}
        </article>)}
        {!diagnosticsReport && <Empty>Run the self-tests to see real feature status.</Empty>}
      </section>}
      {tab === 'Settings' && <section className="settings settings-full">
        {settingsNotice && <div className="settings-notice">{settingsNotice}</div>}
        {desktopConfig && <>
          <Panel title="AGENT"><Toggle label="Agent enabled" value={desktopConfig.agentEnabled} set={(v)=>changeDesktop('agentEnabled',v)}/><Toggle label="Autonomous mode" value={desktopConfig.autonomousMode} set={(v)=>changeDesktop('autonomousMode',v)}/><NumberSetting label="Maximum steps" value={desktopConfig.maxAgentSteps} min={1} max={20} set={(v)=>changeDesktop('maxAgentSteps',v)}/></Panel>
          <Panel title="OLLAMA"><Toggle label="Ollama enabled" value={desktopConfig.ollamaEnabled} set={(v)=>changeDesktop('ollamaEnabled',v)}/><label>Base URL<input value={desktopConfig.ollamaBaseUrl} onChange={(e)=>changeDesktop('ollamaBaseUrl',e.target.value)}/></label><label>Chat model<input list="ollama-models" value={desktopConfig.chatModel} onChange={(e)=>changeDesktop('chatModel',e.target.value)}/></label><label>Embedding model<input list="ollama-models" value={desktopConfig.embeddingModel} onChange={(e)=>changeDesktop('embeddingModel',e.target.value)}/></label><NumberSetting label="Maximum completion tokens" value={desktopConfig.maxCompletionTokens} min={128} max={131072} set={(v)=>changeDesktop('maxCompletionTokens',v)}/><datalist id="ollama-models">{availableModels.map((model)=><option key={model} value={model}/>)}</datalist><p>Agent AI: {ollamaState?.service && ollamaState.chatModel ? 'ONLINE' : 'OFFLINE'}{ollamaState?.error ? ` · ${ollamaState.error}` : ''}</p><div className="button-row"><button onClick={testOllama} disabled={busy}>Test Connection</button><button onClick={refreshModels} disabled={busy}>Refresh Models</button><button onClick={testChatModel} disabled={busy}>Test Chat</button><button onClick={testEmbeddingModel} disabled={busy}>Test Embedding</button><button onClick={()=>pullModels([desktopConfig.chatModel])} disabled={busy}>Install Chat Model</button><button onClick={()=>pullModels([desktopConfig.embeddingModel])} disabled={busy}>Install Embedding Model</button></div></Panel>
          <Panel title="TOOLS"><Toggle label="Agent tools" value={desktopConfig.toolsEnabled} set={(v)=>changeDesktop('toolsEnabled',v)}/><Toggle label="Filesystem tools" value={desktopConfig.filesystemToolsEnabled} set={(v)=>changeDesktop('filesystemToolsEnabled',v)}/><Toggle label="Coding tools" value={desktopConfig.codingToolsEnabled} set={(v)=>changeDesktop('codingToolsEnabled',v)}/><Toggle label="Terminal tools" value={desktopConfig.terminalToolsEnabled} set={(v)=>changeDesktop('terminalToolsEnabled',v)}/><label>Terminal Docker image<input value={desktopConfig.terminalSandboxImage} onChange={(e)=>changeDesktop('terminalSandboxImage',e.target.value)} placeholder="image@sha256:..."/></label><Toggle label="Memory" value={desktopConfig.memoryEnabled} set={(v)=>changeDesktop('memoryEnabled',v)}/><Toggle label="Knowledge base" value={desktopConfig.knowledgeEnabled} set={(v)=>changeDesktop('knowledgeEnabled',v)}/><label>Python execution<select value={desktopConfig.pythonExecutionBackend} onChange={(e)=>changeDesktop('pythonExecutionBackend',e.target.value as 'disabled'|'docker')}><option value="disabled">Disabled</option><option value="docker">Docker sandbox</option></select></label><label>Python Docker image<input value={desktopConfig.pythonSandboxImage} onChange={(e)=>changeDesktop('pythonSandboxImage',e.target.value)} placeholder="image@sha256:..."/></label><p>Terminal and Python stay unavailable unless their pinned Docker sandbox image is configured and Docker is running.</p></Panel>
          <Panel title="NETWORK"><Toggle label="Network enabled" value={desktopConfig.networkEnabled} set={(v)=>changeDesktop('networkEnabled',v)}/><label>Mode<select value={desktopConfig.networkMode} onChange={(e)=>changeDesktop('networkMode',e.target.value as DesktopSettings['networkMode'])}><option value="disabled">OFF</option><option value="local">LOCAL ONLY</option><option value="full">FULL</option></select></label><Toggle label="Web search" value={desktopConfig.webSearchEnabled} set={(v)=>changeDesktop('webSearchEnabled',v)}/><Toggle label="HTTP requests" value={desktopConfig.httpRequestsEnabled} set={(v)=>changeDesktop('httpRequestsEnabled',v)}/><Toggle label="DNS" value={desktopConfig.dnsEnabled} set={(v)=>changeDesktop('dnsEnabled',v)}/><Toggle label="Localhost" value={desktopConfig.allowLocalNetwork} set={(v)=>changeDesktop('allowLocalNetwork',v)}/><Toggle label="Private LAN" value={desktopConfig.allowPrivateNetwork} set={(v)=>changeDesktop('allowPrivateNetwork',v)}/><Toggle label="External network" value={desktopConfig.allowExternalNetwork} set={(v)=>changeDesktop('allowExternalNetwork',v)}/><Toggle label="Approval for external network" value={desktopConfig.requireApprovalForExternalNetwork} set={(v)=>changeDesktop('requireApprovalForExternalNetwork',v)}/><label>SearXNG URL<input value={desktopConfig.searxngBaseUrl} onChange={(e)=>changeDesktop('searxngBaseUrl',e.target.value)}/></label><p>SSRF protection, cloud-metadata blocking, limits, timeouts, and audit logging are always enforced.</p><button onClick={testNetwork} disabled={busy || !desktopConfig.networkEnabled || !desktopConfig.webSearchEnabled}>Test Search</button></Panel>
          <Panel title="PERMISSIONS"><label>Approval mode<select value={desktopConfig.approvalMode} onChange={(e)=>changeDesktop('approvalMode',e.target.value as 'all'|'high-risk')}><option value="high-risk">High-risk actions</option><option value="all">Every tool action</option></select></label><Toggle label="High-risk approval (required)" value={desktopConfig.requireApprovalForHighRisk} disabled set={()=>{}}/><p>High-risk approval cannot be disabled. Approvals are exact-operation or session-scoped and are audited.</p></Panel>
          <Panel title="AUTOMATION"><Toggle label="Automation" value={desktopConfig.automationEnabled} set={(v)=>changeDesktop('automationEnabled',v)}/><Toggle label="Require approval" value={desktopConfig.automationRequireApproval} set={(v)=>changeDesktop('automationRequireApproval',v)}/><NumberSetting label="Maximum concurrent jobs" value={desktopConfig.automationMaxConcurrentJobs} min={1} max={16} set={(v)=>changeDesktop('automationMaxConcurrentJobs',v)}/><NumberSetting label="Maximum runtime (seconds)" value={desktopConfig.automationMaxRuntimeSeconds} min={10} max={3600} set={(v)=>changeDesktop('automationMaxRuntimeSeconds',v)}/></Panel>
          <Panel title="SAVE AND APPLY"><p>Save persists validated values. Apply restarts the backend, verifies health, and reloads the application. Changes require restart.</p><div className="button-row"><button onClick={saveSettingsOnly} disabled={busy}>Save</button><button className="quiet" onClick={resetSettings} disabled={busy}>Reset</button><button onClick={saveDesktop} disabled={busy}>Apply & Restart</button></div></Panel>
          <Panel title="DIAGNOSTICS"><div className="button-row"><button onClick={()=>runDiagnostic('backend')} disabled={busy}>Test Backend</button><button onClick={testOllama} disabled={busy}>Test Ollama</button><button onClick={()=>runDiagnostic('search')} disabled={busy || !desktopConfig.networkEnabled}>Test Network/Search</button><button onClick={()=>runDiagnostic('agent')} disabled={busy}>Test Agent</button><button onClick={()=>runDiagnostic('tools')} disabled={busy}>Test Tools</button><button onClick={()=>runDiagnostic('permissions')} disabled={busy}>Test Permissions</button><button onClick={diagnostics} disabled={busy}>Export Diagnostic Report</button></div></Panel>
        </>}
        <Panel title="API ACCESS"><p>The ephemeral bearer token is never persisted.</p><form className="inline-form" onSubmit={(e)=>{e.preventDefault();setToken(tokenDraft.trim());void run(refresh)}}><input type="password" value={tokenDraft} onChange={(e)=>setTokenDraft(e.target.value)} placeholder="Local API token"/><button disabled={busy}>Connect</button></form></Panel>
      </section>}
    </main>
  </div>
}
