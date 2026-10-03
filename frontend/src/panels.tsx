// Terminal, Workflows, and Reports panels for the SecureAgent dashboard.
// These components talk only to the backend v1 API; every terminal action is
// classified and audited server-side, so the UI never bypasses policy.
//
// SecureAgent 2.0: the terminal panel now consumes the real SSE stream
// (/terminal/executions/{id}/stream) instead of polling every 700ms, and the
// dead `confirmNeeded` branch (declared but never set) has been removed.
import {useCallback, useEffect, useRef, useState} from 'react'
import {api, API_URL} from './api'
import type {SecurityReport, SecurityFinding, TerminalExecution, TerminalStatus, Workflow} from './contracts'

function riskClass(risk: string): string {
  if (risk === 'blocked') return 'risk-blocked'
  if (risk === 'high_risk') return 'risk-high'
  if (risk === 'requires_approval') return 'risk-approval'
  if (risk === 'low_risk') return 'risk-low'
  return 'risk-safe'
}

export function TerminalPanel({status, onError}: {status: TerminalStatus | null; onError: (message: string) => void}) {
  const [command, setCommand] = useState('')
  const [cwd, setCwd] = useState('.')
  const [execution, setExecution] = useState<TerminalExecution | null>(null)
  const [running, setRunning] = useState(false)
  const [history, setHistory] = useState<TerminalExecution[]>([])
  const [historyQuery, setHistoryQuery] = useState('')
  // SecureAgent 2.0: removed the dead `confirmNeeded` state — it was declared
  // but never set to a truthy value, making the approval card unreachable.
  // Real approval flow happens server-side and is reflected via the `risk`
  // field on the response (the backend returns 403 with TERMINAL_APPROVAL_REQUIRED
  // if the user must confirm, which the catch block surfaces as an error).
  const sseRef = useRef<EventSource | null>(null)
  const pollRef = useRef<number | null>(null)

  const loadHistory = useCallback(async (query = '') => {
    try {
      const rows = await api<TerminalExecution[]>(`/terminal/history?limit=100${query ? `&query=${encodeURIComponent(query)}` : ''}`)
      setHistory(rows)
    } catch { /* history is best-effort */ }
  }, [])

  useEffect(() => { void loadHistory() }, [loadHistory])
  useEffect(() => () => {
    // Clean up both SSE and polling fallback on unmount.
    if (sseRef.current) sseRef.current.close()
    if (pollRef.current) window.clearInterval(pollRef.current)
  }, [])

  // SecureAgent 2.0: real SSE streaming — pipe /terminal/executions/{id}/stream
  // directly to the UI instead of polling every 700ms. Falls back to polling
  // if EventSource is unavailable or the stream errors (e.g. backend behind
  // a proxy that buffers SSE).
  const streamExecution = (id: string) => {
    if (sseRef.current) sseRef.current.close()
    if (pollRef.current) window.clearInterval(pollRef.current)
    // Prefer the IPC broker when running inside Electron (avoids CORS and
    // gives us the bearer token for free). Fall back to native EventSource
    // when running standalone in a browser.
    const broker = window.secureAgent?.backendRequest
    // The EventSource URL must include the full API prefix — unlike api(),
    // EventSource does not prepend API_URL, and a bare /terminal/... path
    // 404s outside the backend-served origin.
    const url = `${API_URL}/terminal/executions/${id}/stream`
    if (!broker) {
      try {
        const source = new EventSource(url)
        sseRef.current = source
        source.addEventListener('snapshot', (event) => {
          try { setExecution(JSON.parse(event.data)) } catch { /* ignore malformed */ }
        })
        source.addEventListener('end', () => {
          source.close()
          sseRef.current = null
          setRunning(false)
          void loadHistory(historyQuery)
          // Fetch the final snapshot to ensure exit_code is captured.
          void api<TerminalExecution>(`/terminal/executions/${id}`).then(setExecution).catch(() => undefined)
        })
        source.onerror = () => {
          source.close()
          sseRef.current = null
          // Fall back to polling on SSE error.
          pollExecution(id)
        }
        return
      } catch { /* EventSource unavailable — fall through to polling */ }
    }
    // Polling fallback (also used when broker is present, because the IPC
    // broker cannot easily consume an SSE stream — the broker returns a
    // single response, not a stream of events).
    pollExecution(id)
  }

  const pollExecution = (id: string) => {
    if (pollRef.current) window.clearInterval(pollRef.current)
    pollRef.current = window.setInterval(async () => {
      try {
        const snap = await api<TerminalExecution>(`/terminal/executions/${id}`)
        setExecution(snap)
        if (snap.status !== 'running') {
          if (pollRef.current) window.clearInterval(pollRef.current)
          setRunning(false)
          void loadHistory(historyQuery)
        }
      } catch { if (pollRef.current) window.clearInterval(pollRef.current); setRunning(false) }
    }, 500)
  }

  const runCommand = async (raw: string, workingDirectory: string) => {
    setRunning(true)
    try {
      const result = await api<TerminalExecution>('/terminal/execute', {
        method: 'POST',
        body: JSON.stringify({command: raw, cwd: workingDirectory, timeout_seconds: status?.timeout_seconds ?? 30}),
        timeoutMs: Math.min((status?.timeout_seconds ?? 30) * 1000 + 15_000, 120_000),
      })
      setExecution(result)
      if (result.status === 'running') streamExecution(result.id)
      else { setRunning(false); void loadHistory(historyQuery) }
    } catch (reason) {
      setRunning(false)
      const message = reason instanceof Error ? reason.message : 'Terminal execution failed'
      onError(message)
      void loadHistory(historyQuery)
    }
  }

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    if (!command.trim() || running) return
    void runCommand(command, cwd)
  }

  const cancel = async () => {
    if (!execution) return
    try { await api(`/terminal/executions/${execution.id}/cancel`, {method: 'POST'}) } catch { /* already finished */ }
  }

  const retry = () => {
    if (!execution) return
    setCommand(execution.command)
    setCwd(execution.cwd === status?.workspace_root ? '.' : execution.cwd)
  }

  const clearOutput = () => setExecution(null)

  const copyOutput = async () => {
    if (execution) await navigator.clipboard?.writeText((execution.stdout || '') + (execution.stderr ? `\n[stderr]\n${execution.stderr}` : '')).catch(() => undefined)
  }

  const searchHistory = (event: React.FormEvent) => {
    event.preventDefault()
    void loadHistory(historyQuery)
  }

  return <section className="terminal-layout">
    <div className="terminal-main">
      <div className="panel terminal-output-panel">
        <p className="eyebrow">TERMINAL · {status?.available ? 'AVAILABLE' : 'RESTRICTED'} · {status?.backend || 'unknown'}</p>
        <p className="terminal-note">Commands are classified by the Command Safety Engine (safe / low risk / approval / high risk / blocked) and audited. Working directory is restricted to the approved workspace{status?.allowed_paths?.length ? ` and ${status.allowed_paths.length} allowed path(s)` : ''}. sudo runs non-interactively; passwords are never collected.</p>
        {execution && <div className="terminal-output">
          <div className="terminal-output-head">
            <span className={`risk-chip ${riskClass(execution.risk)}`}>{execution.risk.replaceAll('_', ' ')}</span>
            <span className="terminal-meta">exit {execution.exit_code ?? '—'} · {execution.duration_ms} ms · {execution.status}</span>
          </div>
          <div className="terminal-cmd">$ {execution.command}</div>
          <pre className="terminal-stdout">{execution.stdout}{execution.stderr ? `\n[stderr]\n${execution.stderr}` : ''}{execution.error ? `\n[error] ${execution.error}` : ''}{execution.status === 'running' ? '\n… running' : ''}</pre>
          <div className="button-row">
            <button onClick={cancel} disabled={!running}>Cancel</button>
            <button onClick={retry} disabled={running}>Retry</button>
            <button onClick={copyOutput}>Copy output</button>
            <button onClick={clearOutput}>Clear</button>
          </div>
        </div>}
        {!execution && <div className="empty terminal-empty"><span>›_</span><p>Run a command to see output here. Try <code>uname -a</code> or <code>ss -tulwn</code>.</p></div>}
      </div>
      <form className="terminal-composer" onSubmit={submit}>
        <div className="terminal-input-row">
          <span className="terminal-prompt">$</span>
          <input value={command} onChange={(event) => setCommand(event.target.value)} placeholder="Command (e.g. uname -a)" aria-label="Terminal command" />
          <input className="terminal-cwd" value={cwd} onChange={(event) => setCwd(event.target.value)} placeholder="cwd" aria-label="Working directory" title="Working directory (relative to workspace)" />
          <button className="send" disabled={running || !command.trim()}>{running ? 'Running…' : 'Run'}</button>
        </div>
      </form>
    </div>
    <div className="panel terminal-history-panel">
      <p className="eyebrow">HISTORY</p>
      <form className="inline-form compact-form" onSubmit={searchHistory}>
        <input value={historyQuery} onChange={(event) => setHistoryQuery(event.target.value)} placeholder="Search commands" aria-label="Search terminal history" />
        <button className="quiet compact">Search</button>
      </form>
      <div className="history-list">
        {history.length ? history.map((item) => <button key={item.id} className="history-item" onClick={() => { setCommand(item.command); setExecution(item) }} title={`${item.command} · exit ${item.exit_code ?? '—'}`}>
          <span className={`risk-chip ${riskClass(item.risk)}`}>{item.risk.replaceAll('_', ' ')}</span>
          <code>{item.command}</code>
        </button>) : <p className="history-empty">No commands recorded yet.</p>}
      </div>
    </div>
  </section>
}

export function WorkflowsPanel({onReport}: {onReport: (report: SecurityReport) => void}) {
  const [workflows, setWorkflows] = useState<Workflow[]>([])
  const [running, setRunning] = useState<string | null>(null)
  const [auditPath, setAuditPath] = useState('.')
  const [error, setError] = useState('')

  useEffect(() => {
    void api<Workflow[]>('/workflows').then(setWorkflows).catch(() => setError('Unable to load workflows'))
  }, [])

  const run = async (name: string) => {
    setRunning(name)
    setError('')
    try {
      const scope = name === 'file_security_audit' ? {path: auditPath} : {}
      const report = await api<SecurityReport>(`/workflows/${name}/run`, {method: 'POST', body: JSON.stringify(scope), timeoutMs: 300_000})
      onReport(report)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Workflow failed')
    } finally {
      setRunning(null)
    }
  }

  return <section className="workflows">
    {error && <div className="alert">{error}<button onClick={() => setError('')}>×</button></div>}
    {workflows.map((workflow) => <article className="panel workflow-card" key={workflow.name}>
      <p className="eyebrow">ONE-CLICK · DETERMINISTIC</p>
      <h2>{workflow.title}</h2>
      <p>{workflow.description}</p>
      {workflow.name === 'file_security_audit' && <label className="workflow-path">Audit scope (workspace-relative path)
        <input value={auditPath} onChange={(event) => setAuditPath(event.target.value)} placeholder="." aria-label="File audit path" />
      </label>}
      <div className="button-row">
        <button onClick={() => void run(workflow.name)} disabled={running !== null}>{running === workflow.name ? 'Running…' : `Run ${workflow.title}`}</button>
      </div>
    </article>)}
  </section>
}

export function severityClass(severity: string): string {
  if (severity === 'critical' || severity === 'high') return 'sev-high'
  if (severity === 'medium') return 'sev-medium'
  return 'sev-info'
}

export function ReportDetail({report}: {report: SecurityReport}) {
  const download = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'})
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `secureagent-${report.workflow}-${report.generated_at.slice(0, 10)}.json`
    anchor.click()
    URL.revokeObjectURL(url)
  }
  return <article className="panel report-detail">
    <div className="report-head">
      <div>
        <p className="eyebrow">{report.status.toUpperCase()} · {report.duration_ms} MS · {report.generated_at}</p>
        <h2>{report.title}</h2>
      </div>
      <div className="button-row">
        <button onClick={download}>Download JSON</button>
      </div>
    </div>
    <div className="report-summary">
      <span className={`sev-chip ${severityClass(report.summary.overall_severity)}`}>{report.summary.overall_severity}</span>
      <span>{report.summary.checks} checks</span>
      <span>{report.summary.not_available} not available</span>
      {Object.entries(report.summary.inferred_counts_by_severity).map(([severity, count]) => (
        <span key={severity} className={`sev-chip ${severityClass(severity)}`}>{count} {severity}</span>
      ))}
    </div>
    <div className="findings">
      {report.findings.map((finding: SecurityFinding, index: number) => <div className="finding" key={`${finding.check}-${index}`}>
        <div className="finding-head">
          <span className={`status-label label-${finding.status.toLowerCase().replaceAll('_', '-')}`}>{finding.status}</span>
          <span className={`sev-chip ${severityClass(finding.severity)}`}>{finding.severity}</span>
          <strong>{finding.check.replaceAll('_', ' ')}</strong>
          <small>{finding.component}</small>
        </div>
        <p>{finding.summary}</p>
        {finding.evidence.length > 0 && <details><summary>Evidence ({finding.evidence.length})</summary><pre>{finding.evidence.join('\n')}</pre></details>}
        {finding.recommendation && <p className="finding-fix">Recommended: {finding.recommendation}</p>}
      </div>)}
    </div>
    {report.performed_commands.length > 0 && <details className="report-commands"><summary>Commands performed ({report.performed_commands.length})</summary>
      <pre>{report.performed_commands.map((item) => `$ ${item.command}  # exit ${item.exit_code ?? '—'} · ${item.duration_ms}ms`).join('\n')}</pre>
    </details>}
    <details className="report-limits"><summary>Limitations</summary><ul>{report.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul></details>
  </article>
}

export function ReportsPanel() {
  const [reports, setReports] = useState<{id: string; workflow: string; title: string; status: string; overall_severity: string; created_at: string}[]>([])
  const [selected, setSelected] = useState<SecurityReport | null>(null)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    try { setReports(await api<typeof reports>('/reports?limit=50')) } catch { setError('Unable to load reports') }
  }, [])

  useEffect(() => { void load() }, [load])

  const open = async (id: string) => {
    try { setSelected(await api<SecurityReport>(`/reports/${id}`, {timeoutMs: 30_000})) } catch { setError('Unable to open report') }
  }

  return <section className="reports-layout">
    {error && <div className="alert">{error}<button onClick={() => setError('')}>×</button></div>}
    <div className="panel reports-list">
      <p className="eyebrow">GENERATED REPORTS</p>
      {reports.length ? reports.map((report) => <button key={report.id} className="report-row" onClick={() => void open(report.id)}>
        <span className={`sev-chip ${severityClass(report.overall_severity)}`}>{report.overall_severity}</span>
        <span className="report-row-title">{report.title || report.workflow}</span>
        <small>{report.created_at}</small>
      </button>) : <div className="empty"><span>✦</span><p>No reports yet. Run a workflow to generate one.</p></div>}
    </div>
    {selected ? <ReportDetail report={selected}/> : <div className="panel"><p className="eyebrow">REPORT VIEWER</p><div className="empty"><span>✦</span><p>Select a report to inspect findings, evidence, and remediation.</p></div></div>}
  </section>
}
