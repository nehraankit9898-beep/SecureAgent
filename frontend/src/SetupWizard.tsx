import {useEffect, useMemo, useState} from 'react'

const steps = ['System Requirements', 'AI Runtime', 'AI Model', 'Database', 'Security Configuration', 'Health Check', 'Complete']
const groups: string[][] = [
  ['windows', 'architecture', 'ram', 'disk', 'port'],
  ['localCore'],
  [],
  ['backend', 'database'],
  ['security'],
  ['backend', 'database', 'localCore', 'security'],
  [],
]

const labels: Record<string, string> = {
  windows: 'Operating system', architecture: 'CPU architecture', ram: 'Memory', disk: 'Disk space', port: 'Local port',
  ollama: 'Ollama', ollamaService: 'AI service', chatModel: 'Chat model', embeddingModel: 'Embedding model',
  backend: 'Backend', database: 'Database', localCore: 'Built-in local core', security: 'Security',
}

export default function SetupWizard({onComplete}: {onComplete: () => void}) {
  const bridge = window.secureAgent!
  const [step, setStep] = useState(0)
  const [checks, setChecks] = useState<DesktopChecks>({})
  const [models, setModels] = useState({chat: 'llama3.2', embedding: 'nomic-embed-text'})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const refresh = async () => {
    setError('')
    try { setChecks(await bridge.checkAll()) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'System check failed') }
  }
  useEffect(() => {
    void bridge.bootstrap().then((value) => setModels(value.models))
    void refresh()
  }, [])
  const current = groups[step]
  const currentReady = current.length === 0 || current.every((name) => checks[name]?.ok)
  const allReady = useMemo(() => groups[5].every((name) => checks[name]?.ok), [checks])

  const run = async (operation: () => Promise<void>) => {
    setBusy(true); setError('')
    try { await operation() }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Setup action failed') }
    finally { setBusy(false) }
  }
  const finish = () => void run(async () => { await bridge.completeSetup(); onComplete() })

  return <div className="setup-shell">
    <aside className="setup-rail">
      <div className="setup-brand"><div className="mark">A</div><div><strong>SecureAgent Setup</strong><small>Local-first desktop</small></div></div>
      <ol>{steps.map((name, index) => <li className={index === step ? 'active' : index < step ? 'done' : ''} key={name}>
        <span>{index < step ? '✓' : index + 1}</span><div><b>{name}</b><small>{index === step ? 'In progress' : index < step ? 'Complete' : 'Pending'}</small></div>
      </li>)}</ol>
      <p className="setup-privacy">Your database, configuration, and logs stay in your local user profile.</p>
    </aside>
    <main className="setup-main">
      <div className="setup-progress"><span style={{width: `${((step + 1) / steps.length) * 100}%`}}/></div>
      <p className="eyebrow">STEP {step + 1} OF {steps.length}</p>
      <h1>{steps[step]}</h1>
      <p className="setup-lead">{step === 0 ? 'Confirm this PC can run SecureAgent safely.' : step === 1 ? 'SecureAgent includes a no-key local core. Ollama is an optional enhancement.' : step === 2 ? 'Optional Ollama models can be installed later from Settings.' : step === 3 ? 'Your encrypted user profile boundary keeps mutable data outside the app installation.' : step === 4 ? 'A fresh internal access token is generated in memory at every launch.' : step === 5 ? 'Run the complete readiness check before opening SecureAgent.' : 'Everything is ready. Open your local workspace.'}</p>
      {error && <div className="setup-error">{error}</div>}
      {step < 6 && <section className="check-list">{current.map((name) => <div className="check-row" key={name}>
        <span className={checks[name]?.ok ? 'check-ok' : 'check-warn'}>{checks[name]?.ok ? '✓' : '!'}</span>
        <div><b>{labels[name] || name}</b><small>{checks[name]?.value || 'Checking…'}</small></div>
        <strong>{checks[name]?.ok ? 'Ready' : 'Action needed'}</strong>
      </div>)}</section>}
      {step === 6 && <section className="ready-card"><div className="ready-icon">✓</div><h2>SecureAgent is ready</h2><p>System, local core, database, backend, and security checks passed. Optional Ollama can be added later.</p></section>}
      <div className="setup-actions">
        <div>{step > 0 && <button className="setup-secondary" onClick={() => setStep((value) => value - 1)} disabled={busy}>Back</button>}</div>
        <div className="setup-action-group">
          {step === 1 && !checks.ollama?.ok && <button className="setup-secondary" onClick={() => void bridge.setupOllama()}>Setup AI</button>}
          {step === 2 && (!checks.chatModel?.ok || !checks.embeddingModel?.ok) && <button className="setup-secondary" disabled={busy || !checks.ollamaService?.ok} onClick={() => void run(async () => {setChecks(await bridge.installModels([models.chat, models.embedding]))})}>{busy ? 'Installing…' : 'Install models'}</button>}
          {step === 5 && <button className="setup-secondary" disabled={busy} onClick={() => void run(refresh)}>Check again</button>}
          {step < 6 ? <button className="setup-primary" disabled={busy || !currentReady} onClick={() => setStep((value) => value + 1)}>Continue</button> : <button className="setup-primary" disabled={busy || !allReady} onClick={finish}>{busy ? 'Finishing…' : 'Open SecureAgent'}</button>}
        </div>
      </div>
    </main>
  </div>
}
