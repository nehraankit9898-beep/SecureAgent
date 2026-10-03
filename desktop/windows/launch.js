const byId = (id) => document.getElementById(id)
const showFailure = (status) => {
  byId('error').hidden = false
  byId('title').textContent = 'Startup failed'
  byId('component').textContent = status.component || 'Backend'
  byId('detail').textContent = status.error || status.message || 'Unknown startup error'
  byId('cause').textContent = status.cause || 'Missing packaged runtime, invalid configuration, blocked process, or local security software.'
  byId('action').textContent = status.action || 'Retry once, then create diagnostics and review the logs.'
  byId('log').textContent = status.log || 'SecureAgent profile logs folder'
}
window.secureAgent.onLaunchStatus((status) => {
  byId('message').textContent = status.message || 'Starting…'
  if (status.state === 'ERROR') showFailure(status)
  else byId('error').hidden = true
})
byId('retry').addEventListener('click', async () => {
  byId('error').hidden = true; byId('message').textContent = 'Retrying backend startup…'
  try { await window.secureAgent.retryBackend() } catch (reason) { showFailure({error: reason instanceof Error ? reason.message : 'Retry failed'}) }
})
byId('diagnostics').addEventListener('click', async () => {
  try { const result = await window.secureAgent.createDiagnostics(); byId('log').textContent = result.markdownPath || result.jsonPath }
  catch (reason) { showFailure({component: 'Diagnostics', error: reason instanceof Error ? reason.message : 'Diagnostic creation failed'}) }
})
byId('logs').addEventListener('click', () => window.secureAgent.openLogs())
byId('exit').addEventListener('click', () => window.secureAgent.exit())
