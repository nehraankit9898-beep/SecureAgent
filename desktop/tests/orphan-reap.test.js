/* Behavioral regression tests for BackendManager orphaned-backend recovery
 * (SecureAgent engineering fix B-4).
 *
 * If the Electron main process dies hard, the uvicorn child survives and the
 * next launch would silently pick another port, leaving the orphan serving
 * its loopback port with the previous token until reboot. The manager now
 * persists a pidfile and reaps the orphan on the next start() — but ONLY
 * after verifying, via /proc/<pid>/cmdline on Linux (ps on macOS), that the
 * process really is a SecureAgent backend. Anything else must be left
 * strictly alone.
 */
const assert = require('node:assert/strict')
const {spawn} = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')
const {BackendManager} = require('../services/backend-manager')

function makeManager(tempRoot) {
  return new BackendManager({
    app: {isPackaged: false},
    paths: {database: path.join(tempRoot, 'state.db'), workspace: path.join(tempRoot, 'workspace'), data: tempRoot},
    config: {preferredPort: 0, ollamaBaseUrl: 'http://127.0.0.1:11434', chatModel: 'm', embeddingModel: 'e'},
    token: 'x'.repeat(43),
    logger: {info: () => {}, error: () => {}},
  })
}

const isAlive = (pid) => {
  try { process.kill(pid, 0); return true } catch { return false }
}

const waitUntil = async (condition, timeoutMs = 4000) => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (condition()) return true
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  return condition()
}

test('reapOrphanedBackend leaves unrelated live processes strictly alone', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureagent-orphan-'))
  const manager = makeManager(temp)
  const bystander = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {stdio: 'ignore'})
  try {
    fs.writeFileSync(path.join(temp, 'backend.pid'), JSON.stringify({pid: bystander.pid, port: 1234}))
    await manager.reapOrphanedBackend()
    assert.equal(isAlive(bystander.pid), true, 'unrelated process must NOT be killed')
    assert.equal(fs.existsSync(path.join(temp, 'backend.pid')), false, 'stale pidfile must be cleared')
  } finally {
    try { bystander.kill('SIGKILL') } catch {}
  }
})

test('reapOrphanedBackend terminates a verified SecureAgent backend orphan (linux)', async () => {
  if (process.platform !== 'linux') return // /proc cmdline verification is linux-specific
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureagent-orphan-'))
  const manager = makeManager(temp)
  // A node process whose argv contains the backend markers; /proc/<pid>/cmdline
  // then matches the same pattern the verifier uses for the real backend.
  const orphan = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)', 'uvicorn', 'app.main:app'], {stdio: 'ignore'})
  try {
    assert.ok(await waitUntil(() => fs.existsSync(`/proc/${orphan.pid}/cmdline`)))
    fs.writeFileSync(path.join(temp, 'backend.pid'), JSON.stringify({pid: orphan.pid, port: 1234}))
    await manager.reapOrphanedBackend()
    assert.ok(await waitUntil(() => !isAlive(orphan.pid)), 'verified backend orphan must be terminated')
  } finally {
    try { orphan.kill('SIGKILL') } catch {}
  }
})

test('reapOrphanedBackend tolerates a corrupt or stale pidfile', async () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureagent-orphan-'))
  const manager = makeManager(temp)
  fs.writeFileSync(path.join(temp, 'backend.pid'), 'not-json-at-all')
  await assert.doesNotReject(() => manager.reapOrphanedBackend())
  assert.equal(fs.existsSync(path.join(temp, 'backend.pid')), false)

  fs.writeFileSync(path.join(temp, 'backend.pid'), JSON.stringify({pid: 999999999, port: 1}))
  await assert.doesNotReject(() => manager.reapOrphanedBackend())
  assert.equal(fs.existsSync(path.join(temp, 'backend.pid')), false)
})

test('verifyBackendProcess refuses self and dead pids', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureagent-orphan-'))
  const manager = makeManager(temp)
  assert.equal(manager.verifyBackendProcess(process.pid), false)
  assert.equal(manager.verifyBackendProcess(0), false)
  assert.equal(manager.verifyBackendProcess(-5), false)
  assert.equal(manager.verifyBackendProcess(Number.NaN), false)
})
