const fs = require('node:fs')
const path = require('node:path')
const {spawn, spawnSync} = require('node:child_process')
const {getJson} = require('./network')
const {validateModelName} = require('./security')

function findOllama() {
  const candidates = ['/usr/local/bin/ollama', '/usr/bin/ollama', '/opt/ollama/ollama']
  if (process.env.HOME) candidates.push(path.join(process.env.HOME, '.local', 'bin', 'ollama'))
  const result = spawnSync('which', ['ollama'], {encoding: 'utf8', shell: false})
  if (result.status === 0) candidates.push(result.stdout.trim())
  return candidates.find((candidate) => candidate && fs.existsSync(candidate)) || null
}

async function ollamaStatus(config) {
  const executable = findOllama()
  let models = []
  let service = false
  let version = null
  let code = executable ? 'OLLAMA_SERVICE_STOPPED' : 'OLLAMA_NOT_INSTALLED'
  let error = executable ? 'Ollama is installed but the service is not reachable' : 'Ollama executable was not detected'
  try {
    const [result, versionResult] = await Promise.all([
      getJson(`${config.ollamaBaseUrl}/api/tags`, {}, 2500),
      getJson(`${config.ollamaBaseUrl}/api/version`, {}, 2500),
    ])
    service = true
    models = Array.isArray(result.models) ? result.models.map((item) => item.name).filter((name) => typeof name === 'string') : []
    version = typeof versionResult.version === 'string' ? versionResult.version : null
    code = version ? 'CONNECTED' : 'OLLAMA_INVALID_RESPONSE'
    error = version ? null : 'Ollama did not return a valid version'
  } catch (reason) { if (executable) { code = /timed out/i.test(reason.message) ? 'OLLAMA_TIMEOUT' : 'OLLAMA_SERVICE_STOPPED'; error = reason.message } }
  const hasModel = (name) => models.some((entry) => entry === name || entry.split(':')[0] === name.split(':')[0])
  const chatModel = hasModel(config.chatModel); const embeddingModel = hasModel(config.embeddingModel)
  if (service && (!chatModel || !embeddingModel)) { code = 'MODEL_NOT_INSTALLED'; error = [!chatModel && config.chatModel, !embeddingModel && config.embeddingModel].filter(Boolean).join(', ') }
  return {installed: Boolean(executable), executable: executable ? 'detected' : null, service, version, models, chatModel, embeddingModel, code, error}
}

function pullModel(config, model, onLine = () => {}) {
  const executable = findOllama()
  if (!executable) return Promise.reject(new Error('Ollama is not installed'))
  const safeModel = validateModelName(model)
  return new Promise((resolve, reject) => {
    const child = spawn(executable, ['pull', safeModel], {windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe']})
    child.stdout.on('data', (data) => onLine(data.toString('utf8').slice(0, 1000)))
    child.stderr.on('data', (data) => onLine(data.toString('utf8').slice(0, 1000)))
    child.once('error', reject)
    child.once('exit', (code) => code === 0 ? resolve() : reject(new Error(`Ollama exited with code ${code}`)))
  })
}

module.exports = {findOllama, ollamaStatus, pullModel}
