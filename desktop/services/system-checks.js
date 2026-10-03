const fs = require('node:fs')
const os = require('node:os')
const {ollamaStatus} = require('./ollama')
const {getJson} = require('./network')

function diskFree(root) {
  try { const value = fs.statfsSync(root); return value.bavail * value.bsize }
  catch { return 0 }
}

async function runChecks({paths, config, backend, token}) {
  let health = null
  try { health = await getJson(`${backend.origin}/health`, {}, 1500) } catch {}
  const ollama = await ollamaStatus(config)
  const free = diskFree(paths.root)
  return {
    windows: {ok: ['win32', 'linux', 'darwin'].includes(process.platform), value: `${os.type()} ${os.release()} (${process.platform})`},
    architecture: {ok: ['x64', 'arm64'].includes(process.arch), value: process.arch},
    ram: {ok: os.totalmem() >= 4 * 1024 ** 3, value: `${(os.totalmem() / 1024 ** 3).toFixed(1)} GB`},
    disk: {ok: free >= 2 * 1024 ** 3, value: `${(free / 1024 ** 3).toFixed(1)} GB free`},
    port: {ok: Boolean(backend.port), value: backend.port ? `127.0.0.1:${backend.port}` : 'Unavailable'},
    localCore: {ok: health?.status === 'ok', value: health?.provider || 'Unavailable'},
    ollama: {ok: ollama.installed, optional: true, value: ollama.installed ? `Installed (${ollama.version || 'version unknown'})` : 'OLLAMA_NOT_INSTALLED'},
    ollamaService: {ok: ollama.service, optional: true, value: ollama.service ? 'Running' : `${ollama.code}: ${ollama.error || 'Unavailable'}`},
    chatModel: {ok: ollama.chatModel, optional: true, value: ollama.chatModel ? `${config.chatModel} ready` : `MODEL_NOT_INSTALLED: ${config.chatModel}`},
    embeddingModel: {ok: ollama.embeddingModel, optional: true, value: ollama.embeddingModel ? `${config.embeddingModel} ready` : `MODEL_NOT_INSTALLED: ${config.embeddingModel}`},
    network: {ok: !config.networkEnabled || health?.network === 'enabled', optional: true, value: config.networkEnabled ? `${config.networkMode} / ${config.searxngBaseUrl ? 'configured' : 'missing URL'}` : 'Disabled by policy'},
    backend: {ok: health?.status === 'ok', value: health?.status === 'ok' ? 'Healthy' : 'Unavailable'},
    database: {ok: health?.database === 'ok' && fs.existsSync(paths.database), value: fs.existsSync(paths.database) ? 'Initialized' : 'Pending'},
    security: {ok: Boolean(token) && backend.origin.startsWith('http://127.0.0.1:'), value: 'Ephemeral token + loopback binding'},
  }
}

module.exports = {runChecks, diskFree}
