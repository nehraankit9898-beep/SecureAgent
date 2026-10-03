const http = require('node:http')
const net = require('node:net')

function canBind(port) {
  return new Promise((resolve) => {
    const server = net.createServer()
    server.unref()
    server.once('error', () => resolve(false))
    server.listen({host: '127.0.0.1', port, exclusive: true}, () => server.close(() => resolve(true)))
  })
}

async function selectPort(preferred = 8765) {
  if (Number.isInteger(preferred) && preferred >= 1024 && preferred <= 65535 && await canBind(preferred)) return preferred
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.unref()
    server.once('error', reject)
    server.listen({host: '127.0.0.1', port: 0, exclusive: true}, () => {
      const address = server.address()
      const port = typeof address === 'object' && address ? address.port : 0
      server.close(() => port ? resolve(port) : reject(new Error('No local port available')))
    })
  })
}

function getJson(url, headers = {}, timeout = 2500) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, {headers, timeout}, (response) => {
      const chunks = []
      let size = 0
      response.on('data', (chunk) => {
        size += chunk.length
        if (size > 2_000_000) request.destroy(new Error('Response too large'))
        else chunks.push(chunk)
      })
      response.on('end', () => {
        const text=Buffer.concat(chunks).toString('utf8')
        if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
          try { const data=JSON.parse(text);const failure=data?.error||data;return reject(new Error(`${failure?.code||`HTTP_${response.statusCode||0}`}: ${failure?.message||failure?.detail||'Request failed'}`)) }
          catch { return reject(new Error(`HTTP_${response.statusCode || 0}: Request failed`)) }
        }
        try { resolve(JSON.parse(text)) }
        catch { reject(new Error('Invalid JSON response')) }
      })
    })
    request.once('timeout', () => request.destroy(new Error('Request timed out')))
    request.once('error', reject)
  })
}

async function waitForHealth(origin, attempts = 60, delayMs = 250, expectedVersion = null, token = '') {
  let lastError = new Error('Backend did not become healthy')
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const value = await getJson(`${origin}/health`, {}, 1000)
      if (!value || value.status !== 'ok' || typeof value.version !== 'string' || value.backend !== 'ok' || value.database !== 'ok') throw new Error('Health response schema is invalid')
      if (expectedVersion && value.version !== expectedVersion) throw new Error(`Backend version ${value.version} does not match desktop ${expectedVersion}`)
      if (token) await getJson(`${origin}/api/v1/settings`, {Authorization:`Bearer ${token}`}, 1000)
      return value
    } catch (error) { lastError = error }
    await new Promise((resolve) => setTimeout(resolve, delayMs))
  }
  throw lastError
}

module.exports = {canBind, selectPort, getJson, waitForHealth}
