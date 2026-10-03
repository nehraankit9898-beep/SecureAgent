const SENSITIVE = /([\"']?\b(?:api[-_ ]?key|authorization|access[-_ ]?token|refresh[-_ ]?token|token|password|secret|private[-_ ]?key|client[-_ ]?secret)\b[\"']?\s*[:=]\s*)(?:[\"']?bearer\s+)?[\"']?[^\s,;}\"']+[\"']?/gi
const MODEL_NAME = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/

function redact(value) {
  return String(value ?? '').replace(SENSITIVE, (_match, prefix) => `${prefix}[REDACTED]`)
}

function validateModelName(value) {
  if (typeof value !== 'string' || !MODEL_NAME.test(value) || value.includes('..')) {
    throw new Error('Invalid Ollama model name')
  }
  return value
}

function isTrustedAppUrl(candidate, expectedOrigin) {
  try {
    const url = new URL(candidate)
    return url.origin === expectedOrigin && ['http:', 'https:'].includes(url.protocol)
  } catch {
    return false
  }
}

module.exports = {redact, validateModelName, isTrustedAppUrl}
