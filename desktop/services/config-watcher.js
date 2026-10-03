/** Real-time configuration sync (spec section 24).
 *
 * Holds ONE Server-Sent-Events connection to the backend's
 * `GET /api/v1/config/events` stream and broadcasts every revision change to
 * all renderer windows (`control:config-sync`). The renderer never opens the
 * connection itself — the backend token never crosses into a renderer.
 *
 * Reconnects with bounded backoff; every reconnect re-broadcasts the latest
 * revision so a UI that missed events can refetch.
 */
const BACKOFF_MS = [1000, 2000, 4000, 8000, 15000, 30000]

class ConfigWatcher {
  constructor({logger, onRevision}) {
    this.logger = logger
    this.onRevision = onRevision || (() => {})
    this.origin = null
    this.token = null
    this.controller = null
    this.stopped = true
    this.attempt = 0
    this.lastRevision = null
  }

  start(origin, token) {
    this.origin = origin
    this.token = token
    this.stopped = false
    this.attempt = 0
    void this._loop()
  }

  stop() {
    this.stopped = true
    if (this.controller) { try { this.controller.abort() } catch { /* already closed */ } }
    this.controller = null
  }

  async _loop() {
    while (!this.stopped && this.origin) {
      this.controller = new AbortController()
      try {
        const response = await fetch(`${this.origin}/api/v1/config/events`, {
          headers: {Authorization: `Bearer ${this.token}`, Accept: 'text/event-stream'},
          signal: this.controller.signal,
        })
        if (!response.ok || !response.body) throw new Error(`config stream HTTP ${response.status}`)
        this.attempt = 0
        const decoder = new TextDecoder()
        let buffer = ''
        for await (const chunk of response.body) {
          if (this.stopped) return
          buffer += decoder.decode(chunk, {stream: true})
          let separator
          while ((separator = buffer.indexOf('\n\n')) !== -1) {
            const block = buffer.slice(0, separator)
            buffer = buffer.slice(separator + 2)
            const revision = this._parseEvent(block)
            if (revision !== null && revision !== this.lastRevision) {
              this.lastRevision = revision
              this.onRevision(revision)
            }
          }
        }
        // Stream ended cleanly (server restart): fall through to reconnect.
      } catch (error) {
        if (this.stopped) return
        this.logger?.error('config.watcher_error', error instanceof Error ? error.message : String(error))
      }
      if (this.stopped) return
      const delay = BACKOFF_MS[Math.min(this.attempt, BACKOFF_MS.length - 1)]
      this.attempt += 1
      await new Promise((resolve) => setTimeout(resolve, delay))
    }
  }

  _parseEvent(block) {
    let event = 'message'
    let data = ''
    for (const line of block.split('\n')) {
      if (line.startsWith('event:')) event = line.slice(6).trim()
      else if (line.startsWith('data:')) data += line.slice(5).trim()
    }
    if (event !== 'config' || !data) return null
    try {
      const payload = JSON.parse(data)
      return typeof payload.revision === 'number' ? payload.revision : null
    } catch { return null }
  }
}

module.exports = {ConfigWatcher}
