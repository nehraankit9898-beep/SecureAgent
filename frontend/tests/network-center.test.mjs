import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const app = fs.readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8')
const contracts = fs.readFileSync(new URL('../src/contracts.ts', import.meta.url), 'utf8')
const networkApi = fs.readFileSync(new URL('../../backend/app/network_api.py', import.meta.url), 'utf8')
const networkCenter = fs.readFileSync(new URL('../../backend/app/network_center.py', import.meta.url), 'utf8')

test('network center reads real backend state instead of local-only switches', () => {
  assert.match(app, /api<NetworkStatus>\('\/network'\)/)
  assert.match(app, /'\/network\/policy', \{method: 'PATCH'/)
  assert.match(app, /'\/network\/test', \{method: 'POST'\}/)
  assert.match(contracts, /export type NetworkStatus/)
  assert.match(contracts, /effective:NetworkEffectivePolicy/)
})

test('every network mode tier is exposed and the effective mode is server-computed', () => {
  for (const mode of ['disabled', 'localhost', 'private', 'external', 'full']) {
    assert.ok(app.includes(`<option value="${mode}">`), `missing tier ${mode}`)
  }
  assert.match(app, /SETTINGS ∩ CONTROL CENTER/)
  assert.match(app, /narrowed by the Control Center/)
  assert.match(app, /narrowed by Settings/)
})

test('the panel surfaces capability reasons and always-on protections', () => {
  assert.match(app, /entry\.reason \|\| 'blocked'/)
  assert.match(app, /protections/)
  assert.match(app, /telemetry\.blocked_count/)
})

test('backend network center is the enforcement point for these switches', () => {
  assert.match(networkCenter, /MODE_RANK = \{"disabled": 0, "localhost": 1/)
  assert.match(networkCenter, /ALWAYS_ON_PROTECTIONS/)
  assert.match(networkCenter, /SafeHttpClient/)
  assert.match(networkCenter, /web_search_operational/)
  assert.match(networkApi, /@router\.patch\("\/policy"\)/)
  assert.match(networkApi, /Control Center/)
})
