import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const app=fs.readFileSync(new URL('../src/App.tsx',import.meta.url),'utf8')
const main=fs.readFileSync(new URL('../../backend/app/main.py',import.meta.url),'utf8')
const refs=[...app.matchAll(/api(?:<[^>]+>)?\(`?['"]([^'"`$]+)|api(?:<[^>]+>)?\(['"]([^'"]+)/g)].map(m=>m[1]||m[2]).filter(Boolean)
test('all static frontend API paths map to backend routes',()=>{
  const normalized=refs.map(x=>x.replace(/\/$/,'')).filter(x=>!x.includes('${'))
  for(const route of normalized){
    const suffix=route.replace(/^\//,'').split('/')[0]
    assert.ok(main.includes(`/${suffix}`),`missing backend route for ${route}`)
  }
})
test('provider honesty is visible',()=>{
  assert.match(app,/active_provider/)
  assert.match(app,/never fabricates AI answers/)
})
test('agent responses are validated defensively and completion tokens are configurable',()=>{
  assert.match(app,/invalid agent response/)
  assert.match(app,/maxCompletionTokens/)
  assert.doesNotMatch(app,/\.direct_answer/)
})
test('frontend exposes complete knowledge and automation workflows',()=>{
  assert.match(app,/reindex: docReindex/)
  assert.match(app,/title: docTitle\.trim\(\) \|\| null/)
  assert.match(app,/scheduleKind==='interval'/)
  assert.match(app,/interval_seconds:scheduleKind==='interval'/)
  assert.match(app,/Recurring interval/)
})

test('terminal SSE stream URL includes the full API prefix',()=>{
  const panels=fs.readFileSync(new URL('../src/panels.tsx',import.meta.url),'utf8')
  // Regression: EventSource does not get the /api/v1 prefix from api(); a
  // bare /terminal/... URL 404s and silently degraded to polling forever.
  assert.match(panels,/API_URL\}\/terminal\/executions\/\$\{id\}\/stream/)
})

test('desktop shell never prompts for the token it cannot know',()=>{
  // Regression: inside Electron the IPC broker injects the ephemeral token;
  // showing "enter the local API token" there is false (the user has no way
  // to know it). The prompt must only appear in standalone browser mode.
  assert.match(app,/!authentication\.required \|\| authentication\.local_bypass \|\| window\.secureAgent/)
})

test('connection test successes are surfaced as notices, not errors',()=>{
  // Regression: successful Test Chat/Embedding/Search results were pushed
  // through setError() and rendered inside the red error banner.
  for (const name of ['testChatModel','testEmbeddingModel','testNetwork','diagnostics']) {
    const re = new RegExp(`const ${name} = [\\s\\S]*?setSettingsNotice\\(`)
    assert.match(app, re, `${name} must report success via settingsNotice`)
  }
  assert.doesNotMatch(app,/testChatModel\(\); setError\(/)
})
