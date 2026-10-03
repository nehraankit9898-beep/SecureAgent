import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const main=fs.readFileSync(new URL('../../backend/app/main.py',import.meta.url),'utf8')
const security=fs.readFileSync(new URL('../../backend/app/security.py',import.meta.url),'utf8')
const client=fs.readFileSync(new URL('../src/api.ts',import.meta.url),'utf8')
const app=fs.readFileSync(new URL('../src/App.tsx',import.meta.url),'utf8')
const contracts=fs.readFileSync(new URL('../src/contracts.ts',import.meta.url),'utf8')
const ipc=fs.readFileSync(new URL('../../desktop/ipc/register.js',import.meta.url),'utf8')
const network=fs.readFileSync(new URL('../../desktop/services/network.js',import.meta.url),'utf8')

const expected=[
['GET','/api/v1/auth/status'],['GET','/health'],['GET','/api/v1/health'],['GET','/api/v1/system/health'],['GET','/api/v1/diagnostics/{component}'],['GET','/api/v1/ready'],['GET','/api/v1/models'],['GET','/api/v1/ollama/status'],['POST','/api/v1/ollama/test-chat'],['POST','/api/v1/ollama/test-embedding'],['POST','/api/v1/network/test'],['GET','/api/v1/network/test'],['POST','/api/v1/chat'],['GET','/api/v1/tools'],['POST','/api/v1/agent/tasks'],['GET','/api/v1/agent/tasks'],['GET','/api/v1/agent/tasks/{item_id}'],['POST','/api/v1/agent/tasks/{item_id}/resume'],['POST','/api/v1/agent/tasks/{item_id}/reject'],['POST','/api/v1/agent/tasks/{item_id}/cancel'],['POST','/api/v1/orchestrate'],['GET','/api/v1/memories'],['POST','/api/v1/memories'],['PATCH','/api/v1/memories/{item_id}'],['DELETE','/api/v1/memories/{item_id}'],['GET','/api/v1/schedules'],['POST','/api/v1/schedules'],['PATCH','/api/v1/schedules/{item_id}'],['POST','/api/v1/schedules/{item_id}/approve'],['POST','/api/v1/schedules/{item_id}/cancel'],['DELETE','/api/v1/schedules/{item_id}'],['GET','/api/v1/schedule-runs'],['POST','/api/v1/documents'],['GET','/api/v1/documents'],['POST','/api/v1/documents/search'],['DELETE','/api/v1/documents/{item_id}'],['GET','/api/v1/audit'],['GET','/api/v1/settings'],
// Linux terminal agent, workflows, reports, permission center, notifications.
// The new /terminal/mode (HOST_CONTROL switch) and /terminal/executions/{id}/stream
// (SSE live updates) endpoints are part of the v1 contract surface.
['GET','/api/v1/system/info'],['GET','/api/v1/terminal/status'],['POST','/api/v1/terminal/execute'],['GET','/api/v1/terminal/history'],['GET','/api/v1/terminal/executions/{item_id}'],['POST','/api/v1/terminal/executions/{item_id}/cancel'],['GET','/api/v1/terminal/executions/{item_id}/stream'],['POST','/api/v1/terminal/mode'],['GET','/api/v1/workflows'],['POST','/api/v1/workflows/{name}/run'],['GET','/api/v1/reports'],['GET','/api/v1/reports/{item_id}'],['GET','/api/v1/permissions/grants'],['POST','/api/v1/permissions/grants'],['DELETE','/api/v1/permissions/grants/{item_id}'],['GET','/api/v1/notifications'],
// SecureAgent 2.0 additions: unified diagnostics, SAFE/ASSIST/CONTROL mode,
// emergency stop, resume, audit export/clear, filesystem paths, config patch,
// preset, config events, status cards, security, permissions overview/patch,
// tools patch, automation actions.
['GET','/api/v1/diagnostics'],['GET','/api/v1/mode'],['POST','/api/v1/mode'],['POST','/api/v1/emergency-stop'],['POST','/api/v1/resume'],['GET','/api/v1/status'],['GET','/api/v1/security'],['GET','/api/v1/permissions'],['PATCH','/api/v1/permissions'],['GET','/api/v1/config'],['PATCH','/api/v1/config'],['POST','/api/v1/config/preset'],['GET','/api/v1/config/events'],['PATCH','/api/v1/tools/{name}'],['POST','/api/v1/audit/export'],['POST','/api/v1/audit/clear'],['GET','/api/v1/filesystem'],['POST','/api/v1/filesystem/paths'],['DELETE','/api/v1/filesystem/paths'],['POST','/api/v1/filesystem/paths/remove'],['POST','/api/v1/automation/{action}'],['GET','/api/v1/terminal/executions']]

function backendHas([method,path]) {
  const suffix=path==='/health'?'"/health"':`config.api_prefix + "${path.replace('/api/v1','')}"`
  return main.includes(`@app.${method.toLowerCase()}(${suffix}`)
}

test('frozen endpoint inventory contains every documented backend operation',()=>{
  assert.equal(expected.length,76)
  for(const endpoint of expected) assert.ok(backendHas(endpoint),`missing ${endpoint.join(' ')}`)
  assert.ok([...main.matchAll(/^@app\.(?:get|post|patch|delete|put|websocket)\(/gm)].length>=expected.length)
})

test('contract version and request correlation are enforced on both sides',()=>{
  assert.match(main,/API_CONTRACT_VERSION = "1\.0\.0"/)
  assert.match(client,/API_CONTRACT_VERSION = '1\.0\.0'/)
  assert.match(main,/X-API-Contract-Version/)
  assert.match(client,/X-Request-ID/)
  assert.match(client,/API_CONTRACT_MISMATCH/)
})

test('error envelope and centralized parsers agree',()=>{
  for(const source of [main,security]) assert.match(source,/['"]success['"]\s*:\s*False/)
  assert.match(main,/"request_id":request_id_var\.get\(\)/)
  assert.match(client,/'error' in data/)
  assert.match(ipc,/data\?\.error\|\|data/)
  assert.match(network,/data\?\.error\|\|data/)
  for(const code of ['REQUEST_TIMEOUT','BACKEND_UNAVAILABLE','AUTHENTICATION_REQUIRED','RATE_LIMITED']) assert.ok(client.includes(code)||main.includes(code))
})

test('frontend agent and long-running request contracts match backend',()=>{
  assert.match(app,/api<Orchestration>\('\/orchestrate',[\s\S]*method: 'POST'[\s\S]*timeoutMs: 130_000/)
  assert.match(app,/api\('\/documents',[\s\S]*method: 'POST'[\s\S]*timeoutMs: 120_000/)
  assert.match(app,/api<SearchHit\[]>\('\/documents\/search',[\s\S]*method: 'POST'[\s\S]*timeoutMs: 60_000/)
  assert.match(contracts,/response_type:'direct_answer'\|'tool_result'/)
  assert.doesNotMatch(contracts,/\bany\b/)
})

test('Ollama checks use backend truth rather than direct UI success',()=>{
  assert.match(ipc,/\/api\/v1\/ollama\/status/)
  assert.match(ipc,/\/api\/v1\/ollama\/test-chat/)
  assert.match(ipc,/\/api\/v1\/ollama\/test-embedding/)
  assert.match(ipc,/failure\?\.code/)
})
