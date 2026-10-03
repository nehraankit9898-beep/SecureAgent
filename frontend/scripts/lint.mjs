import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(scriptDirectory, '..', 'src')
const files = fs.readdirSync(root, {recursive: true})
  .filter((name) => /\.(ts|tsx)$/.test(String(name)))
  .map((name) => path.join(root, String(name)))
const failures = []
for (const file of files) {
  const text = fs.readFileSync(file, 'utf8')
  const checks = [
    [/(?:\:\s*any\b|\bas\s+any\b|<any>)/, 'explicit any is forbidden'],
    [/console\.log\s*\(/, 'console.log is forbidden'],
    [/dangerouslySetInnerHTML/, 'dangerous HTML injection is forbidden'],
    [/http:\/\/localhost/, 'hard-coded localhost is forbidden'],
  ]
  for (const [pattern, message] of checks) if (pattern.test(text)) failures.push(`${file}: ${message}`)
  if (!file.endsWith('api.ts') && /\bfetch\s*\(/.test(text)) failures.push(`${file}: use the centralized API client`)
}
if (failures.length) {
  console.error(failures.join('\n'))
  process.exit(1)
}
console.log(`SOURCE_LINT_PASS files=${files.length}`)
