const fs = require('node:fs')
const path = require('node:path')

function createAppPaths(appData) {
  const root = path.join(appData, 'SecureAgent')
  const paths = {
    root,
    config: path.join(root, 'config'),
    data: path.join(root, 'data'),
    logs: path.join(root, 'logs'),
    models: path.join(root, 'models'),
    workspace: path.join(root, 'workspace'),
  }
  for (const directory of Object.values(paths)) fs.mkdirSync(directory, {recursive: true})
  return {...paths, configFile: path.join(paths.config, 'desktop.json'), database: path.join(paths.data, 'secure_agent.db')}
}

module.exports = {createAppPaths}
