const path = require('node:path')
const {pathToFileURL} = require('node:url')
const {BrowserWindow, shell} = require('electron')
const {isTrustedAppUrl} = require('../services/security')

function createMainWindow() {
  const window = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 980,
    minHeight: 680,
    show: false,
    backgroundColor: '#f9f8f7',
    title: 'SecureAgent',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: true,
      devTools: !require('electron').app.isPackaged,
    },
  })
  const allowedExternalUrls = new Set([
    'https://ollama.com/download/windows',
    'https://ollama.com/download/mac',
    'https://ollama.com/download/linux',
  ])
  window.webContents.setWindowOpenHandler(({url}) => {
    if (allowedExternalUrls.has(url)) void shell.openExternal(url)
    return {action: 'deny'}
  })
  window.webContents.on('will-navigate', (event, url) => {
    const origin = window.__secureAgentOrigin || ''
    const launchFile = pathToFileURL(path.join(__dirname, 'launch.html')).href
    if (!isTrustedAppUrl(url, origin) && url !== launchFile) event.preventDefault()
  })
  window.once('ready-to-show', () => window.show())
  return window
}

module.exports = {createMainWindow}
