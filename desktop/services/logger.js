const fs = require('node:fs')
const path = require('node:path')
const {redact} = require('./security')

class FileLogger {
  constructor(directory) {
    this.file = path.join(directory, `desktop-${new Date().toISOString().slice(0, 10)}.log`)
  }
  rotate() {
    try {
      if (!fs.existsSync(this.file) || fs.statSync(this.file).size < 5 * 1024 * 1024) return
      for (let i=4;i>=1;i-=1) { const from=`${this.file}.${i}`; const to=`${this.file}.${i+1}`; if(fs.existsSync(from)){if(i===4)fs.rmSync(from,{force:true});else fs.renameSync(from,to)} }
      fs.renameSync(this.file,`${this.file}.1`)
    } catch {}
  }
  write(level, event, details = '') {
    this.rotate()
    const line = JSON.stringify({timestamp: new Date().toISOString(), level, event, details: redact(details)})
    fs.appendFileSync(this.file, `${line}\n`, 'utf8')
  }
  info(event, details) { this.write('info', event, details) }
  error(event, details) { this.write('error', event, details) }
}

module.exports = {FileLogger}
