'use strict'
// LyFlow Node.js RASP Probe — preload module
// Usage: node --require /opt/ly-agent/rasp/nodejs/ly_rasp.js app.js
// Or:   NODE_OPTIONS="--require /opt/ly-agent/rasp/nodejs/ly_rasp.js" node app.js

const http = require('http')
const BRIDGE = process.env.LY_RASP_BRIDGE || 'http://127.0.0.1:17891/v1/rasp/events'
const APP = process.env.LY_RASP_APP || 'nodejs-app'
const TOKEN = process.env.LY_RASP_TOKEN || ''

function sendEvent(hookType, payload) {
  const body = JSON.stringify({
    event_type: `rasp.node.${hookType}`,
    hook_type: hookType,
    application: APP,
    summary: `${hookType}: ${(payload.cmdline || payload.command || payload.query || payload.path || payload.url || 'signal').slice(0, 120)}`,
    cmdline: payload.cmdline || payload.command || '',
    query: payload.query || payload.sql || '',
    path: payload.path || payload.file || '',
    url: payload.url || '',
    source_ip: '',
    occurred_at: new Date().toISOString(),
  })
  const req = http.request(BRIDGE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Ly-RASP-Token': TOKEN },
    timeout: 3000,
  })
  req.on('error', () => {})
  req.write(body)
  req.end()
}

// ── child_process hook ──
const cp = require('child_process')
const origExec = cp.exec; const origExecSync = cp.execSync
const origSpawn = cp.spawn; const origSpawnSync = cp.spawnSync
const origExecFile = cp.execFile; const origExecFileSync = cp.execFileSync

function wrapExec(fn, name) {
  return function (cmd, ...args) {
    const command = typeof cmd === 'string' ? cmd : (Array.isArray(cmd) ? cmd.join(' ') : String(cmd))
    sendEvent('command_exec', { command, hook: `child_process.${name}` })
    return fn.call(this, cmd, ...args)
  }
}
cp.exec = wrapExec(origExec, 'exec')
cp.execSync = wrapExec(origExecSync, 'execSync')
cp.spawn = wrapExec(origSpawn, 'spawn')
cp.spawnSync = wrapExec(origSpawnSync, 'spawnSync')
cp.execFile = wrapExec(origExecFile, 'execFile')
cp.execFileSync = wrapExec(origExecFileSync, 'execFileSync')

// ── fs read/write hook ──
const fs = require('fs')
const origReadFile = fs.readFile; const origReadFileSync = fs.readFileSync
const origWriteFile = fs.writeFile; const origWriteFileSync = fs.writeFileSync

function wrapFs(fn, hookType) {
  return function (path, ...args) {
    sendEvent(hookType, { path: String(path), hook: 'fs' })
    return fn.apply(this, arguments)
  }
}
fs.readFile = wrapFs(origReadFile, 'file_read')
fs.readFileSync = wrapFs(origReadFileSync, 'file_read')
fs.writeFile = wrapFs(origWriteFile, 'file_write')
fs.writeFileSync = wrapFs(origWriteFileSync, 'file_write')

// ── http.request hook (SSRF) ──
const origRequest = http.request
http.request = function (url, ...args) {
  const target = typeof url === 'string' ? url : (url.hostname || url.host || JSON.stringify(url).slice(0, 80))
  sendEvent('ssrf', { url: target, hook: 'http.request' })
  return origRequest.call(this, url, ...args)
}

// ── mysql / pg hook ──
try {
  const mysql2 = require('mysql2')
  const origCreateConn = mysql2.createConnection
  mysql2.createConnection = function (cfg) {
    try {
      const conn = origCreateConn.call(this, cfg)
      const origQuery = conn.query
      conn.query = function (sql, ...args) {
        const q = typeof sql === 'string' ? sql : (sql && sql.sql ? sql.sql : JSON.stringify(sql).slice(0, 120))
        sendEvent('sql', { query: q, hook: 'mysql2.query' })
        return origQuery.call(this, sql, ...args)
      }
      return conn
    } catch (_) { return origCreateConn.call(this, cfg) }
  }
  const origPool = mysql2.createPool
  mysql2.createPool = function (cfg) {
    const pool = origPool.call(this, cfg)
    const origGetConn = pool.getConnection
    pool.getConnection = function (cb) {
      origGetConn.call(this, (err, conn) => {
        if (!err && conn) {
          const oq = conn.query
          conn.query = function (sql, ...args) {
            const q = typeof sql === 'string' ? sql : (sql && sql.sql ? sql.sql : JSON.stringify(sql).slice(0, 120))
            sendEvent('sql', { query: q, hook: 'mysql2.pool' })
            return oq.call(this, sql, ...args)
          }
        }
        if (typeof cb === 'function') cb(err, conn)
      })
    }
    return pool
  }
} catch (_) {}

try {
  const pg = require('pg')
  const origPGClient = pg.Client
  if (origPGClient && origPGClient.prototype) {
    const origQuery = origPGClient.prototype.query
    origPGClient.prototype.query = function (sql, ...args) {
      const q = typeof sql === 'string' ? sql : (sql && sql.text ? sql.text : JSON.stringify(sql).slice(0, 120))
      sendEvent('sql', { query: q, hook: 'pg.query' })
      return origQuery.call(this, sql, ...args)
    }
  }
} catch (_) {}

try {
  const mssql = require('mssql')
  const origMssqlQuery = mssql.query
  if (origMssqlQuery) {
    mssql.query = function (sql, ...args) {
      const q = typeof sql === 'string' ? sql : (sql && sql.query ? sql.query : JSON.stringify(sql).slice(0, 120))
      sendEvent('sql', { query: q, hook: 'mssql.query' })
      return origMssqlQuery.call(this, sql, ...args)
    }
  }
} catch (_) {}

try {
  const mongodb = require('mongodb')
  const origCollection = mongodb.Collection
  if (origCollection && origCollection.prototype) {
    const fns = ['find', 'findOne', 'insertOne', 'insertMany', 'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'aggregate']
    fns.forEach(name => {
      const orig = origCollection.prototype[name]
      if (orig) {
        origCollection.prototype[name] = function (query, ...args) {
          if (query) sendEvent('injection', { query: JSON.stringify(query).slice(0, 120), hook: `mongodb.${name}` })
          return orig.call(this, query, ...args)
        }
      }
    })
  }
} catch (_) {}

// ── eval / Function constructor ──
const _origEval = global.eval
global.eval = function (code) {
  sendEvent('command_exec', { command: String(code).slice(0, 120), hook: 'eval' })
  return _origEval(code)
}

const _origFn = global.Function
global.Function = function (...args) {
  const body = args.length > 0 ? String(args[args.length - 1]).slice(0, 120) : 'dynamic'
  sendEvent('deserialization', { command: body, hook: 'Function' })
  return _origFn.apply(this, args)
}

process.stdout.write('[ly_rasp] Node.js RASP probe loaded\n')
