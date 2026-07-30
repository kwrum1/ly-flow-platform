#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { readFile, realpath, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { buildAPIRoutes, requireRegistry } from './route-api-contract-builder.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const args = new Map()
for (let index = 2; index < process.argv.length; index += 2) {
  args.set(process.argv[index], process.argv[index + 1])
}
const registryPath = args.get('--registry')
const outputPath = args.get('--output')
if (!registryPath || !outputPath) {
  process.stderr.write('usage: generate-route-api-contract.mjs --registry <path> --output <path>\n')
  process.exit(2)
}

const VALID_BODIES = Object.freeze({
  '/api/v1/security-events': { event_uid: 'evt-contract', category: 'runtime', severity: 'high', title: 'Contract fixture', occurred_at: '2026-01-01T00:00:00Z' },
  '/api/v1/event-migration': { action: 'observe' },
  '/api/v1/auth/register': { username: 'contract-user', password: 'Contract-Pass-123!', role: 'viewer' },
  '/api/v1/auth/login': { username: 'admin', password: 'Contract-Pass-123!' },
  '/api/v1/auth/bootstrap-token': { token: 'contract-bootstrap-token' },
  '/api/v1/auth/change-password': { old_password: 'Contract-Pass-123!', new_password: 'Contract-Pass-456!' },
  '/api/v1/auth/users/password': { user_id: 2, new_password: 'Contract-Pass-456!' },
  '/api/v1/auth/users/': { username: 'contract-user', role: 'analyst', is_active: true },
  '/api/v1/rules': { filename: 'contract.rules.yaml', rule: 'title: contract-rule' },
  '/api/v1/rules/score-weights': { base: 1, source: 1, support: 1 },
  '/api/v1/rules/items/': { enabled: true, score: 1 },
  '/api/v1/rules/sources/': { source_url: 'https://fixtures.invalid/rules' },
  '/api/v1/rule-platform/sources': { id: 'contract-source', name: 'Contract source', url: 'https://fixtures.invalid/rules' },
  '/api/v1/rule-platform/sync': { source_id: 'contract-source', content: 'alert tcp any any -> any any (sid:1;)' },
  '/api/v1/rule-platform/rollback': { version: 'contract-version' },
  '/api/v1/response/policy': { allow_actions: ['isolate'], maintenance_windows: [] },
  '/api/v1/response/advisories': { candidate_id: 'candidate-contract', action: 'isolate', target: 'agent-contract' },
  '/api/v1/response/advisories/': { idempotency_key: 'contract-approval' },
  '/api/v1/rules/subscription': { enabled: true },
  '/api/v1/rules/test': { source: 'contract', message: 'contract fixture' },
  '/api/v1/xdr/log': { message: 'contract fixture' },
  '/api/v1/unified/events/search': { query: 'contract', limit: 1, offset: 0 },
  '/api/v1/traffic/mirror-interface': { enabled: false, interface: 'lo' },
  '/api/v1/situation/target-location': { latitude: 0, longitude: 0 },
  '/api/v1/system/time': { sync: true, ntp_server: 'pool.ntp.org' },
  '/api/v1/incidents/': { status: 'investigating', version: 1 },
  '/api/v1/rasp/protection/enable': { agent_id: 'agent-contract', block_mode: false },
  '/api/v1/rasp/protection/disable': { agent_id: 'agent-contract' },
  '/api/v1/rasp/event': { agent_id: 'agent-contract', event_type: 'contract', severity: 'low' },
  '/api/v1/trace/analyze': { session_id: 'session-contract' },
  '/api/v1/trace/search': { query: 'contract', limit: 1 },
  '/api/v1/assets/': { hostname: 'contract-host', ip: '192.0.2.10' },
  '/api/v1/assets/heartbeat': { host_id: 'host-contract', status: 'online' },
  '/api/v1/agent/capabilities/': { field: 'traffic', enabled: true },
  '/api/v1/agent/name/': { display_name: 'contract-agent' },
  '/api/v1/agent/names': { agent_id: 'agent-contract', display_name: 'contract-agent' },
  '/api/v1/agent/enroll': { token: 'contract-enrollment', hostname: 'contract-host', capabilities: [] },
  '/api/v1/agent/heartbeat': { agent_id: 'agent-contract', agent_key: 'contract-key', status: 'online' },
  '/api/v1/agent/config': { agent_id: 'agent-contract', agent_key: 'contract-key' },
  '/api/v1/agent/identity': { action: 'inspect', agent_id: 'agent-contract' },
  '/api/v1/agent/traffic-event': { agent_id: 'agent-contract', stream: 'traffic', data: {} },
  '/api/v1/agent/task-result': { agent_id: 'agent-contract', task_id: 'task-contract', status: 'success', result: {} },
  '/api/v1/agent/component-alert': { agent_id: 'agent-contract', component: 'contract', severity: 'low', title: 'Contract fixture' },
  '/api/v1/agent/runtime-event': { agent_id: 'agent-contract', event_type: 'contract', severity: 'low' },
  '/api/v1/agent/snapshot': { agent_id: 'agent-contract', agent_key: 'contract-key', hostname: 'contract-host', ip: '192.0.2.10', os: 'linux', arch: 'amd64', kernel: 'contract', capabilities: [], interfaces: [], listening_ports: [], performance: {}, processes: [] },
})

const AUDITED_MUTATIONS = new Set([
  '/api/v1/security-events', '/api/v1/security-events/', '/api/v1/event-migration',
  '/api/v1/admin/incident-lifecycle/checkpoint', '/api/v1/auth/bootstrap-token',
  '/api/v1/rule-platform/sources', '/api/v1/rule-platform/sync', '/api/v1/rule-platform/compile-preview',
  '/api/v1/rule-platform/rollback', '/api/v1/response/advisories', '/api/v1/response/advisories/',
  '/api/v1/incidents/', '/api/v1/agent/identity',
])
const RUNTIME_MUTATIONS = new Set([
  '/api/v1/rules', '/api/v1/rules/subscription', '/api/v1/rules/update', '/api/v1/engine-rules/update',
  '/api/v1/traffic/mirror-interface', '/api/v1/situation/target-location', '/api/v1/system/time',
  '/api/v1/rasp/protection/enable', '/api/v1/rasp/protection/disable', '/api/v1/assets/', '/api/v1/assets/heartbeat',
])
const NON_MUTATING_WRITES = new Set([
  '/api/v1/rules/test', '/api/v1/xdr/log', '/api/v1/unified/events/search',
  '/api/v1/trace/analyze', '/api/v1/trace/search',
])
const STREAM_MUTATIONS = new Set([
  '/api/v1/rasp/event', '/api/v1/agent/traffic-event', '/api/v1/agent/component-alert', '/api/v1/agent/runtime-event',
])
const AMBIGUOUS_METHODS = new Set([
  '/', '/api/v1/health', '/api/v1/stats', '/api/v1/events', '/api/v1/rules/categories',
  '/api/v1/rules/stats', '/api/v1/xdr/stats', '/api/v1/xdr/events', '/api/v1/xdr/sources',
  '/api/v1/xdr/top-events', '/api/v1/xdr/chains', '/api/v1/xdr/posture',
])
const DYNAMIC_PREFIXES = new Set([
  '/api/v1/auth/users/', '/api/v1/rules/sources/', '/api/v1/response/advisories/',
  '/api/v1/incidents/', '/api/v1/assets/',
])
const API_ONLY = new Set([
  '/', '/api/v1/security-events', '/api/v1/security-events/', '/api/v1/event-migration',
  '/api/v1/admin/incident-lifecycle/checkpoint', '/api/v1/auth/bootstrap-token', '/api/v1/debug/components',
])

const rawRegistry = JSON.parse(await readFile(resolve(registryPath), 'utf8'))
const registry = requireRegistry(rawRegistry).sort((left, right) => left.path.localeCompare(right.path))
const frontend = JSON.parse(await readFile(resolve(root, 'contracts/product-acceptance/v1/frontend-routes.json'), 'utf8'))
if (!frontend || frontend.schema_version !== 1 || !Array.isArray(frontend.routes)) throw new Error('frontend route contract is malformed')
const paths = registry.map((record) => record.path)
const digest = createHash('sha256').update(`${paths.join('\n')}\n`).digest('hex')
const apiRoutes = buildAPIRoutes(registry, {
  validBodies: VALID_BODIES,
  auditedMutations: AUDITED_MUTATIONS,
  runtimeMutations: RUNTIME_MUTATIONS,
  nonMutatingWrites: NON_MUTATING_WRITES,
  streamMutations: STREAM_MUTATIONS,
  ambiguousMethods: AMBIGUOUS_METHODS,
  dynamicPrefixes: DYNAMIC_PREFIXES,
  apiOnly: API_ONLY,
})
const contract = {
  schema_version: 1,
  registry: { mounted_path_count: registry.length, sorted_path_sha256: digest },
  roles: ['admin', 'analyst', 'viewer'],
  frontend_routes: frontend.routes,
  api_routes: apiRoutes,
  expected_red_gaps: [
    { id: 'unsupported-navigation-metadata', current: 'Sixteen unsupported navigation or metadata paths remain present.', required: 'Remove unsupported paths from navigation, metadata, routes, and links.', owner_task: 'T15' },
    { id: 'standalone-consolidation-pages', current: 'Six duplicate protected pages remain mounted as standalone routes.', required: 'Consolidate each page into its exact canonical workflow.', owner_task: 'T15' },
    { id: 'authenticated-unknown-path-dashboard-fallback', current: 'Authenticated unknown protected paths redirect to /dashboard.', required: 'Render an authenticated 404 without dashboard fallback.', owner_task: 'T15' },
    { id: 'broad-handler-method-guards', current: 'Twelve mounted handlers accept methods beyond their intended read contract.', required: 'Align handler method rejection with the documented API contract.', owner_task: 'T14' },
    { id: 'proxy-sensitive-loopback-bootstrap', current: 'Bootstrap authorization trusts the socket RemoteAddr loopback classification.', required: 'Define trusted-proxy handling and an additional bootstrap authorization boundary.', owner_task: 'T06' },
  ],
}
const destination = resolve(outputPath)
const allowedRoots = [resolve(root, 'contracts/product-acceptance/v1')]
if (process.env.LYFLOW_ROUTE_CONTRACT_TEMP_ROOT) allowedRoots.push(resolve(process.env.LYFLOW_ROUTE_CONTRACT_TEMP_ROOT))
const realParent = await realpath(dirname(destination))
const approved = await Promise.all(allowedRoots.map(async (allowedRoot) => {
  const realAllowed = await realpath(allowedRoot)
  const pathFromAllowed = relative(realAllowed, realParent)
  return pathFromAllowed === '' || (!pathFromAllowed.startsWith('..') && !isAbsolute(pathFromAllowed))
}))
if (!approved.some(Boolean)) throw new Error(`output path is outside approved contract roots: ${destination}`)
const temporary = `${destination}.tmp-${process.pid}`
try {
  await writeFile(temporary, `${JSON.stringify(contract, null, 2)}\n`, { mode: 0o644, flag: 'wx' })
  await rename(temporary, destination)
} finally {
  await rm(temporary, { force: true })
}
process.stdout.write(`generated route/API contract: ${destination}\n`)
