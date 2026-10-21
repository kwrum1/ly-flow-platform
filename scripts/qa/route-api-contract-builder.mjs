function fixturePath(path) {
  if (path.includes('{id}')) return path.replace('{id}', 'contract-id')
  if (!path.endsWith('/')) return path
  const suffixes = {
    '/api/v1/security-events/': 'event-contract', '/api/v1/auth/users/': '2', '/api/v1/rules/items/': 'rule-contract',
    '/api/v1/rules/sources/': 'source-contract', '/api/v1/response/advisories/': 'advisory-contract/approve',
    '/api/v1/threats/': 'traffic', '/api/v1/component-alerts/': 'runtime', '/api/v1/incidents/': 'incident-contract',
    '/api/v1/timeline/': 'timeline-contract', '/api/v1/assets/': 'host-contract', '/api/v1/agents/': 'agent-contract',
    '/api/v1/agent/capabilities/': 'agent-contract', '/api/v1/agent/name/': 'agent-contract',
    '/api/v1/agent/rasp/probe/java/source/': 'Probe.java',
  }
  return path + (suffixes[path] ?? 'contract-id')
}

function invalidMethod(methods) {
  for (const method of ['DELETE', 'PATCH', 'PUT', 'POST', 'GET']) {
    if (!methods.includes(method)) return method
  }
  return 'PATCH'
}

function operation(record, method, methods, config) {
  const read = method === 'GET' || method === 'HEAD' || method === 'WS'
  const roles = (read ? record.read_roles : record.write_roles) ?? []
  const write = !read
  const mutation = write && !config.nonMutatingWrites.has(record.path)
  let persistence = 'none'
  let readback = method === 'WS' ? 'stream' : 'not-applicable'
  if (mutation && config.auditedMutations.has(record.path)) {
    persistence = 'durable-with-audit'
    readback = 'read-after-write'
  } else if (mutation && config.runtimeMutations.has(record.path)) {
    persistence = 'ephemeral'
    readback = 'runtime-state'
  } else if (mutation && config.streamMutations.has(record.path)) {
    persistence = record.path === '/api/v1/agent/traffic-event' || record.path === '/api/v1/agent/runtime-event' ? 'ephemeral' : 'durable'
    readback = 'response'
  } else if (mutation) {
    persistence = 'durable'
    readback = 'read-after-write'
  } else if (write) {
    readback = config.runtimeMutations.has(record.path) ? 'runtime-state' : 'response'
  }
  const path = fixturePath(record.path)
  const validBody = write ? (config.validBodies[record.path] ?? {}) : null
  const invalidUsesBody = write && method !== 'DELETE' && Object.keys(validBody).length > 0
  const invalidUsesMissingResource = method === 'DELETE'
  const invalidFixtureMethod = invalidUsesBody || invalidUsesMissingResource ? method : invalidMethod(methods)
  const invalidFixturePath = invalidUsesMissingResource ? record.path : path
  const invalidStatuses = invalidUsesBody ? [400] : invalidUsesMissingResource ? [404] : [405]
  return {
    method,
    allowed_roles: roles,
    valid_fixture: { method, path, body: validBody, expected_statuses: method === 'WS' ? [101] : [200] },
    invalid_fixture: {
      method: method === 'WS' ? 'WS' : invalidFixtureMethod,
      path: method === 'WS' ? path : invalidFixturePath,
      body: method === 'WS' ? { upgrade: false } : invalidUsesBody ? {} : null,
      expected_statuses: method === 'WS' ? [400] : invalidStatuses,
    },
    mutation,
    readback,
    persistence,
  }
}

function disposition(record, apiOnly) {
  if (record.auth_mode === 'public') return 'public'
  if (record.auth_mode === 'agent-credential') return 'agent-only'
  if (record.auth_mode === 'loopback') return 'loopback-only'
  return apiOnly.has(record.path) ? 'api-only' : 'ui-workflow'
}

export function requireRegistry(value) {
  if (!Array.isArray(value) || value.length !== 121) throw new Error('generated registry must contain exactly 121 records')
  const seen = new Set()
  for (const record of value) {
    if (!record || typeof record !== 'object' || typeof record.path !== 'string' || typeof record.auth_mode !== 'string') {
      throw new Error('generated registry contains a malformed record')
    }
    if (seen.has(record.path)) throw new Error(`generated registry contains duplicate path: ${record.path}`)
    seen.add(record.path)
    if (!Array.isArray(record.read_roles) && record.read_roles !== null) throw new Error(`invalid read roles: ${record.path}`)
    if (!Array.isArray(record.write_roles) && record.write_roles !== null) throw new Error(`invalid write roles: ${record.path}`)
    if (!Array.isArray(record.methods) || record.methods.length === 0 || new Set(record.methods).size !== record.methods.length) {
      throw new Error(`invalid methods: ${record.path}`)
    }
  }
  return value
}

export function buildAPIRoutes(registry, config) {
  return registry.map((record) => {
    const methods = record.methods
    const notes = []
    if (config.ambiguousMethods.has(record.path)) notes.push('Current handler lacks a method guard; intended contract is narrower than current behavior.')
    if (config.dynamicPrefixes.has(record.path)) notes.push('Mounted prefix owns dynamic resource or action suffixes under this single record.')
    if (config.runtimeMutations.has(record.path)) notes.push('Current mutation is runtime-only or does not provide durable persistence.')
    return {
      path: record.path,
      auth_mode: record.auth_mode,
      operations: methods.map((method) => operation(record, method, methods, config)),
      disposition: disposition(record, config.apiOnly),
      ...(notes.length > 0 ? { notes: notes.join(' ') } : {}),
    }
  })
}
