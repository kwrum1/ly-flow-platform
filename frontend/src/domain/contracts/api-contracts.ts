export type ApiDomain =
  | 'auth'
  | 'stats'
  | 'events'
  | 'incidents'
  | 'timeline'
  | 'topology'
  | 'xdr'
  | 'unified'
  | 'rasp'
  | 'trace'
  | 'assets'
  | 'agent'
  | 'threatIntelligence'
  | 'rules'
  | 'publicSituation'

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

export type ConsumerSurface =
  | 'dashboard'
  | 'events'
  | 'incidents'
  | 'timeline'
  | 'topology'
  | 'assets'
  | 'intelligence'
  | 'settings'
  | 'agentControl'
  | 'globalSituation'

export type RefreshMode = 'stream' | 'poll' | 'request'

export interface RuleCountSemantics {
  signature_count: number
  rule_file_count: number
  source: 'signed_active_lifecycle' | 'signed_active_ledger' | 'filesystem_scan'
  ledger_digest?: string
}

export interface NativeRuleCountContract {
  counts: Record<string, number>
  listed_counts?: Record<string, number>
  count_semantics: Record<string, RuleCountSemantics>
}

export interface NativeEngineRulesResponse extends NativeRuleCountContract {
  items: readonly Record<string, unknown>[]
  total: number
  data?: NativeRuleCountContract
}

export interface ApiContractEndpoint {
  path: string
  methods: readonly HttpMethod[]
  consumerSurface: ConsumerSurface
  refreshMode: RefreshMode
  authRequired: boolean
}

export interface ApiDomainContract {
  basePath: string
  endpoints: readonly ApiContractEndpoint[]
}

export type ApiContractMatrix = Record<ApiDomain, ApiDomainContract>

export type DashboardModule = 'assets' | 'events' | 'incidents' | 'timeline' | 'topology'

export interface DashboardModuleContract {
  module: DashboardModule
  listEndpoint: string
  detailEndpoint?: string
  mutateEndpoints?: readonly string[]
  requiredFields: readonly string[]
  listAliases: readonly string[]
}

export type DashboardContractMatrix = Record<DashboardModule, DashboardModuleContract>

export const API_CONTRACT_MATRIX: ApiContractMatrix = {
  auth: {
    basePath: '/api/v1/auth',
    endpoints: [
      {
        path: '/api/v1/auth/register',
        methods: ['POST'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: false,
      },
      {
        path: '/api/v1/auth/login',
        methods: ['POST'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: false,
      },
      {
        path: '/api/v1/auth/logout',
        methods: ['POST'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/auth/profile',
        methods: ['GET'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/auth/change-password',
        methods: ['POST'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/auth/users',
        methods: ['GET'],
        consumerSurface: 'settings',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/auth/users/password',
        methods: ['POST'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/auth/users/{id}',
        methods: ['PUT', 'DELETE'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: true,
      },
    ],
  },
  stats: {
    basePath: '/api/v1',
    endpoints: [
      {
        path: '/api/v1/stats',
        methods: ['GET'],
        consumerSurface: 'dashboard',
        refreshMode: 'poll',
        authRequired: true,
      },
    ],
  },
  events: {
    basePath: '/api/v1',
    endpoints: [
      {
        path: '/api/v1/events',
        methods: ['GET'],
        consumerSurface: 'events',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/events/{id}',
        methods: ['GET'],
        consumerSurface: 'events',
        refreshMode: 'request',
        authRequired: true,
      },
    ],
  },
  incidents: {
    basePath: '/api/v1/incidents',
    endpoints: [
      {
        path: '/api/v1/incidents',
        methods: ['GET'],
        consumerSurface: 'incidents',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/incidents/{id}',
        methods: ['GET'],
        consumerSurface: 'incidents',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/incidents/{id}/status',
        methods: ['PATCH'],
        consumerSurface: 'incidents',
        refreshMode: 'request',
        authRequired: true,
      },
    ],
  },
  timeline: {
    basePath: '/api/v1/timeline',
    endpoints: [
      {
        path: '/api/v1/timeline',
        methods: ['GET'],
        consumerSurface: 'timeline',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/incidents/{id}/timeline',
        methods: ['GET'],
        consumerSurface: 'timeline',
        refreshMode: 'request',
        authRequired: true,
      },
    ],
  },
  topology: {
    basePath: '/api/v1/topology',
    endpoints: [
      {
        path: '/api/v1/topology',
        methods: ['GET'],
        consumerSurface: 'topology',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/topology/assets/{id}',
        methods: ['GET'],
        consumerSurface: 'topology',
        refreshMode: 'request',
        authRequired: true,
      },
    ],
  },
  xdr: {
    basePath: '/api/v1/xdr',
    endpoints: [
      {
        path: '/api/v1/xdr/stats',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/xdr/events',
        methods: ['GET'],
        consumerSurface: 'events',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/xdr/sources',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/xdr/top-events',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/xdr/log',
        methods: ['GET'],
        consumerSurface: 'events',
        refreshMode: 'stream',
        authRequired: true,
      },
    ],
  },
  unified: {
    basePath: '/api/v1/unified',
    endpoints: [
      {
        path: '/api/v1/unified/stats',
        methods: ['GET'],
        consumerSurface: 'dashboard',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/unified/events',
        methods: ['GET'],
        consumerSurface: 'events',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/unified/events/search',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'request',
        authRequired: true,
      },
    ],
  },
  rasp: {
    basePath: '/api/v1/rasp',
    endpoints: [
      {
        path: '/api/v1/rasp/stats',
        methods: ['GET'],
        consumerSurface: 'dashboard',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/rasp/events',
        methods: ['GET'],
        consumerSurface: 'events',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/rasp/rules',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/rasp/agents',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/rasp/protection/enable',
        methods: ['POST'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/rasp/protection/disable',
        methods: ['POST'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/rasp/protection/status',
        methods: ['GET'],
        consumerSurface: 'settings',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/rasp/event',
        methods: ['POST'],
        consumerSurface: 'events',
        refreshMode: 'stream',
        authRequired: false,
      },
      {
        path: '/api/v1/rasp/elkeid-rules',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'request',
        authRequired: true,
      },
    ],
  },
  trace: {
    basePath: '/api/v1/trace',
    endpoints: [
      {
        path: '/api/v1/trace/stats',
        methods: ['GET'],
        consumerSurface: 'dashboard',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/trace/sessions',
        methods: ['GET'],
        consumerSurface: 'events',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/trace/sessions/{id}',
        methods: ['GET'],
        consumerSurface: 'events',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/trace/events',
        methods: ['GET'],
        consumerSurface: 'events',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/trace/analyze',
        methods: ['POST'],
        consumerSurface: 'intelligence',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/trace/search',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'request',
        authRequired: true,
      },
    ],
  },
  assets: {
    basePath: '/api/v1/assets',
    endpoints: [
      {
        path: '/api/v1/assets/stats',
        methods: ['GET'],
        consumerSurface: 'assets',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/assets',
        methods: ['GET'],
        consumerSurface: 'assets',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/assets/{id}',
        methods: ['GET'],
        consumerSurface: 'assets',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/assets/groups',
        methods: ['GET'],
        consumerSurface: 'assets',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/assets/heartbeat',
        methods: ['POST'],
        consumerSurface: 'assets',
        refreshMode: 'stream',
        authRequired: false,
      },
    ],
  },
  agent: {
    basePath: '/api/v1/agent',
    endpoints: [
      {
        path: '/api/v1/agent/enroll',
        methods: ['POST'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: false,
      },
      {
        path: '/api/v1/agent/heartbeat',
        methods: ['POST'],
        consumerSurface: 'dashboard',
        refreshMode: 'stream',
        authRequired: false,
      },
      {
        path: '/api/v1/agent/config',
        methods: ['GET'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/agent/task-result',
        methods: ['POST'],
        consumerSurface: 'dashboard',
        refreshMode: 'stream',
        authRequired: false,
      },
      {
        path: '/api/v1/agent/runtime-event',
        methods: ['POST'],
        consumerSurface: 'events',
        refreshMode: 'stream',
        authRequired: false,
      },
      {
        path: '/api/v1/agent/install.sh',
        methods: ['GET'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: false,
      },
      {
        path: '/api/v1/agent/download',
        methods: ['GET'],
        consumerSurface: 'settings',
        refreshMode: 'request',
        authRequired: false,
      },
      {
        path: '/api/v1/agent/snapshot',
        methods: ['POST'],
        consumerSurface: 'assets',
        refreshMode: 'stream',
        authRequired: false,
      },
    ],
  },
  threatIntelligence: {
    basePath: '/api/v1/threat-intelligence',
    endpoints: [
      {
        path: '/api/v1/threat-intelligence/rasp-apps',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/threat-intelligence/runtime-hosts',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/threat-intelligence/combined',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'poll',
        authRequired: true,
      },
    ],
  },
  rules: {
    basePath: '/api/v1/rules',
    endpoints: [
      {
        path: '/api/v1/rules/sources',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'poll',
        authRequired: true,
      },
      {
        path: '/api/v1/rules/sync/{source}/dry-run',
        methods: ['POST'],
        consumerSurface: 'intelligence',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/rules/sync/{source}',
        methods: ['POST'],
        consumerSurface: 'intelligence',
        refreshMode: 'request',
        authRequired: true,
      },
      {
        path: '/api/v1/rules/sync/history',
        methods: ['GET'],
        consumerSurface: 'intelligence',
        refreshMode: 'poll',
        authRequired: true,
      },
    ],
  },
  publicSituation: {
    basePath: '/api/v1/public/situation',
    endpoints: [
      {
        path: '/api/v1/public/situation/global',
        methods: ['GET'],
        consumerSurface: 'globalSituation',
        refreshMode: 'poll',
        authRequired: false,
      },
    ],
  },
}

export const DASHBOARD_CONTRACT_MATRIX: DashboardContractMatrix = {
  assets: {
    module: 'assets',
    listEndpoint: '/api/v1/assets',
    detailEndpoint: '/api/v1/assets/{id}',
    requiredFields: ['id', 'hostname', 'ip', 'status'],
    listAliases: ['assets', 'hosts', 'items'],
  },
  events: {
    module: 'events',
    listEndpoint: '/api/v1/unified/events',
    detailEndpoint: '/api/v1/events/{id}',
    requiredFields: ['id', 'event_type', 'source', 'severity', 'timestamp'],
    listAliases: ['events', 'items', 'list'],
  },
  incidents: {
    module: 'incidents',
    listEndpoint: '/api/v1/incidents',
    detailEndpoint: '/api/v1/incidents/{id}',
    mutateEndpoints: ['/api/v1/incidents/{id}/status'],
    requiredFields: ['id', 'severity', 'status', 'title', 'event_count', 'created_at'],
    listAliases: ['incidents', 'items', 'list'],
  },
  timeline: {
    module: 'timeline',
    listEndpoint: '/api/v1/timeline',
    detailEndpoint: '/api/v1/incidents/{id}/timeline',
    requiredFields: ['id', 'timestamp', 'source_module', 'event_type', 'severity'],
    listAliases: ['timeline', 'events', 'items'],
  },
  topology: {
    module: 'topology',
    listEndpoint: '/api/v1/topology',
    detailEndpoint: '/api/v1/topology/assets/{id}',
    requiredFields: ['nodes', 'edges', 'updated_at'],
    listAliases: ['topology', 'items'],
  },
}

export function validateDashboardContractPayload(module: DashboardModule, payload: Record<string, unknown>) {
  const contract = DASHBOARD_CONTRACT_MATRIX[module]
  const missing = contract.requiredFields.filter(field => {
    const value = payload[field]
    return value === undefined || value === null || (typeof value === 'string' && value.trim() === '')
  })

  return {
    valid: missing.length === 0,
    missing,
  }
}

export const THREAT_INTELLIGENCE_TABS = [
  { key: 'rasp-apps', label: 'rasp应用', endpoint: '/api/v1/threat-intelligence/rasp-apps' },
  { key: 'runtime-hosts', label: 'runtime主机', endpoint: '/api/v1/threat-intelligence/runtime-hosts' },
  { key: 'combined', label: '合并', endpoint: '/api/v1/threat-intelligence/combined' },
] as const

export interface AssetOpsMetrics {
  cpuModel: string | null
  cpuUsagePercent: number | null
  memoryTotalMb: number | null
  memoryUsedMb: number | null
  memoryUsagePercent: number | null
  diskTotalGb: number | null
  diskUsedGb: number | null
  diskUsagePercent: number | null
  os: string | null
  arch: string | null
  agentVersion: string | null
  lastUpdatedAt: string | null
  stale: boolean
}
