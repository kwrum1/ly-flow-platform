export type Role = 'admin' | 'analyst' | 'viewer'
export type FrontendDisposition = 'retain' | 'consolidate' | 'remove' | '404'
export type FrontendAuthMode = 'public' | 'session-decision' | 'session'
export type FrontendSource = 'router' | 'navigation' | 'metadata'
export type HttpContractMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'WS'
export type ApiAuthMode = 'public' | 'jwt' | 'agent-credential' | 'loopback'
export type ApiDisposition = 'ui-workflow' | 'api-only' | 'agent-only' | 'public' | 'loopback-only'
export type ReadbackExpectation = 'not-applicable' | 'response' | 'read-after-write' | 'stream' | 'runtime-state'
export type PersistenceExpectation = 'none' | 'ephemeral' | 'durable' | 'durable-with-audit' | 'artifact'
export type OwnerTask = 'T06' | 'T14' | 'T15'

export type ContractFixture = {
  readonly method: HttpContractMethod
  readonly path: string
  readonly body: Readonly<Record<string, unknown>> | null
  readonly expectedStatuses: readonly number[]
}

export type ApiOperationContract = {
  readonly method: HttpContractMethod
  readonly allowedRoles: readonly Role[]
  readonly validFixture: ContractFixture
  readonly invalidFixture: ContractFixture
  readonly mutation: boolean
  readonly readback: ReadbackExpectation
  readonly persistence: PersistenceExpectation
}

export type ApiRouteAcceptanceContract = {
  readonly path: string
  readonly authMode: ApiAuthMode
  readonly operations: readonly ApiOperationContract[]
  readonly disposition: ApiDisposition
  readonly notes?: string
}

export type FrontendRouteAcceptanceContract = {
  readonly path: string
  readonly disposition: FrontendDisposition
  readonly canonicalPaths: readonly string[]
  readonly authMode: FrontendAuthMode
  readonly allowedRoles: readonly Role[]
  readonly currentSources: readonly FrontendSource[]
  readonly currentGap?: string
}

export type ExpectedRedGap = {
  readonly id: string
  readonly current: string
  readonly required: string
  readonly ownerTask: OwnerTask
}

export type ProductAcceptanceContract = {
  readonly schemaVersion: 1
  readonly registry: {
    readonly mountedPathCount: number
    readonly sortedPathSha256: string
  }
  readonly roles: readonly Role[]
  readonly frontendRoutes: readonly FrontendRouteAcceptanceContract[]
  readonly apiRoutes: readonly ApiRouteAcceptanceContract[]
  readonly expectedRedGaps: readonly ExpectedRedGap[]
}
