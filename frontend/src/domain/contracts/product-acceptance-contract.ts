import rawContract from '../../../../contracts/product-acceptance/v1/route-api-contract.json'

import type {
  ApiAuthMode,
  ApiDisposition,
  ApiOperationContract,
  ApiRouteAcceptanceContract,
  ContractFixture,
  ExpectedRedGap,
  FrontendAuthMode,
  FrontendDisposition,
  FrontendRouteAcceptanceContract,
  FrontendSource,
  HttpContractMethod,
  OwnerTask,
  PersistenceExpectation,
  ProductAcceptanceContract,
  ReadbackExpectation,
  Role,
} from './product-acceptance-types'
import {
  array,
  boolean,
  closedRecord,
  identifier,
  jsonObject,
  path,
  positiveInteger,
  ProductAcceptanceContractError,
  sha256,
  string,
} from './product-acceptance-validation'

export { ProductAcceptanceContractError } from './product-acceptance-validation'

function role(value: unknown, field: string): Role {
  switch (value) {
    case 'admin':
    case 'analyst':
    case 'viewer':
      return value
    default:
      throw new ProductAcceptanceContractError(field)
  }
}

function method(value: unknown, field: string): HttpContractMethod {
  switch (value) {
    case 'GET':
    case 'HEAD':
    case 'POST':
    case 'PUT':
    case 'PATCH':
    case 'DELETE':
    case 'WS':
      return value
    default:
      throw new ProductAcceptanceContractError(field)
  }
}

function fixture(value: unknown, field: string): ContractFixture {
  const input = closedRecord(value, field, ['method', 'path', 'body', 'expected_statuses'])
  const bodyValue = input['body']
  const body = bodyValue === null ? null : jsonObject(bodyValue, `${field}.body`)
  const statuses = array(input['expected_statuses'], `${field}.expected_statuses`, { minItems: 1, unique: true }).map((status, index) => {
    if (typeof status !== 'number' || !Number.isInteger(status) || status < 100 || status > 599) {
      throw new ProductAcceptanceContractError(`${field}.expected_statuses.${index}`)
    }
    return status
  })
  return { method: method(input['method'], `${field}.method`), path: path(input['path'], `${field}.path`), body, expectedStatuses: statuses }
}

function readback(value: unknown, field: string): ReadbackExpectation {
  switch (value) {
    case 'not-applicable':
    case 'response':
    case 'read-after-write':
    case 'stream':
    case 'runtime-state':
      return value
    default:
      throw new ProductAcceptanceContractError(field)
  }
}

function persistence(value: unknown, field: string): PersistenceExpectation {
  switch (value) {
    case 'none':
    case 'ephemeral':
    case 'durable':
    case 'durable-with-audit':
    case 'artifact':
      return value
    default:
      throw new ProductAcceptanceContractError(field)
  }
}

function operation(value: unknown, field: string): ApiOperationContract {
  const input = closedRecord(value, field, ['method', 'allowed_roles', 'valid_fixture', 'invalid_fixture', 'mutation', 'readback', 'persistence'])
  return {
    method: method(input['method'], `${field}.method`),
    allowedRoles: array(input['allowed_roles'], `${field}.allowed_roles`, { unique: true }).map((item, index) => role(item, `${field}.allowed_roles.${index}`)),
    validFixture: fixture(input['valid_fixture'], `${field}.valid_fixture`),
    invalidFixture: fixture(input['invalid_fixture'], `${field}.invalid_fixture`),
    mutation: boolean(input['mutation'], `${field}.mutation`),
    readback: readback(input['readback'], `${field}.readback`),
    persistence: persistence(input['persistence'], `${field}.persistence`),
  }
}

function apiAuthMode(value: unknown, field: string): ApiAuthMode {
  switch (value) {
    case 'public':
    case 'jwt':
    case 'agent-credential':
    case 'loopback':
      return value
    default:
      throw new ProductAcceptanceContractError(field)
  }
}

function apiDisposition(value: unknown, field: string): ApiDisposition {
  switch (value) {
    case 'ui-workflow':
    case 'api-only':
    case 'agent-only':
    case 'public':
    case 'loopback-only':
      return value
    default:
      throw new ProductAcceptanceContractError(field)
  }
}

function apiRoute(value: unknown, field: string): ApiRouteAcceptanceContract {
  const input = closedRecord(value, field, ['path', 'auth_mode', 'operations', 'disposition', 'notes'])
  const notes = input['notes'] === undefined ? undefined : string(input['notes'], `${field}.notes`)
  return {
    path: path(input['path'], `${field}.path`),
    authMode: apiAuthMode(input['auth_mode'], `${field}.auth_mode`),
    operations: array(input['operations'], `${field}.operations`, { minItems: 1 }).map((item, index) => operation(item, `${field}.operations.${index}`)),
    disposition: apiDisposition(input['disposition'], `${field}.disposition`),
    ...(notes === undefined ? {} : { notes }),
  }
}

function frontendDisposition(value: unknown, field: string): FrontendDisposition {
  switch (value) {
    case 'retain':
    case 'consolidate':
    case 'remove':
    case '404':
      return value
    default:
      throw new ProductAcceptanceContractError(field)
  }
}

function frontendAuthMode(value: unknown, field: string): FrontendAuthMode {
  switch (value) {
    case 'public':
    case 'session-decision':
    case 'session':
      return value
    default:
      throw new ProductAcceptanceContractError(field)
  }
}

function frontendSource(value: unknown, field: string): FrontendSource {
  switch (value) {
    case 'router':
    case 'navigation':
    case 'metadata':
      return value
    default:
      throw new ProductAcceptanceContractError(field)
  }
}

function frontendRoute(value: unknown, field: string): FrontendRouteAcceptanceContract {
  const input = closedRecord(value, field, ['path', 'disposition', 'canonical_paths', 'auth_mode', 'allowed_roles', 'current_sources', 'current_gap'])
  const currentGap = input['current_gap'] === undefined ? undefined : string(input['current_gap'], `${field}.current_gap`)
  return {
    path: path(input['path'], `${field}.path`),
    disposition: frontendDisposition(input['disposition'], `${field}.disposition`),
    canonicalPaths: array(input['canonical_paths'], `${field}.canonical_paths`, { unique: true }).map((item, index) => path(item, `${field}.canonical_paths.${index}`)),
    authMode: frontendAuthMode(input['auth_mode'], `${field}.auth_mode`),
    allowedRoles: array(input['allowed_roles'], `${field}.allowed_roles`, { unique: true }).map((item, index) => role(item, `${field}.allowed_roles.${index}`)),
    currentSources: array(input['current_sources'], `${field}.current_sources`, { minItems: 1, unique: true }).map((item, index) => frontendSource(item, `${field}.current_sources.${index}`)),
    ...(currentGap === undefined ? {} : { currentGap }),
  }
}

function ownerTask(value: unknown, field: string): OwnerTask {
  switch (value) {
    case 'T06':
    case 'T14':
    case 'T15':
      return value
    default:
      throw new ProductAcceptanceContractError(field)
  }
}

function redGap(value: unknown, field: string): ExpectedRedGap {
  const input = closedRecord(value, field, ['id', 'current', 'required', 'owner_task'])
  return {
    id: identifier(input['id'], `${field}.id`),
    current: string(input['current'], `${field}.current`),
    required: string(input['required'], `${field}.required`),
    ownerTask: ownerTask(input['owner_task'], `${field}.owner_task`),
  }
}

export function parseProductAcceptanceContract(value: unknown): ProductAcceptanceContract {
  const input = closedRecord(value, 'contract', ['schema_version', 'registry', 'roles', 'frontend_routes', 'api_routes', 'expected_red_gaps'])
  if (input['schema_version'] !== 1) throw new ProductAcceptanceContractError('contract.schema_version')
  const registry = closedRecord(input['registry'], 'contract.registry', ['mounted_path_count', 'sorted_path_sha256'])
  const mountedPathCount = positiveInteger(registry['mounted_path_count'], 'contract.registry.mounted_path_count')
  return {
    schemaVersion: 1,
    registry: { mountedPathCount, sortedPathSha256: sha256(registry['sorted_path_sha256'], 'contract.registry.sorted_path_sha256') },
    roles: array(input['roles'], 'contract.roles', { minItems: 3, unique: true }).map((item, index) => role(item, `contract.roles.${index}`)),
    frontendRoutes: array(input['frontend_routes'], 'contract.frontend_routes', { minItems: 1 }).map((item, index) => frontendRoute(item, `contract.frontend_routes.${index}`)),
    apiRoutes: array(input['api_routes'], 'contract.api_routes', { minItems: 1 }).map((item, index) => apiRoute(item, `contract.api_routes.${index}`)),
    expectedRedGaps: array(input['expected_red_gaps'], 'contract.expected_red_gaps', { minItems: 1 }).map((item, index) => redGap(item, `contract.expected_red_gaps.${index}`)),
  }
}

export const PRODUCT_ACCEPTANCE_CONTRACT = parseProductAcceptanceContract(rawContract)
