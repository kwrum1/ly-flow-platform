export type UnknownRecord = Readonly<Record<string, unknown>>

export class ProductAcceptanceContractError extends Error {
  readonly field: string

  constructor(field: string) {
    super(`Invalid product acceptance contract field: ${field}`)
    this.name = 'ProductAcceptanceContractError'
    this.field = field
  }
}

type ArrayRules = {
  readonly minItems?: number
  readonly unique?: boolean
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function jsonObject(value: unknown, field: string): UnknownRecord {
  if (!isRecord(value)) throw new ProductAcceptanceContractError(field)
  return value
}

export function closedRecord(value: unknown, field: string, allowedKeys: readonly string[]): UnknownRecord {
  const input = jsonObject(value, field)
  const allowed = new Set(allowedKeys)
  if (Object.keys(input).some((key) => !allowed.has(key))) throw new ProductAcceptanceContractError(field)
  return input
}

export function array(value: unknown, field: string, rules: ArrayRules = {}): readonly unknown[] {
  if (!Array.isArray(value) || value.length < (rules.minItems ?? 0)) throw new ProductAcceptanceContractError(field)
  if (rules.unique) {
    const serialized = value.map((item) => JSON.stringify(item))
    if (new Set(serialized).size !== value.length) throw new ProductAcceptanceContractError(field)
  }
  return value
}

export function string(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new ProductAcceptanceContractError(field)
  return value
}

export function path(value: unknown, field: string): string {
  const parsed = string(value, field)
  if (!parsed.startsWith('/')) throw new ProductAcceptanceContractError(field)
  return parsed
}

export function sha256(value: unknown, field: string): string {
  const parsed = string(value, field)
  if (!/^[a-f0-9]{64}$/.test(parsed)) throw new ProductAcceptanceContractError(field)
  return parsed
}

export function identifier(value: unknown, field: string): string {
  const parsed = string(value, field)
  if (!/^[a-z0-9-]+$/.test(parsed)) throw new ProductAcceptanceContractError(field)
  return parsed
}

export function boolean(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') throw new ProductAcceptanceContractError(field)
  return value
}

export function positiveInteger(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) throw new ProductAcceptanceContractError(field)
  return value
}
