// Feature flags for the LyFlow v2 console rollout.
// Flags default to false so an existing deployment keeps its current UI.
export function parseFlag(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase())
}

export function resolveFeatures(env = {}) {
  return {
    uiShellV2: parseFlag(env.VITE_UI_SHELL_V2_ENABLED, true),
    queryV2: parseFlag(env.VITE_QUERY_V2_ENABLED),
    attackV2: parseFlag(env.VITE_ATTACK_V2_ENABLED, true),
    agentFacade: parseFlag(env.VITE_AGENT_FACADE_ENABLED),
    responseApproval: parseFlag(env.VITE_RESPONSE_APPROVAL_ENABLED),
  }
}

export const features = resolveFeatures(import.meta.env || {})

export function isFeatureEnabled(name) {
  return Boolean(features[name])
}
