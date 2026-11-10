/**
 * Frontend RBAC role groups.
 *
 * These are a deliberate 1:1 mirror of the backend policy groups in
 * `server/cmd/route_registry.go`:
 *
 *   allRoles      = [admin, analyst, viewer]  // default read access
 *   operatorRoles = [admin, analyst]          // default write access
 *   adminRoles    = [admin]                   // paths listed in
 *                                             // `adminOnly` in
 *                                             // route_registry_data.go
 *
 * A route's `meta.roles` must be exactly one of these three arrays. Keeping
 * the arrays in one module stops the router, the v4 navigation and the tests
 * from drifting into ad-hoc combinations (for example `['admin','viewer']`,
 * which no backend group grants).
 */
export const ALL_ROLES = Object.freeze(['admin', 'analyst', 'viewer'])
export const OPERATOR_ROLES = Object.freeze(['admin', 'analyst'])
export const ADMIN_ROLES = Object.freeze(['admin'])

export const ROLE_SETS = Object.freeze([ALL_ROLES, OPERATOR_ROLES, ADMIN_ROLES])

/** True when `role` may open a route protected by `roles`. No roles = open to any signed-in role. */
export function canAccessRoles(roles, role) {
  if (!Array.isArray(roles) || roles.length === 0) return true
  return roles.includes(role)
}

/**
 * First page every role can open. `/overview` is backed only by allRoles
 * endpoints, so it is a safe landing page for admin, analyst and viewer
 * alike — including as the target of the no-permission recovery link.
 */
export const DEFAULT_HOME_PATH = '/overview'
