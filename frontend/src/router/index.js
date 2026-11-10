import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { evaluateAuthGuard } from './guard'
import { ADMIN_ROLES, ALL_ROLES, OPERATOR_ROLES } from './roles'

/**
 * Role assignment source of truth: the backend route policy groups in
 * `server/cmd/route_registry.go` + the `adminOnly` set in
 * `server/cmd/route_registry_data.go`.
 *
 *   default read  -> allRoles      = admin + analyst + viewer
 *   default write -> operatorRoles = admin + analyst
 *   adminOnly     -> adminRoles    = admin
 *
 * A page may only be opened by a role that can actually call every API it
 * needs, so a page that performs a write or reads an admin-only endpoint is
 * never exposed to `viewer`.
 */
const routes = [
  { path: '/', redirect: '/overview' },
  { path: '/login', name: 'Login', component: () => import('../views/Login.vue'), meta: { requiresAuth: false } },
  { path: '/change-password', name: 'ChangePassword', component: () => import('../views/ChangePassword.vue'), meta: { requiresAuth: false } },
  {
    path: '/',
    component: () => import('../v4/shell/VShell.vue'),
    meta: { requiresAuth: true },
    children: [
      // Read-only posture. Backed by GET /unified/events, /incidents,
      // /agents, /assets -> allRoles.
      { path: 'overview', name: 'Overview', component: () => import('../v4/pages/Overview.vue'), meta: { roles: ALL_ROLES } },
      // Triage writes PUT /incidents/{id}/status and /incidents/{id}/assign.
      // `/api/v1/incidents/` is not adminOnly, so its write roles are
      // operatorRoles.
      { path: 'incidents', name: 'Incidents', component: () => import('../v4/pages/Incidents.vue'), meta: { roles: OPERATOR_ROLES } },
      // Read-only search. GET /unified/events + /agents -> allRoles.
      { path: 'events', name: 'Events', component: () => import('../v4/pages/Events.vue'), meta: { roles: ALL_ROLES } },
      // Read-only detection surface. GET /threats/{category},
      // /component-alerts/{category}, /unified/events, /agents -> allRoles.
      { path: 'threats', name: 'Threats', component: () => import('../v4/pages/Threats.vue'), meta: { roles: ALL_ROLES } },
      // The page can delete agents (DELETE /agents/{id}), rewrite
      // capabilities/tags/names and drive /defense/sessions and
      // /rasp/policy/actions/{version}/*. None of those paths are adminOnly,
      // so the backend grants writes to operatorRoles; viewer must not enter.
      { path: 'assets', name: 'Assets', component: () => import('../v4/pages/Assets.vue'), meta: { roles: OPERATOR_ROLES } },
      // The page is built on GET /debug/components, which is in `adminOnly`.
      { path: 'health', name: 'Health', component: () => import('../v4/pages/Health.vue'), meta: { roles: ADMIN_ROLES } },
      // `/api/v1/rules` and `/api/v1/rule-platform/*` writes are adminOnly.
      { path: 'rules', name: 'Rules', component: () => import('../v4/pages/Rules.vue'), meta: { roles: ADMIN_ROLES } },
      // The page lists users via GET /auth/users, which is adminOnly.
      { path: 'settings', name: 'Settings', component: () => import('../v4/pages/Settings.vue'), meta: { roles: ADMIN_ROLES } },
      // The denial surface itself must stay open to every signed-in role,
      // otherwise the guard would bounce between /forbidden and itself.
      { path: 'forbidden', name: 'Forbidden', component: () => import('../views/Forbidden.vue'), meta: {} },

      // Legacy routes are folded into the v4 surfaces so old links keep
      // working. Each carries the roles of the surface it lands on.
      { path: 'dashboard', redirect: '/overview', meta: { roles: ALL_ROLES } },
      { path: 'situation/global', redirect: '/overview', meta: { roles: ALL_ROLES } },
      { path: 'traffic-threats', redirect: '/threats', meta: { roles: ALL_ROLES } },
      { path: 'traffic-observe', redirect: '/threats', meta: { roles: ALL_ROLES } },
      { path: 'runtime', redirect: '/threats', meta: { roles: ALL_ROLES } },
      { path: 'rasp', redirect: '/threats', meta: { roles: ALL_ROLES } },
      { path: 'application-threats', redirect: '/threats', meta: { roles: ALL_ROLES } },
      { path: 'system-security-audit', redirect: '/threats', meta: { roles: ALL_ROLES } },
      { path: 'data-quality', redirect: '/health', meta: { roles: ADMIN_ROLES } },
      { path: 'engines', redirect: '/health', meta: { roles: ADMIN_ROLES } },
      { path: 'control-center', redirect: '/settings', meta: { roles: ADMIN_ROLES } },
      { path: 'install-config', redirect: '/settings', meta: { roles: ADMIN_ROLES } },
      { path: 'users', redirect: '/settings', meta: { roles: ADMIN_ROLES } },
      { path: 'response', redirect: '/incidents', meta: { roles: OPERATOR_ROLES } },
      { path: 'evidence', redirect: '/incidents', meta: { roles: OPERATOR_ROLES } },
      { path: 'timeline', redirect: '/incidents', meta: { roles: OPERATOR_ROLES } },
      { path: 'xdr', redirect: '/incidents', meta: { roles: OPERATOR_ROLES } },
      { path: 'host-ops', redirect: '/assets', meta: { roles: OPERATOR_ROLES } },
      { path: 'real-time-posture', redirect: '/overview', meta: { roles: ALL_ROLES } },
      { path: 'rule-visibility', redirect: '/rules', meta: { roles: ADMIN_ROLES } },
      { path: 'rule-updates', redirect: '/rules', meta: { roles: ADMIN_ROLES } },
    ],
  },
  // `/dashboard` is readable by all three roles, so the known
  // unknown-path fallback still lands somewhere every role may open.
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach((to, from, next) => {
  const authStore = useAuthStore()
  const tokenFromStorage = localStorage.getItem('token') || ''

  const decision = evaluateAuthGuard({
    toPath: to.path,
    requiresAuth: to.matched.some((record) => record.meta?.requiresAuth),
    roles: to.matched.flatMap((record) => record.meta?.roles || []),
    isAuthenticated: authStore.isAuthenticated,
    token: authStore.token || tokenFromStorage,
    needsPasswordChange: authStore.needsPasswordChange || localStorage.getItem('needs_password_change') === 'true',
    passwordChanged: authStore.passwordChanged || localStorage.getItem('password_changed') === 'true',
    userRole: authStore.user?.role || localStorage.getItem('role') || '',
  })

  if (decision === true) {
    next()
    return
  }

  next(decision)
})

export default router
