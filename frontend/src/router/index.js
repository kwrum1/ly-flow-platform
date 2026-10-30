import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { evaluateAuthGuard } from './guard'

const routes = [
  { path: '/', redirect: '/overview' },
  { path: '/login', name: 'Login', component: () => import('../views/Login.vue'), meta: { requiresAuth: false } },
  { path: '/change-password', name: 'ChangePassword', component: () => import('../views/ChangePassword.vue'), meta: { requiresAuth: false } },
  {
    path: '/',
    component: () => import('../v4/shell/VShell.vue'),
    meta: { requiresAuth: true },
    children: [
      { path: 'overview', name: 'Overview', component: () => import('../v4/pages/Overview.vue'), meta: { roles: ['admin'] } },
      { path: 'incidents', name: 'Incidents', component: () => import('../v4/pages/Incidents.vue'), meta: { roles: ['admin'] } },
      { path: 'events', name: 'Events', component: () => import('../v4/pages/Events.vue'), meta: { roles: ['admin'] } },
      { path: 'threats', name: 'Threats', component: () => import('../v4/pages/Threats.vue'), meta: { roles: ['admin'] } },
      { path: 'assets', name: 'Assets', component: () => import('../v4/pages/Assets.vue'), meta: { roles: ['admin'] } },
      { path: 'health', name: 'Health', component: () => import('../v4/pages/Health.vue'), meta: { roles: ['admin'] } },
      { path: 'rules', name: 'Rules', component: () => import('../v4/pages/Rules.vue'), meta: { roles: ['admin'] } },
      { path: 'settings', name: 'Settings', component: () => import('../v4/pages/Settings.vue'), meta: { roles: ['admin'] } },
      { path: 'forbidden', name: 'Forbidden', component: () => import('../views/Forbidden.vue'), meta: {} },

      // Legacy routes are folded into the v4 surfaces so old links keep working.
      { path: 'dashboard', redirect: '/overview', meta: { roles: ['admin'] } },
      { path: 'situation/global', redirect: '/overview', meta: { roles: ['admin'] } },
      { path: 'traffic-threats', redirect: '/threats', meta: { roles: ['admin'] } },
      { path: 'traffic-observe', redirect: '/threats', meta: { roles: ['admin'] } },
      { path: 'runtime', redirect: '/threats', meta: { roles: ['admin'] } },
      { path: 'rasp', redirect: '/threats', meta: { roles: ['admin'] } },
      { path: 'application-threats', redirect: '/threats', meta: { roles: ['admin'] } },
      { path: 'system-security-audit', redirect: '/threats', meta: { roles: ['admin'] } },
      { path: 'data-quality', redirect: '/health', meta: { roles: ['admin'] } },
      { path: 'engines', redirect: '/health', meta: { roles: ['admin'] } },
      { path: 'control-center', redirect: '/settings', meta: { roles: ['admin'] } },
      { path: 'install-config', redirect: '/settings', meta: { roles: ['admin'] } },
      { path: 'users', redirect: '/settings', meta: { roles: ['admin'] } },
      { path: 'response', redirect: '/incidents', meta: { roles: ['admin'] } },
      { path: 'evidence', redirect: '/incidents', meta: { roles: ['admin'] } },
      { path: 'timeline', redirect: '/incidents', meta: { roles: ['admin'] } },
      { path: 'xdr', redirect: '/incidents', meta: { roles: ['admin'] } },
      { path: 'host-ops', redirect: '/assets', meta: { roles: ['admin'] } },
      { path: 'real-time-posture', redirect: '/overview', meta: { roles: ['admin'] } },
      { path: 'rule-visibility', redirect: '/rules', meta: { roles: ['admin'] } },
      { path: 'rule-updates', redirect: '/rules', meta: { roles: ['admin'] } },
    ],
  },
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
