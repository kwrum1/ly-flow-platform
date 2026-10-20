import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { evaluateAuthGuard } from './guard'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/login', name: 'Login', component: () => import('../views/Login.vue'), meta: { requiresAuth: false } },
  { path: '/change-password', name: 'ChangePassword', component: () => import('../views/ChangePassword.vue'), meta: { requiresAuth: false } },
  {
    path: '/',
    component: () => import('../app/AppShell.vue'),
    meta: { requiresAuth: true },
    children: [
      { path: 'dashboard', name: 'Overview', component: () => import('../views/situation/OverviewV2.vue'), meta: { roles: ['admin'] } },
      { path: 'situation/global', name: 'GlobalSituation', component: () => import('../views/situation/GlobalSituation.vue'), meta: { roles: ['admin'] } },
      { path: 'events', name: 'EventsWorkbench', component: () => import('../views/events/EventsRoute.vue'), meta: { roles: ['admin'] } },
      { path: 'events/:uid', name: 'EventDetail', component: () => import('../views/events/EventsV2.vue'), meta: { roles: ['admin'] } },
      { path: 'incidents', name: 'Incidents', component: () => import('../views/incidents/IncidentRoute.vue'), meta: { roles: ['admin'] } },
      { path: 'timeline', name: 'IncidentsTimeline', component: () => import('../pages/IncidentsTimeline.vue'), meta: { roles: ['admin'] } },
      { path: 'xdr', name: 'AttackWorkbench', component: () => import('../pages/AttackWorkbench.vue'), meta: { roles: ['admin'] } },
      { path: 'assets', name: 'AssetsAgents', component: () => import('../pages/AssetsAgents.vue'), meta: { roles: ['admin'] } },
      { path: 'response', name: 'ResponseCenter', component: () => import('../pages/ResponseCenter.vue'), meta: { roles: ['admin'] } },
      { path: 'evidence', name: 'EvidenceCenter', component: () => import('../pages/EvidenceCenter.vue'), meta: { roles: ['admin'] } },
      { path: 'engines', name: 'EngineHealth', component: () => import('../pages/EngineHealth.vue'), meta: { roles: ['admin'] } },
      { path: 'runtime', name: 'HostLogThreats', component: () => import('../pages/TrafficThreats.vue'), props: { category: 'runtime', title: '运行威胁' }, meta: { roles: ['admin'] } },
      { path: 'rasp', name: 'RaspThreats', component: () => import('../pages/TrafficThreats.vue'), props: { category: 'rasp', title: '应用威胁' }, meta: { roles: ['admin'] } },
      { path: 'trace', name: 'SignalsTrace', component: () => import('../pages/SignalsRuntime.vue'), props: { mode: 'trace' }, meta: { roles: ['admin'] } },
      { path: 'rules', name: 'RulesCenter', component: () => import('../pages/RulesCenter.vue'), meta: { roles: ['admin'] } },
      { path: 'users', name: 'Users', component: () => import('../pages/UsersAdmin.vue'), meta: { roles: ['admin'] } },
      { path: 'install-config', name: 'InstallConfig', component: () => import('../pages/InstallConfig.vue'), meta: { roles: ['admin'] } },
      { path: 'traffic-observe', name: 'TrafficObserve', component: () => import('../pages/TrafficObserve.vue'), meta: { roles: ['admin'] } },
      { path: 'traffic-threats', name: 'TrafficThreats', component: () => import('../pages/TrafficThreats.vue'), meta: { roles: ['admin'] } },
      { path: 'application-threats', name: 'ApplicationThreats', component: () => import('../pages/ApplicationThreats.vue'), meta: { roles: ['admin'] } },
      { path: 'system-security-audit', name: 'SystemSecurityAudit', component: () => import('../pages/SystemSecurityAudit.vue'), meta: { roles: ['admin'] } },
      { path: 'control-center', name: 'ControlCenter', component: () => import('../pages/ControlCenter.vue'), meta: { roles: ['admin'] } },
      { path: 'host-ops', name: 'HostOps', component: () => import('../pages/HostOps.vue'), meta: { roles: ['admin'] } },
      { path: 'real-time-posture', name: 'RealTimePosture', component: () => import('../pages/RealTimePosture.vue'), meta: { roles: ['admin'] } },
      { path: 'rule-visibility', name: 'RuleVisibility', component: () => import('../pages/RuleVisibility.vue'), meta: { roles: ['admin'] } },
      { path: 'rule-updates', name: 'RuleUpdates', component: () => import('../pages/RuleUpdates.vue'), meta: { roles: ['admin'] } },
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
