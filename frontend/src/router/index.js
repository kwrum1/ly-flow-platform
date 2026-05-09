import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue')
  },
  {
    path: '/',
    component: () => import('../layout/Layout.vue'),
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('../views/Dashboard.vue')
      },
      {
        path: 'assets',
        name: 'Assets',
        component: () => import('../views/Assets.vue')
      },
      {
        path: 'events',
        name: 'Events',
        component: () => import('../views/Events.vue')
      },
      {
        path: 'events/:id',
        name: 'EventDetail',
        component: () => import('../views/EventDetail.vue')
      },
      {
        path: 'threat-intel',
        name: 'ThreatIntel',
        component: () => import('../views/ThreatIntel.vue')
      },
      {
        path: 'vulnerabilities',
        name: 'Vulnerabilities',
        component: () => import('../views/Vulnerabilities.vue')
      },
      {
        path: 'reports',
        name: 'Reports',
        component: () => import('../views/Reports.vue')
      },
      {
        path: 'settings',
        name: 'Settings',
        component: () => import('../views/Settings.vue')
      }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
