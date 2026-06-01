<template>
  <div class="ly-layout">
    <aside class="ly-sidebar">
      <div class="sidebar-header">
        <div class="brand-mark">LY</div>
        <div>
          <div class="logo-text">流影安全</div>
          <div class="logo-subtitle">Signal Command</div>
        </div>
      </div>

      <nav class="sidebar-nav" aria-label="主导航">
        <section
          v-for="group in navGroups"
          :key="group.title"
          class="nav-section"
        >
          <div class="nav-section-title">
            {{ group.title }}
          </div>
          <button
            v-for="item in group.items"
            :key="item.path"
            type="button"
            class="nav-item"
            :class="{ active: isNavActive(item) }"
            :data-testid="navTestId(item.path)"
            @click="goPage(item.path)"
          >
            <svg
              class="nav-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
            >
              <path :d="item.icon" />
            </svg>
            <span class="nav-copy">
              <span class="nav-text">{{ item.label }}</span>
              <span class="nav-hint">{{ item.hint }}</span>
            </span>
            <span
              v-if="item.badge"
              class="nav-badge"
            >{{ item.badge }}</span>
          </button>
        </section>
      </nav>

      <div class="sidebar-footer">
        <div class="operator-card">
          <div class="user-avatar">
            {{ usernameInitial }}
          </div>
          <div class="user-detail">
            <span class="user-name">{{ username }}</span>
            <span class="user-role">{{ roleName }}</span>
          </div>
        </div>
      </div>
    </aside>

    <div class="ly-main">
      <header class="ly-header">
        <div class="header-left">
          <div class="breadcrumb">
            <span
              v-for="(item, idx) in breadcrumbs"
              :key="`${item}-${idx}`"
              class="breadcrumb-item"
            >
              <span
                v-if="idx > 0"
                class="breadcrumb-sep"
              >/</span>
              {{ item }}
            </span>
          </div>
          <div class="route-intent">
            {{ routeIntent }}
          </div>
        </div>
        <div class="header-right">
          <div class="status-panel">
            <div class="status-row">
              <span class="status-key">Realtime</span>
              <span class="status-value">{{ realtimeSummary }}</span>
            </div>
            <div class="status-row">
              <span class="status-key">Polling</span>
              <span class="status-value" :class="pollingFreshness">{{ pollingSummary }}</span>
            </div>
            <div class="status-row">
              <span class="status-key">阶段</span>
              <span class="status-value">{{ completedStages }}</span>
            </div>
          </div>
          <div class="signal-health">
            <span class="health-dot" />
            <span>监测在线</span>
          </div>
          <div class="header-time">
            <span class="time-text">{{ currentTime }}</span>
            <span class="time-date">{{ currentDate }}</span>
          </div>
        </div>
      </header>

      <main class="ly-content">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { CONNECTION_STATUS } from '../realtime'
import { platformNow } from '../shared/time'
import {
  navGroups as sharedNavGroups,
  routeMeta as sharedRouteMeta
} from './nav-config'

export default {
  name: 'Layout',
  setup() {
    const router = useRouter()
    const route = useRoute()
    const currentTime = ref('')
    const currentDate = ref('')
    const realtimeStatus = ref(typeof navigator !== 'undefined' && navigator.onLine ? CONNECTION_STATUS.OPEN : CONNECTION_STATUS.DEGRADED)
    const pollingFreshness = ref('fresh')
    const completedStages = ref('T1 · T2 · T3 · T4 · T5')

    const routeMeta = sharedRouteMeta

    const getStorage = (key, fallback = '') => {
      try {
        return localStorage.getItem(key) || fallback
      } catch {
        return fallback
      }
    }

    const username = ref(getStorage('username', 'Admin'))
    const currentUserRole = computed(() => getStorage('role', 'viewer'))
    const roleName = computed(() => currentUserRole.value === 'admin' ? '安全管理员' : '安全运营')
    const navGroups = computed(() => sharedNavGroups
      .map((group) => ({
        ...group,
        items: group.items.filter((item) => {
          if (!Array.isArray(item.roles) || item.roles.length === 0) return true
          return item.roles.includes(currentUserRole.value)
        }),
      }))
      .filter((group) => group.items.length > 0))
    const usernameInitial = computed(() => username.value.slice(0, 1).toUpperCase())
    const currentMeta = computed(() => routeMeta[route.path] || routeMeta['/dashboard'])
    const breadcrumbs = computed(() => currentMeta.value.crumbs)
    const routeIntent = computed(() => currentMeta.value.intent)

    const realtimeSummary = computed(() => {
      if (realtimeStatus.value === CONNECTION_STATUS.OPEN) return '实时连接正常'
      if (realtimeStatus.value === CONNECTION_STATUS.CONNECTING) return '实时连接中'
      if (realtimeStatus.value === CONNECTION_STATUS.DEGRADED) return '实时降级轮询'
      if (realtimeStatus.value === CONNECTION_STATUS.ERROR) return '实时连接异常'
      if (realtimeStatus.value === CONNECTION_STATUS.CLOSED) return '实时连接关闭'
      return '实时连接空闲'
    })

    const pollingSummary = computed(() => pollingFreshness.value === 'stale' ? 'stale' : 'fresh')

    const isNavActive = (item) => item.match.some(path => route.path === path || (path !== '/intelligence' && route.path.startsWith(`${path}/`)))
    const goPage = (path) => {
      if (route.path !== path) router.push(path)
    }
    const navTestId = (path) => `nav-item-${String(path || '').replace(/^\//, '').replace(/\//g, '-') || 'root'}`

    let timer = null
    const syncConnectivity = () => {
      const online = typeof navigator !== 'undefined' ? navigator.onLine : true
      realtimeStatus.value = online ? CONNECTION_STATUS.OPEN : CONNECTION_STATUS.DEGRADED
      pollingFreshness.value = online ? 'fresh' : 'stale'
    }

    const updateTime = () => {
      const now = platformNow()
      currentTime.value = now.toLocaleTimeString('zh-CN', {
        timeZone: 'Asia/Shanghai', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
      })
      currentDate.value = now.toLocaleDateString('zh-CN', {
        timeZone: 'Asia/Shanghai', weekday: 'short', month: '2-digit', day: '2-digit'
      })
    }

    onMounted(() => {
      updateTime()
      syncConnectivity()
      window.addEventListener('online', syncConnectivity)
      window.addEventListener('offline', syncConnectivity)
      timer = setInterval(updateTime, 1000)
    })

    onUnmounted(() => {
      if (timer) clearInterval(timer)
      window.removeEventListener('online', syncConnectivity)
      window.removeEventListener('offline', syncConnectivity)
    })

    return {
      currentTime,
      currentDate,
      username,
      roleName,
      usernameInitial,
      navGroups,
      breadcrumbs,
      routeIntent,
      realtimeSummary,
      pollingFreshness,
      pollingSummary,
      completedStages,
      isNavActive,
      goPage,
      navTestId
    }
  }
}
</script>

<style scoped>
.ly-layout {
  display: flex;
  height: 100vh;
  overflow: hidden;
  background: var(--bg-gradient);
}

.ly-sidebar {
  width: var(--sidebar-width);
  background: linear-gradient(180deg, rgba(4, 12, 24, 0.98), rgba(7, 17, 31, 0.94));
  border-right: 1px solid var(--border-light);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  box-shadow: 18px 0 60px rgba(0, 0, 0, 0.26);
}

.sidebar-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 22px 18px;
  border-bottom: 1px solid var(--border-light);
}

.brand-mark {
  width: 42px;
  height: 42px;
  display: grid;
  place-items: center;
  border-radius: 14px;
  background: linear-gradient(135deg, var(--primary-light), var(--primary-dark));
  color: #06101d;
  font-weight: 950;
  letter-spacing: -0.08em;
  box-shadow: 0 16px 42px rgba(56, 189, 248, 0.22);
}

.logo-text {
  color: var(--text-primary);
  font-size: 16px;
  font-weight: 900;
  letter-spacing: 0.02em;
}

.logo-subtitle {
  margin-top: 2px;
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.sidebar-nav {
  flex: 1;
  padding: 14px 12px;
  overflow-y: auto;
}

.nav-section + .nav-section {
  margin-top: 18px;
}

.nav-section-title {
  padding: 0 10px 8px;
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 900;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

.nav-item {
  position: relative;
  width: 100%;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 10px;
  border: 1px solid transparent;
  border-radius: 14px;
  background: transparent;
  color: var(--text-secondary);
  text-align: left;
  cursor: pointer;
  transition: all var(--transition-fast);
}

.nav-item + .nav-item {
  margin-top: 4px;
}

.nav-item:hover {
  background: var(--sidebar-item-hover);
  border-color: rgba(56, 189, 248, 0.18);
  color: var(--text-primary);
}

.nav-item.active {
  background: linear-gradient(135deg, rgba(56, 189, 248, 0.18), rgba(139, 92, 246, 0.12));
  border-color: rgba(56, 189, 248, 0.38);
  color: var(--text-primary);
  box-shadow: inset 3px 0 0 var(--primary-light), 0 14px 34px rgba(56, 189, 248, 0.08);
}

.nav-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  color: currentColor;
}

.nav-copy {
  min-width: 0;
  display: flex;
  flex: 1;
  flex-direction: column;
  gap: 1px;
}

.nav-text {
  color: currentColor;
  font-size: 13px;
  font-weight: 850;
}

.nav-hint {
  overflow: hidden;
  color: var(--text-muted);
  font-size: 11px;
  white-space: nowrap;
  text-overflow: ellipsis;
}

.nav-badge {
  padding: 2px 7px;
  border-radius: 999px;
  background: var(--risk-critical-bg);
  color: var(--risk-critical);
  border: 1px solid var(--risk-critical-border);
  font-size: 10px;
  font-weight: 900;
}

.sidebar-footer {
  padding: 14px;
  border-top: 1px solid var(--border-light);
}

.operator-card {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px;
  border: 1px solid var(--border-light);
  border-radius: 16px;
  background: rgba(15, 23, 42, 0.52);
}

.user-avatar {
  width: 34px;
  height: 34px;
  display: grid;
  place-items: center;
  border-radius: 50%;
  background: rgba(56, 189, 248, 0.14);
  color: var(--primary-light);
  font-weight: 900;
}

.user-detail {
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.user-name {
  color: var(--text-primary);
  font-size: 13px;
  font-weight: 800;
}

.user-role {
  color: var(--text-muted);
  font-size: 11px;
}

.ly-main {
  min-width: 0;
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.ly-header {
  min-height: var(--header-height);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 0 24px;
  background: var(--header-bg);
  border-bottom: 1px solid var(--border-light);
  backdrop-filter: blur(18px);
}

.header-left {
  min-width: 0;
}

.breadcrumb {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--text-secondary);
}

.breadcrumb-item {
  font-size: 13px;
  font-weight: 800;
}

.breadcrumb-item:last-child {
  color: var(--text-primary);
}

.breadcrumb-sep {
  color: var(--text-muted);
  margin-right: 6px;
}

.route-intent {
  margin-top: 3px;
  color: var(--text-muted);
  font-size: 12px;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.status-panel {
  display: grid;
  gap: 2px;
  min-height: 38px;
  padding: 6px 12px;
  border: 1px solid var(--border-light);
  border-radius: 10px;
  background: rgba(15, 23, 42, 0.58);
}

.status-row {
  display: flex;
  gap: 8px;
  font-size: 11px;
}

.status-key {
  color: var(--text-muted);
  min-width: 46px;
}

.status-value {
  color: var(--text-secondary);
  font-weight: 700;
}

.status-value.stale {
  color: var(--risk-critical);
}

.status-value.fresh {
  color: var(--risk-low);
}

.signal-health,
.header-time {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 38px;
  padding: 0 12px;
  border: 1px solid var(--border-light);
  border-radius: 999px;
  background: rgba(15, 23, 42, 0.58);
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 800;
}

.health-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--risk-low);
  box-shadow: 0 0 14px var(--risk-low);
}

.time-text {
  color: var(--primary-light);
  font-family: 'SF Mono', 'Cascadia Code', Consolas, monospace;
}

.time-date {
  color: var(--text-muted);
}

.ly-content {
  flex: 1;
  min-height: 0;
  overflow: auto;
}

@media (max-width: 1280px) {
  .nav-hint,
  .route-intent {
    display: none;
  }
}

@media (max-width: 768px) {
  .logo-subtitle,
  .logo-text,
  .nav-copy,
  .nav-section-title,
  .sidebar-footer,
  .signal-health,
  .status-panel,
  .time-date {
    display: none;
  }

  .ly-sidebar {
    width: 76px;
  }

  .sidebar-header,
  .nav-item {
    justify-content: center;
  }

  .ly-header {
    padding: 0 14px;
  }
}
</style>
