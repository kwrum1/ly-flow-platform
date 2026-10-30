<template>
  <div class="lf-shell" :class="{ 'is-collapsed': collapsed, 'is-nav-open': navOpen }">
    <button v-if="navOpen" class="lf-scrim" type="button" aria-label="关闭导航" @click="navOpen = false" />

    <aside class="lf-rail" aria-label="主导航">
      <RouterLink class="lf-brand" to="/dashboard" aria-label="流影安全态势感知首页" @click="navOpen = false">
        <span class="lf-brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.7">
            <path d="M12 2.8 20 6v6.1c0 4.6-3.4 7.7-8 9.1-4.6-1.4-8-4.5-8-9.1V6l8-3.2Z" />
            <path d="M8.6 12.2l2.3 2.3 4.5-4.6" />
          </svg>
        </span>
        <span class="lf-brand-copy">
          <strong>流影安全</strong>
          <small>LYFLOW · XDR</small>
        </span>
      </RouterLink>

      <nav class="lf-nav">
        <section v-for="group in groups" :key="group.title" class="lf-nav-group">
          <h2>{{ group.title }}</h2>
          <RouterLink
            v-for="item in group.items"
            :key="item.path"
            :to="item.path"
            class="lf-nav-item"
            :class="{ active: isActive(item.path) }"
            :title="collapsed ? `${item.label} — ${item.description}` : item.description"
            @click="navOpen = false"
          >
            <el-icon class="lf-nav-icon"><component :is="iconFor(item.path)" /></el-icon>
            <span class="lf-nav-label">{{ item.label }}</span>
          </RouterLink>
        </section>
      </nav>

      <div class="lf-rail-foot">
        <span class="lf-rail-dot" :data-state="truth.components" />
        <span v-if="!collapsed" class="lf-rail-foot-copy">
          {{ truthLabel }}
        </span>
      </div>
    </aside>

    <div class="lf-body">
      <header class="lf-truthbar">
        <button class="lf-icon-btn lf-nav-trigger" type="button" aria-label="打开导航" @click="navOpen = true">
          <el-icon><Menu /></el-icon>
        </button>
        <button class="lf-icon-btn lf-collapse" type="button" :aria-label="collapsed ? '展开导航' : '收起导航'" @click="toggleCollapsed">
          <el-icon><Expand v-if="collapsed" /><Fold v-else /></el-icon>
        </button>

        <nav class="lf-crumb" aria-label="当前位置">
          <span>{{ activeGroup?.title || '态势' }}</span>
          <i>/</i>
          <b>{{ activeItem?.label || '运营总览' }}</b>
        </nav>

        <form class="lf-search" role="search" @submit.prevent="submitSearch">
          <el-icon class="lf-search-icon"><Search /></el-icon>
          <input v-model="searchText" type="search" placeholder="搜索 IP / 域名 / 哈希 / 进程 / 用户" aria-label="全局搜索" />
          <kbd>/</kbd>
        </form>

        <div class="lf-truth">
          <span class="lf-truth-item" :data-state="truth.components" :title="componentTitle">
            <i />
            组件 {{ componentShort }}
          </span>
          <span class="lf-truth-item" :data-state="agentState" :title="agentTitle">
            <i />
            Agent {{ agentShort }}
          </span>
          <span class="lf-truth-item" :data-state="timeState" :title="timeTitle">
            <i />
            时钟 {{ timeShort }}
          </span>
          <span class="lf-truth-fresh" :title="freshTitle">{{ freshShort }}</span>
        </div>

        <time class="lf-clock">{{ currentTime }}</time>

        <button class="lf-icon-btn" type="button" :title="theme === 'dark' ? '切换浅色主题' : '切换深色主题'" @click="toggleTheme">
          <el-icon><Sunny v-if="theme === 'dark'" /><Moon v-else /></el-icon>
        </button>

        <div class="lf-account">
          <span class="lf-avatar">{{ userInitial }}</span>
          <span class="lf-account-copy">
            <b>{{ authStore.user?.username || '管理员' }}</b>
            <small>{{ roleLabel }}</small>
          </span>
          <button class="lf-logout" type="button" @click="handleLogout">退出</button>
        </div>
      </header>

      <div v-if="truth.components === 'degraded' || truth.components === 'error'" class="lf-degraded" role="status">
        <el-icon><Warning /></el-icon>
        <span v-if="degradedComponents.length">
          <b>{{ degradedComponents.length }}</b> 个组件未就绪：
          <code v-for="name in degradedComponents" :key="name">{{ name }}</code>
          状态来自 <code>/api/v1/debug/components</code>
        </span>
        <span v-else>
          组件接口返回「{{ truth.components }}」，但未指出具体组件；请检查 <code>/api/v1/debug/components</code>。
        </span>
      </div>

      <main class="lf-main lf-scroll">
        <RouterView v-slot="{ Component, route }">
          <Transition name="lf-view" mode="out-in">
            <component :is="Component" :key="route.fullPath" />
          </Transition>
        </RouterView>
      </main>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import {
  Aim, Collection, Connection, Cpu, DataAnalysis, DataLine, Document,
  Expand, Fold, Lock, Menu, Monitor, Moon, Operation, Place, Search, Setting,
  Sunny, Warning,
} from '@element-plus/icons-vue'
import { opsClient, overviewClient } from '../../api/domain'
import { formatChinaTime, refreshPlatformTimeOffset } from '../../shared/time'
import { useAuthStore } from '../../stores/auth'
import { activeGroupForPath, visibleGroups } from './navigation'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

const collapsed = ref(false)
const navOpen = ref(false)
const searchText = ref('')
const currentTime = ref(formatChinaTime())
const theme = ref('light')

const truth = reactive({
  components: 'unknown',      // ok | degraded | error | unknown
  nonOk: [],
  agentsOnline: null,
  agentsTotal: null,
  timeSource: 'unknown',
  offsetMs: null,
  updatedAt: null,
  error: '',
})

let clockTimer = null
let truthTimer = null

const groups = computed(() => visibleGroups(authStore.user?.role || 'viewer'))
const activeGroup = computed(() => activeGroupForPath(route.path, groups.value))
const activeItem = computed(() => activeGroup.value?.items.find((item) => isActive(item.path)) || activeGroup.value?.items[0])
const userInitial = computed(() => String(authStore.user?.username || 'A').slice(0, 1).toUpperCase())
const roleLabel = computed(() => ({ admin: '管理员', analyst: '分析员', viewer: '只读' })[authStore.user?.role] || '管理员')

const iconMap = {
  '/dashboard': Monitor,
  '/incidents': Aim,
  '/events': Document,
  '/traffic-threats': DataLine,
  '/runtime': DataAnalysis,
  '/rasp': Lock,
  '/situation/global': Place,
  '/assets': Connection,
  '/response': Operation,
  '/evidence': Collection,
  '/data-quality': DataAnalysis,
  '/engines': Cpu,
  '/rules': Collection,
  '/control-center': Setting,
  '/install-config': Setting,
  '/users': Connection,
}

function iconFor(path) {
  return iconMap[path] || Monitor
}

function isActive(path) {
  return route.path === path || route.path.startsWith(`${path}/`)
}

const degradedComponents = computed(() => truth.nonOk || [])

const componentShort = computed(() => {
  if (truth.components === 'unknown') return '未知'
  if (truth.components === 'ok') return '正常'
  if (truth.components === 'error') return '不可用'
  if (!truth.nonOk.length) return '降级'
  return `${truth.nonOk.length} 异常`
})

const componentTitle = computed(() => {
  if (truth.components === 'unknown') return '未能读取组件健康接口，状态未知'
  if (truth.components === 'degraded') return `未就绪组件：${truth.nonOk.join('、')}`
  return '组件健康检查全部通过'
})

const agentState = computed(() => {
  if (truth.agentsOnline === null) return 'unknown'
  return truth.agentsOnline > 0 ? 'online' : 'degraded'
})

const agentShort = computed(() => {
  if (truth.agentsOnline === null) return '未知'
  return `${truth.agentsOnline}/${truth.agentsTotal ?? '?'}`
})

const agentTitle = computed(() => (
  truth.agentsOnline === null
    ? '未能读取 Agent 列表，在线数未知'
    : `在线 ${truth.agentsOnline} / 共 ${truth.agentsTotal} 台 Agent`
))

const timeState = computed(() => {
  if (truth.timeSource === 'unknown') return 'unknown'
  if (truth.timeSource === 'ntp' || truth.timeSource === 'system') return 'healthy'
  return 'degraded'
})

const timeShort = computed(() => {
  if (truth.timeSource === 'unknown') return '未知'
  const src = truth.timeSource === 'ntp' ? 'NTP' : truth.timeSource === 'manual' ? '手动' : truth.timeSource
  if (truth.offsetMs === null) return src
  const sec = Math.round(Number(truth.offsetMs) / 1000)
  return `${src} ${sec >= 0 ? '+' : ''}${sec}s`
})

const timeTitle = computed(() => (
  truth.timeSource === 'unknown'
    ? '未能读取系统时间接口'
    : `时间来源 ${truth.timeSource}，偏移 ${truth.offsetMs ?? '未知'} ms。手动时间源不会自动校准。`
))

const freshShort = computed(() => (
  truth.updatedAt ? `同步 ${truth.updatedAt}` : '状态未更新'
))

const freshTitle = computed(() => (
  truth.updatedAt ? `最近一次状态读取 ${truth.updatedAt}` : '尚未成功读取平台状态'
))

const truthLabel = computed(() => {
  if (truth.components === 'unknown') return '平台状态未知'
  if (truth.components === 'ok') return '组件全部正常'
  if (truth.components === 'error') return '组件不可用'
  if (!truth.nonOk.length) return '组件降级'
  return `${truth.nonOk.length} 个组件异常`
})

function applyTheme(next) {
  theme.value = next
  document.documentElement.dataset.theme = next
  try { localStorage.setItem('lyflow-theme', next) } catch { /* storage unavailable */ }
  window.dispatchEvent(new CustomEvent('lyflow-theme-changed', { detail: { theme: next } }))
}

function toggleTheme() {
  applyTheme(theme.value === 'dark' ? 'light' : 'dark')
}

function toggleCollapsed() {
  collapsed.value = !collapsed.value
  try { localStorage.setItem('lyflow-nav-collapsed', collapsed.value ? '1' : '0') } catch { /* ignore */ }
}

function submitSearch() {
  const query = searchText.value.trim()
  if (!query) return
  router.push({ path: '/events', query: { q: query } })
}

async function loadTruth() {
  const [components, agents, systemTime] = await Promise.allSettled([
    opsClient.components(),
    opsClient.agents({ limit: 200 }),
    opsClient.systemTime(),
  ])

  if (components.status === 'fulfilled' && components.value) {
    const payload = components.value
    const map = payload.components || {}
    const nonOk = Object.keys(map).filter((name) => (map[name]?.status || 'unknown') !== 'ok')
    truth.nonOk = nonOk
    truth.components = payload.status === 'ok' && nonOk.length === 0
      ? 'ok'
      : (payload.status === 'error' ? 'error' : 'degraded')
  } else {
    truth.components = 'unknown'
    truth.nonOk = []
  }

  if (agents.status === 'fulfilled') {
    const list = agents.value?.items || []
    truth.agentsTotal = list.length
    truth.agentsOnline = list.filter((agent) => String(agent.status || '').toLowerCase() === 'online').length
  } else {
    truth.agentsOnline = null
    truth.agentsTotal = null
  }

  if (systemTime.status === 'fulfilled' && systemTime.value) {
    truth.timeSource = String(systemTime.value.source || 'unknown')
    truth.offsetMs = systemTime.value.offset_ms ?? null
  } else {
    truth.timeSource = 'unknown'
    truth.offsetMs = null
  }

  truth.error = [components, agents, systemTime]
    .filter((item) => item.status === 'rejected')
    .map((item) => String(item.reason?.message || '读取失败'))
    .join('; ')
  truth.updatedAt = formatChinaTime()
}

async function handleLogout() {
  await authStore.logout()
  router.push('/login')
}

function onKeydown(event) {
  if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
    event.preventDefault()
    document.querySelector('.lf-search input')?.focus()
  }
}

onMounted(() => {
  let stored = 'dark'
  try {
    stored = localStorage.getItem('lyflow-theme') || 'dark'
    collapsed.value = localStorage.getItem('lyflow-nav-collapsed') === '1'
  } catch { /* ignore */ }
  applyTheme(stored === 'light' ? 'light' : 'dark')
  refreshPlatformTimeOffset(overviewClient.systemTime).catch(() => {})
  loadTruth()
  clockTimer = setInterval(() => { currentTime.value = formatChinaTime() }, 1000)
  truthTimer = setInterval(loadTruth, 45000)
  window.addEventListener('keydown', onKeydown)
})

onUnmounted(() => {
  if (clockTimer) clearInterval(clockTimer)
  if (truthTimer) clearInterval(truthTimer)
  window.removeEventListener('keydown', onKeydown)
})
</script>

<style scoped>
.lf-shell {
  display: grid;
  grid-template-columns: var(--lyf-rail-width) minmax(0, 1fr);
  width: 100%;
  height: 100vh;
  min-width: 0;
  background: var(--lyf-paper);
  color: var(--lyf-ink);
  transition: grid-template-columns var(--lyf-motion);
}

.lf-shell.is-collapsed { grid-template-columns: var(--lyf-rail-collapsed) minmax(0, 1fr); }

/* ---------------- rail ---------------- */

.lf-rail {
  display: flex;
  min-width: 0;
  flex-direction: column;
  overflow: hidden;
  background: var(--lyf-rail);
  border-right: 1px solid var(--lyf-rail-line);
}

.lf-brand {
  display: flex;
  height: 56px;
  flex: 0 0 56px;
  align-items: center;
  gap: 10px;
  padding: 0 16px;
  border-bottom: 1px solid var(--lyf-rail-line);
  color: var(--lyf-rail-text-strong);
  text-decoration: none;
  white-space: nowrap;
}

.lf-brand-mark {
  display: grid;
  width: 28px;
  height: 28px;
  flex: 0 0 28px;
  place-items: center;
  border: 1px solid var(--lyf-accent-line);
  border-radius: var(--lyf-radius-sm);
  color: var(--lyf-accent);
  background: rgb(47 211 190 / 8%);
}

.lf-brand-copy { min-width: 0; }
.lf-brand-copy strong { display: block; font-size: 14px; font-weight: 650; letter-spacing: 0.01em; }
.lf-brand-copy small {
  display: block;
  margin-top: 1px;
  color: #6f7b8a;
  font-family: var(--lyf-font-data);
  font-size: 9px;
  font-weight: 600;
  letter-spacing: 0.16em;
}

.lf-nav {
  flex: 1;
  overflow-x: hidden;
  overflow-y: auto;
  padding: 10px 8px 16px;
  scrollbar-width: thin;
  scrollbar-color: #2b333d transparent;
}

.lf-nav-group { margin-bottom: 14px; }

.lf-nav-group h2 {
  height: 22px;
  margin: 0;
  padding: 4px 9px;
  color: #5f6b7a;
  font-family: var(--lyf-font-data);
  font-size: 9.5px;
  font-weight: 600;
  letter-spacing: 0.16em;
  line-height: 14px;
  text-transform: uppercase;
  white-space: nowrap;
}

.lf-nav-item {
  position: relative;
  display: flex;
  height: 34px;
  align-items: center;
  gap: 10px;
  margin: 1px 0;
  padding: 0 9px;
  border-radius: var(--lyf-radius-sm);
  color: var(--lyf-rail-text);
  font-size: 12.5px;
  font-weight: 500;
  text-decoration: none;
  transition: color var(--lyf-motion-fast), background var(--lyf-motion-fast);
}

.lf-nav-item:hover { background: rgb(255 255 255 / 4.5%); color: var(--lyf-rail-text-strong); }

.lf-nav-item.active {
  background: linear-gradient(90deg, rgb(34 211 238 / 16%), rgb(34 211 238 / 4%));
  color: var(--lyf-accent);
  font-weight: 600;
  box-shadow: inset 0 0 18px -8px var(--lyf-accent), 0 0 14px -8px var(--lyf-accent);
}

.lf-nav-item.active::before {
  content: "";
  position: absolute;
  left: -8px;
  top: 7px;
  bottom: 7px;
  width: 2px;
  background: var(--lyf-accent);
}

.lf-nav-icon { flex: 0 0 16px; font-size: 16px; }
.lf-nav-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.lf-rail-foot {
  display: flex;
  height: 44px;
  flex: 0 0 44px;
  align-items: center;
  gap: 8px;
  padding: 0 17px;
  border-top: 1px solid var(--lyf-rail-line);
  color: #6f7b8a;
  font-size: 11px;
  white-space: nowrap;
}

.lf-rail-dot {
  width: 6px;
  height: 6px;
  flex: 0 0 6px;
  border-radius: 50%;
  background: #5f6b7a;
}

.lf-rail-dot[data-state='ok'] { background: #2fd3be; }
.lf-rail-dot[data-state='degraded'] { background: #e8c15c; }
.lf-rail-dot[data-state='error'] { background: #ff7a70; }
.lf-rail-dot[data-state='unknown'] { background: transparent; border: 1px solid #5f6b7a; }

.is-collapsed .lf-brand { padding: 0; justify-content: center; }
.is-collapsed .lf-brand-copy,
.is-collapsed .lf-nav-label,
.is-collapsed .lf-nav-group h2,
.is-collapsed .lf-rail-foot-copy { display: none; }
.is-collapsed .lf-nav-item { justify-content: center; padding: 0; }
.is-collapsed .lf-nav-item.active::before { left: -8px; }
.is-collapsed .lf-rail-foot { justify-content: center; padding: 0; }

/* ---------------- body ---------------- */

.lf-body {
  display: grid;
  min-width: 0;
  min-height: 0;
  grid-template-rows: var(--lyf-topbar-height) auto minmax(0, 1fr);
}

.lf-truthbar {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 12px;
  padding: 0 16px;
  border-bottom: var(--lyf-hairline);
  background: var(--lyf-surface);
}

.lf-icon-btn {
  display: grid;
  width: 30px;
  height: 30px;
  flex: 0 0 30px;
  place-items: center;
  border: 1px solid transparent;
  border-radius: var(--lyf-radius-sm);
  background: transparent;
  color: var(--lyf-ink-3);
  cursor: pointer;
}

.lf-icon-btn:hover { border-color: var(--lyf-line); background: var(--lyf-surface-2); color: var(--lyf-accent); }
.lf-nav-trigger { display: none; }

.lf-crumb {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 7px;
  color: var(--lyf-ink-3);
  font-size: 11.5px;
  white-space: nowrap;
}

.lf-crumb i { color: var(--lyf-line-2); font-style: normal; }
.lf-crumb b { color: var(--lyf-ink); font-weight: 600; }

.lf-search {
  position: relative;
  display: flex;
  width: min(280px, 22vw);
  min-width: 140px;
  align-items: center;
  margin-left: 4px;
}

.lf-search input {
  width: 100%;
  height: 30px;
  padding: 0 26px 0 28px;
  border: 1px solid var(--lyf-line);
  border-radius: var(--lyf-radius-sm);
  background: var(--lyf-surface-2);
  color: var(--lyf-ink);
  font: inherit;
  font-size: 11.5px;
  outline: 0;
  transition: border-color var(--lyf-motion-fast), background var(--lyf-motion-fast);
}

.lf-search input::placeholder { color: var(--lyf-ink-3); }
.lf-search input:focus { border-color: var(--lyf-accent); background: var(--lyf-surface); }

.lf-search-icon {
  position: absolute;
  left: 9px;
  color: var(--lyf-ink-3);
  font-size: 13px;
  pointer-events: none;
}

.lf-search kbd {
  position: absolute;
  right: 7px;
  padding: 0 4px;
  border: 1px solid var(--lyf-line);
  border-radius: 3px;
  color: var(--lyf-ink-3);
  font-family: var(--lyf-font-data);
  font-size: 9.5px;
  line-height: 15px;
}

.lf-truth {
  display: flex;
  align-items: center;
  gap: 4px;
  margin-left: auto;
}

.lf-truth-item {
  display: inline-flex;
  height: 24px;
  align-items: center;
  gap: 5px;
  padding: 0 7px;
  border: 1px solid transparent;
  border-radius: 3px;
  color: var(--lyf-ink-2);
  font-family: var(--lyf-font-data);
  font-size: 10px;
  font-weight: 500;
  white-space: nowrap;
}

.lf-truth-item i {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
}

.lf-truth-item[data-state='ok'],
.lf-truth-item[data-state='online'],
.lf-truth-item[data-state='healthy'] { color: var(--lyf-success); }
.lf-truth-item[data-state='degraded'] { color: var(--lyf-medium); }
.lf-truth-item[data-state='error'] { color: var(--lyf-critical); }
.lf-truth-item[data-state='unknown'] { color: var(--lyf-unknown); }
.lf-truth-item[data-state='unknown'] i { background: transparent; border: 1px solid currentColor; }

.lf-truth-fresh {
  color: var(--lyf-ink-3);
  font-family: var(--lyf-font-data);
  font-size: 10px;
  white-space: nowrap;
}

.lf-clock {
  color: var(--lyf-ink-3);
  font-family: var(--lyf-font-data);
  font-size: 11px;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.lf-account {
  display: flex;
  align-items: center;
  gap: 8px;
  padding-left: 8px;
  border-left: var(--lyf-hairline);
}

.lf-avatar {
  display: grid;
  width: 26px;
  height: 26px;
  place-items: center;
  border-radius: var(--lyf-radius-sm);
  background: var(--lyf-ink);
  color: var(--lyf-surface);
  font-size: 11px;
  font-weight: 700;
}

[data-theme='dark'] .lf-avatar { background: var(--lyf-accent); color: #06120f; }

.lf-account-copy { display: grid; gap: 0; line-height: 1.2; }
.lf-account-copy b { color: var(--lyf-ink); font-size: 11px; font-weight: 600; }
.lf-account-copy small { color: var(--lyf-ink-3); font-size: 10px; }

.lf-logout {
  height: 24px;
  padding: 0 7px;
  border: 1px solid var(--lyf-line);
  border-radius: 3px;
  background: transparent;
  color: var(--lyf-ink-3);
  font: inherit;
  font-size: 10.5px;
  cursor: pointer;
}

.lf-logout:hover { border-color: var(--lyf-critical-line); color: var(--lyf-critical); }

.lf-degraded {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 7px 16px;
  border-bottom: 1px solid var(--lyf-medium-line);
  background: var(--lyf-medium-soft);
  color: var(--lyf-medium);
  font-size: 11.5px;
}

.lf-degraded code {
  margin: 0 2px;
  padding: 1px 4px;
  border-radius: 3px;
  background: rgb(0 0 0 / 5%);
  font-family: var(--lyf-font-data);
  font-size: 10.5px;
}

.lf-main {
  min-width: 0;
  min-height: 0;
  padding: 20px;
  overflow: auto;
  background:
    radial-gradient(120% 80% at 78% -20%, rgb(34 211 238 / 8%), transparent 52%),
    radial-gradient(90% 70% at 6% 0%, rgb(56 189 248 / 5%), transparent 46%),
    linear-gradient(rgb(34 211 238 / 3.5%) 1px, transparent 1px),
    linear-gradient(90deg, rgb(34 211 238 / 3.5%) 1px, transparent 1px),
    var(--lyf-paper);
  background-size: auto, auto, 44px 44px, 44px 44px, auto;
}

.lf-main > * { min-width: 0; }

.lf-scroll {
  overflow: auto;
  scrollbar-width: thin;
  scrollbar-color: var(--lyf-line-2) transparent;
}

.lf-scroll::-webkit-scrollbar { width: 9px; height: 9px; }
.lf-scroll::-webkit-scrollbar-thumb { border-radius: 8px; background: var(--lyf-line-2); }
.lf-scroll::-webkit-scrollbar-track { background: transparent; }

.lf-view-enter-active,
.lf-view-leave-active { transition: opacity 0.14s ease; }
.lf-view-enter-from,
.lf-view-leave-to { opacity: 0; }

.lf-scrim { display: none; }

/* ---------------- responsive ---------------- */

@media (max-width: 1240px) {
  .lf-search { display: none; }
  .lf-truth-fresh { display: none; }
}

@media (max-width: 1080px) {
  .lf-truth-item[data-state] { font-size: 0; gap: 0; padding: 0 5px; }
  .lf-truth-item[data-state] i { width: 6px; height: 6px; }
  .lf-clock { display: none; }
}

@media (max-width: 900px) {
  .lf-shell,
  .lf-shell.is-collapsed { grid-template-columns: minmax(0, 1fr); }

  .lf-rail {
    position: fixed;
    z-index: 30;
    inset: 0 auto 0 0;
    width: var(--lyf-rail-width);
    transform: translateX(-100%);
    transition: transform var(--lyf-motion);
  }

  .is-nav-open .lf-rail { transform: translateX(0); }

  .lf-scrim {
    position: fixed;
    z-index: 25;
    inset: 0;
    display: block;
    border: 0;
    background: rgb(10 13 16 / 45%);
  }

  .lf-nav-trigger { display: grid; }
  .lf-collapse { display: none; }
  .lf-main { padding: 12px; }
  .lf-truth { display: none; }
  .lf-account-copy { display: none; }
}

@media (max-width: 620px) {
  .lf-crumb { display: none; }
  .lf-logout { display: none; }
  .lf-main { padding: 10px; }
}
</style>
