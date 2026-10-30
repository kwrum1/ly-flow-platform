<template>
  <div class="v-shell" :class="{ 'is-collapsed': collapsed, 'nav-open': navOpen }">
    <button v-if="navOpen" class="v-scrim nav" type="button" aria-label="关闭导航" @click="navOpen = false" />

    <aside class="v-rail" aria-label="主导航">
      <RouterLink class="v-brand" to="/overview" aria-label="流影安全首页" @click="navOpen = false">
        <span class="v-brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8">
            <path d="M12 3 19.5 6v5.6c0 4.2-3.1 7-7.5 8.4-4.4-1.4-7.5-4.2-7.5-8.4V6L12 3Z" />
            <path d="M8.8 12.1l2.2 2.2 4.2-4.3" />
          </svg>
        </span>
        <span class="v-brand-copy">
          <strong>流影安全</strong>
          <small>LYFLOW XDR</small>
        </span>
      </RouterLink>

      <nav class="v-nav">
        <section v-for="group in groups" :key="group.title" class="v-nav-group">
          <h2>{{ group.title }}</h2>
          <RouterLink
            v-for="item in group.items"
            :key="item.path"
            :to="item.path"
            class="v-nav-item"
            :class="{ active: isActive(item.path) }"
            :title="collapsed ? item.label : item.description"
            @click="navOpen = false"
          >
            <el-icon><component :is="iconFor(item.path)" /></el-icon>
            <span class="v-nav-label">{{ item.label }}</span>
          </RouterLink>
        </section>
      </nav>

      <div class="v-rail-foot">
        <span class="v-state" :data-state="truth.components === 'ok' ? 'healthy' : truth.components === 'unknown' ? 'unknown' : truth.components === 'error' ? 'failed' : 'degraded'" />
        <span v-if="!collapsed">{{ footLabel }}</span>
      </div>
    </aside>

    <div class="v-body">
      <header class="v-header">
        <button class="v-icon-btn nav-trigger" type="button" aria-label="打开导航" @click="navOpen = true">
          <el-icon><Menu /></el-icon>
        </button>
        <button class="v-icon-btn collapse-trigger" type="button" :aria-label="collapsed ? '展开导航' : '收起导航'" @click="toggleCollapsed">
          <el-icon><Expand v-if="collapsed" /><Fold v-else /></el-icon>
        </button>

        <nav class="v-crumb" aria-label="当前位置">
          <span>{{ activeGroup?.title || '态势' }}</span>
          <span class="v-dim">/</span>
          <b>{{ activeItem?.label || '态势总览' }}</b>
        </nav>

        <form class="v-search" role="search" @submit.prevent="submitSearch">
          <el-icon><Search /></el-icon>
          <input v-model="searchText" type="search" placeholder="搜索 IP / 域名 / 哈希 / 进程" aria-label="全局搜索" />
        </form>

        <div class="v-truth">
          <span class="v-truth-item" :data-state="truth.components" :title="componentTitle">
            <i />组件 {{ componentShort }}
          </span>
          <span class="v-truth-item" :data-state="agentState" :title="agentTitle">
            <i />Agent {{ agentShort }}
          </span>
          <span class="v-truth-item" :data-state="timeState" :title="timeTitle">
            <i />时钟 {{ timeShort }}
          </span>
        </div>

        <time class="v-clock">{{ currentTime }}</time>

        <button class="v-icon-btn" type="button" :title="theme === 'dark' ? '切换浅色' : '切换深色'" @click="toggleTheme">
          <el-icon><Sunny v-if="theme === 'dark'" /><Moon v-else /></el-icon>
        </button>

        <div class="v-account">
          <span class="v-avatar">{{ userInitial }}</span>
          <span class="v-account-copy">
            <b>{{ authStore.user?.username || '管理员' }}</b>
            <small>{{ roleLabel }}</small>
          </span>
          <button class="v-logout" type="button" @click="handleLogout">退出</button>
        </div>
      </header>

      <main class="v-main v-scroll">
        <div v-if="degradedComponents.length || truth.components === 'error'" class="v-banner" role="status">
          <el-icon><Warning /></el-icon>
          <span v-if="degradedComponents.length">
            <b>{{ degradedComponents.length }}</b> 个组件未就绪：
            <code v-for="name in degradedComponents" :key="name">{{ name }}</code>
          </span>
          <span v-else>组件接口返回「{{ truth.components }}」，但未指出具体组件。</span>
        </div>

        <RouterView v-slot="{ Component, route }">
          <Transition name="v-fade" mode="out-in">
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
  Aim, Bell, Collection, Cpu, DataAnalysis, Document, Expand, Fold, Menu,
  Monitor, Moon, Search, Setting, Sunny, TrendCharts, Warning,
} from '@element-plus/icons-vue'
import { opsClient, overviewClient } from '../../api/domain'
import { formatChinaTime, refreshPlatformTimeOffset } from '../../shared/time'
import { useAuthStore } from '../../stores/auth'
import { V4_NAVIGATION } from '../navigation'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

const collapsed = ref(false)
const navOpen = ref(false)
const searchText = ref('')
const currentTime = ref(formatChinaTime())
const theme = ref('light')

const truth = reactive({
  components: 'unknown',
  nonOk: [],
  agentsOnline: null,
  agentsTotal: null,
  timeSource: 'unknown',
  offsetMs: null,
})

let clockTimer = null
let truthTimer = null

const groups = computed(() => V4_NAVIGATION)
const activeGroup = computed(() => groups.value.find((g) => g.items.some((i) => isActive(i.path))) || groups.value[0])
const activeItem = computed(() => activeGroup.value?.items.find((i) => isActive(i.path)) || activeGroup.value?.items[0])
const userInitial = computed(() => String(authStore.user?.username || 'A').slice(0, 1).toUpperCase())
const roleLabel = computed(() => ({ admin: '管理员', analyst: '分析员', viewer: '只读' })[authStore.user?.role] || '管理员')

const iconMap = {
  '/overview': Monitor,
  '/incidents': Aim,
  '/events': Document,
  '/threats': DataAnalysis,
  '/assets': Cpu,
  '/health': TrendCharts,
  '/rules': Collection,
  '/settings': Setting,
}

const iconFor = (path) => iconMap[path] || Bell

function isActive(path) {
  return route.path === path || route.path.startsWith(`${path}/`)
}

const degradedComponents = computed(() => truth.nonOk || [])

const componentShort = computed(() => {
  if (truth.components === 'unknown') return '未知'
  if (truth.components === 'ok') return '正常'
  if (truth.components === 'error') return '不可用'
  return truth.nonOk.length ? `${truth.nonOk.length} 异常` : '降级'
})

const componentTitle = computed(() => (
  truth.components === 'unknown'
    ? '未能读取组件健康接口，状态未知'
    : truth.components === 'degraded'
      ? `未就绪组件：${truth.nonOk.join('、') || '接口报告降级'}`
      : '组件健康检查全部通过'
))

const agentState = computed(() => (truth.agentsOnline === null ? 'unknown' : truth.agentsOnline > 0 ? 'online' : 'degraded'))
const agentShort = computed(() => (truth.agentsOnline === null ? '未知' : `${truth.agentsOnline}/${truth.agentsTotal ?? '?'}`))
const agentTitle = computed(() => (truth.agentsOnline === null ? '未能读取 Agent 列表' : `在线 ${truth.agentsOnline} / 共 ${truth.agentsTotal} 台 Agent`))

const timeState = computed(() => {
  if (truth.timeSource === 'unknown') return 'unknown'
  return truth.timeSource === 'ntp' || truth.timeSource === 'system' ? 'healthy' : 'degraded'
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

const footLabel = computed(() => {
  if (truth.components === 'unknown') return '平台状态未知'
  if (truth.components === 'ok') return '组件全部正常'
  if (truth.components === 'error') return '组件不可用'
  return truth.nonOk.length ? `${truth.nonOk.length} 个组件异常` : '组件降级'
})

function applyTheme(next) {
  theme.value = next
  document.documentElement.dataset.theme = next
  try { localStorage.setItem('lyflow-theme', next) } catch { /* ignore */ }
}

function toggleTheme() {
  applyTheme(theme.value === 'dark' ? 'light' : 'dark')
}

function toggleCollapsed() {
  collapsed.value = !collapsed.value
  try { localStorage.setItem('lyflow-nav-collapsed', collapsed.value ? '1' : '0') } catch { /* ignore */ }
}

function submitSearch() {
  const q = searchText.value.trim()
  if (!q) return
  router.push({ path: '/events', query: { q } })
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
    truth.components = payload.status === 'ok' && nonOk.length === 0 ? 'ok' : payload.status === 'error' ? 'error' : 'degraded'
  } else {
    truth.components = 'unknown'
    truth.nonOk = []
  }

  if (agents.status === 'fulfilled') {
    const list = agents.value?.items || []
    truth.agentsTotal = list.length
    truth.agentsOnline = list.filter((a) => String(a.status || '').toLowerCase() === 'online').length
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
}

async function handleLogout() {
  await authStore.logout()
  router.push('/login')
}

onMounted(() => {
  let stored = 'light'
  try {
    stored = localStorage.getItem('lyflow-theme') || 'light'
    collapsed.value = localStorage.getItem('lyflow-nav-collapsed') === '1'
  } catch { /* ignore */ }
  applyTheme(stored === 'dark' ? 'dark' : 'light')
  refreshPlatformTimeOffset(overviewClient.systemTime).catch(() => {})
  loadTruth()
  clockTimer = setInterval(() => { currentTime.value = formatChinaTime() }, 1000)
  truthTimer = setInterval(loadTruth, 45000)
})

onUnmounted(() => {
  if (clockTimer) clearInterval(clockTimer)
  if (truthTimer) clearInterval(truthTimer)
})
</script>
