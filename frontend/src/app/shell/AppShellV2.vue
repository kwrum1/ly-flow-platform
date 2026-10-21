<template>
  <div class="sx-shell">
    <header class="sx-topbar">
      <RouterLink class="sx-brand" to="/dashboard" aria-label="流影安全态势感知首页">
        <span class="sx-brand-mark"><XdrLogo :size="28" /></span>
        <span class="sx-brand-copy">
          <strong>流影安全</strong>
          <small>LYFLOW · SITUATION AWARENESS</small>
        </span>
      </RouterLink>

      <nav class="sx-groups" aria-label="主导航">
        <RouterLink
          v-for="group in groups"
          :key="group.title"
          :to="group.items[0].path"
          class="sx-group-link"
          :class="{ active: activeGroup && activeGroup.title === group.title }"
        >
          {{ group.title }}
        </RouterLink>
      </nav>

      <div class="sx-topbar-spacer" />

      <form class="sx-global-search" role="search" @submit.prevent="submitSearch">
        <span class="sx-search-icon" aria-hidden="true">⌕</span>
        <input v-model="searchText" type="search" placeholder="搜索 IP / 域名 / 哈希 / 进程 / 用户" aria-label="全局搜索" />
        <kbd>/</kbd>
      </form>

      <div class="sx-topbar-status">
        <span class="sx-status-chip" :class="{ offline: !platformOnline }">
          <i />
          {{ platformOnline ? '平台在线' : '连接中断' }}
        </span>
        <time class="sx-clock">{{ currentTime }}</time>
      </div>

      <button class="sx-theme-btn" type="button" :title="theme === 'dark' ? '切换浅色主题' : '切换深色主题'" :aria-label="theme === 'dark' ? '切换浅色主题' : '切换深色主题'" @click="toggleTheme">
        <el-icon v-if="theme === 'dark'"><Sunny /></el-icon>
        <el-icon v-else><Moon /></el-icon>
      </button>

      <div class="sx-account">
        <span class="sx-avatar">{{ userInitial }}</span>
        <span class="sx-account-copy">
          <b>{{ authStore.user?.username || '管理员' }}</b>
          <small>{{ roleLabel }}</small>
        </span>
        <button class="sx-logout" type="button" @click="handleLogout">退出</button>
      </div>
    </header>

    <div class="sx-subbar">
      <div class="sx-breadcrumb">
        <span>{{ activeGroup?.title || '态势' }}</span>
        <i>/</i>
        <b>{{ activeItem?.label || '态势总览' }}</b>
      </div>
      <nav v-if="activeGroup" class="sx-tabs" aria-label="二级导航">
        <RouterLink
          v-for="item in activeGroup.items"
          :key="item.path"
          :to="item.path"
          class="sx-tab"
          :class="{ active: isActive(item.path) }"
        >
          {{ item.label }}
        </RouterLink>
      </nav>
      <div class="sx-subbar-meta">
        <span>数据实时同步</span>
        <i class="sx-live"><em />LIVE</i>
      </div>
    </div>

    <main class="sx-main sx-scroll">
      <RouterView v-slot="{ Component, route }">
        <Transition name="sx-view" mode="out-in">
          <component :is="Component" :key="route.fullPath" />
        </Transition>
      </RouterView>
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import { Moon, Sunny } from '@element-plus/icons-vue'
import { overviewClient } from '../../api/domain'
import XdrLogo from '../../components/XdrLogo.vue'
import { formatChinaTime, refreshPlatformTimeOffset } from '../../shared/time'
import { useAuthStore } from '../../stores/auth'
import { activeGroupForPath, visibleGroups } from './navigation'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()
const searchText = ref('')
const currentTime = ref(formatChinaTime())
const platformOnline = ref(true)
const theme = ref('light')
let clockTimer = null
let healthTimer = null

const groups = computed(() => visibleGroups(authStore.user?.role || 'viewer'))
const activeGroup = computed(() => activeGroupForPath(route.path, groups.value))
const activeItem = computed(() => activeGroup.value?.items.find((item) => isActive(item.path)) || activeGroup.value?.items[0])
const userInitial = computed(() => String(authStore.user?.username || 'A').slice(0, 1).toUpperCase())
const roleLabel = computed(() => ({ admin: '管理员', analyst: '分析员', viewer: '只读' })[authStore.user?.role] || '管理员')

function isActive(path) {
  return route.path === path || route.path.startsWith(`${path}/`)
}

function submitSearch() {
  const query = searchText.value.trim()
  if (!query) return
  router.push({ path: '/events', query: { q: query } })
}

function applyTheme(next) {
  theme.value = next
  document.documentElement.dataset.theme = next
  try { localStorage.setItem('lyflow-theme', next) } catch { /* storage may be unavailable */ }
  window.dispatchEvent(new CustomEvent('lyflow-theme-changed', { detail: { theme: next } }))
}

function toggleTheme() {
  applyTheme(theme.value === 'dark' ? 'light' : 'dark')
}

async function refreshHealth() {
  try {
    const result = await overviewClient.health()
    platformOnline.value = Boolean(result)
  } catch {
    platformOnline.value = false
  }
}

async function handleLogout() {
  await authStore.logout()
  router.push('/login')
}

function onKeydown(event) {
  if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
    event.preventDefault()
    document.querySelector('.sx-global-search input')?.focus()
  }
}

onMounted(() => {
  let stored = 'light'
  try { stored = localStorage.getItem('lyflow-theme') || 'light' } catch { /* ignore */ }
  applyTheme(stored === 'dark' ? 'dark' : 'light')
  refreshPlatformTimeOffset(overviewClient.systemTime).catch(() => {})
  refreshHealth()
  clockTimer = setInterval(() => { currentTime.value = formatChinaTime() }, 1000)
  healthTimer = setInterval(refreshHealth, 30000)
  window.addEventListener('keydown', onKeydown)
})

onUnmounted(() => {
  if (clockTimer) clearInterval(clockTimer)
  if (healthTimer) clearInterval(healthTimer)
  window.removeEventListener('keydown', onKeydown)
})
</script>

<style scoped>
.sx-shell {
  display: grid;
  width: 100%;
  height: 100vh;
  min-width: 0;
  grid-template-rows: var(--sx-header-height) var(--sx-tabs-height) minmax(0, 1fr);
  background: var(--sx-canvas);
  color: var(--sx-text);
}

.sx-topbar {
  position: relative;
  z-index: 20;
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 18px;
  padding: 0 18px;
  background:
    radial-gradient(circle at 16% -80%, rgb(43 153 255 / 30%), transparent 42%),
    linear-gradient(100deg, #081a2c 0%, #0b243c 55%, #0a1f33 100%);
  box-shadow: 0 1px 0 rgb(255 255 255 / 4%) inset, 0 8px 22px -16px rgb(0 0 0 / 55%);
  color: #e8f3ff;
}

.sx-brand {
  display: flex;
  min-width: 188px;
  align-items: center;
  gap: 10px;
  color: #f3f9ff;
  text-decoration: none;
}

.sx-brand-mark {
  display: grid;
  width: 34px;
  height: 34px;
  place-items: center;
  border: 1px solid rgb(86 188 255 / 28%);
  border-radius: 9px;
  background: linear-gradient(145deg, rgb(22 92 150 / 55%), rgb(7 34 57 / 30%));
  box-shadow: 0 0 20px -8px rgb(50 190 255 / 65%);
}

.sx-brand-copy strong,
.sx-brand-copy small {
  display: block;
  line-height: 1.15;
}

.sx-brand-copy strong {
  font-size: 15px;
  font-weight: 760;
  letter-spacing: 0.02em;
}

.sx-brand-copy small {
  margin-top: 2px;
  color: #7e9cb8;
  font-size: 12px;
  font-weight: 650;
  letter-spacing: 0.13em;
}

.sx-groups {
  display: flex;
  height: 100%;
  align-items: stretch;
  gap: 2px;
}

.sx-group-link {
  position: relative;
  display: flex;
  align-items: center;
  padding: 0 13px;
  color: #a9c1d8;
  font-size: 13px;
  font-weight: 620;
  text-decoration: none;
  white-space: nowrap;
  transition: color var(--transition-fast), background var(--transition-fast);
}

.sx-group-link::after {
  content: "";
  position: absolute;
  right: 13px;
  bottom: 0;
  left: 13px;
  height: 2px;
  border-radius: 2px 2px 0 0;
  background: transparent;
  transition: background var(--transition-fast), box-shadow var(--transition-fast);
}

.sx-group-link:hover {
  color: #eaf6ff;
  background: rgb(255 255 255 / 3.5%);
}

.sx-group-link.active {
  color: #fff;
}

.sx-group-link.active::after {
  background: linear-gradient(90deg, #36b5ff, #31e0c1);
  box-shadow: 0 0 14px rgb(54 181 255 / 75%);
}

.sx-topbar-spacer {
  flex: 1;
}

.sx-global-search {
  position: relative;
  display: flex;
  width: min(300px, 25vw);
  min-width: 160px;
  align-items: center;
}

.sx-global-search input {
  width: 100%;
  height: 32px;
  padding: 0 30px 0 30px;
  border: 1px solid rgb(126 170 206 / 22%);
  border-radius: 7px;
  background: rgb(3 19 34 / 42%);
  color: #e7f4ff;
  font: inherit;
  font-size: 11px;
  outline: 0;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast), background var(--transition-fast);
}

.sx-global-search input::placeholder {
  color: #7190ad;
}

.sx-global-search input:focus {
  border-color: rgb(66 186 255 / 65%);
  background: rgb(3 19 34 / 66%);
  box-shadow: 0 0 0 3px rgb(32 143 225 / 14%);
}

.sx-search-icon {
  position: absolute;
  left: 10px;
  color: #6f92b1;
  font-size: 15px;
  line-height: 1;
  pointer-events: none;
}

.sx-global-search kbd {
  position: absolute;
  right: 8px;
  padding: 1px 4px;
  border: 1px solid rgb(126 170 206 / 22%);
  border-radius: 3px;
  color: #6f92b1;
  font: inherit;
  font-size: 11px;
  line-height: 1.2;
}

.sx-topbar-status {
  display: flex;
  align-items: center;
  gap: 12px;
  white-space: nowrap;
}

.sx-status-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-height: 23px;
  padding: 2px 8px;
  border: 1px solid rgb(55 211 155 / 22%);
  border-radius: 5px;
  background: rgb(27 133 98 / 11%);
  color: #8fe6c3;
  font-size: 12px;
  font-weight: 650;
}

.sx-status-chip i {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #35d39b;
  box-shadow: 0 0 0 3px rgb(53 211 155 / 13%);
  animation: sx-pulse 1.8s infinite;
}

.sx-status-chip.offline {
  border-color: rgb(255 111 97 / 26%);
  background: rgb(190 48 38 / 12%);
  color: #ffb5ae;
}

.sx-status-chip.offline i {
  background: #ff6b61;
  box-shadow: 0 0 0 3px rgb(255 107 97 / 13%);
}

.sx-clock {
  color: #8fa9c1;
  font-size: 11px;
  font-variant-numeric: tabular-nums;
}

.sx-theme-btn {
  display: grid;
  width: 30px;
  height: 30px;
  place-items: center;
  border: 1px solid rgb(126 170 206 / 20%);
  border-radius: 7px;
  background: rgb(255 255 255 / 4%);
  color: #a6c4dd;
  cursor: pointer;
  transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
}

.sx-theme-btn:hover {
  border-color: rgb(89 191 255 / 48%);
  background: rgb(49 154 233 / 13%);
  color: #dff4ff;
}

.sx-account {
  display: flex;
  align-items: center;
  gap: 8px;
  padding-left: 4px;
}

.sx-avatar {
  display: grid;
  width: 27px;
  height: 27px;
  place-items: center;
  border: 1px solid rgb(112 195 255 / 32%);
  border-radius: 50%;
  background: linear-gradient(145deg, rgb(36 120 184 / 70%), rgb(12 65 103 / 70%));
  color: #e7f8ff;
  font-size: 11px;
  font-weight: 750;
}

.sx-account-copy {
  display: grid;
  gap: 1px;
  line-height: 1.15;
}

.sx-account-copy b {
  color: #eaf6ff;
  font-size: 11px;
  font-weight: 650;
}

.sx-account-copy small {
  color: #7e9cb8;
  font-size: 11px;
}

.sx-logout {
  height: 25px;
  padding: 0 8px;
  border: 1px solid rgb(126 170 206 / 20%);
  border-radius: 5px;
  background: transparent;
  color: #8fa9c1;
  font: inherit;
  font-size: 12px;
  cursor: pointer;
}

.sx-logout:hover {
  border-color: rgb(255 111 97 / 40%);
  color: #ffb5ae;
}

.sx-subbar {
  position: relative;
  z-index: 15;
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 18px;
  padding: 0 20px;
  border-bottom: 1px solid var(--sx-line);
  background: color-mix(in srgb, var(--sx-surface) 92%, transparent);
  box-shadow: 0 4px 14px -14px rgb(15 35 58 / 38%);
  backdrop-filter: blur(14px);
}

.sx-breadcrumb {
  display: flex;
  min-width: 110px;
  align-items: center;
  gap: 7px;
  color: var(--sx-text-3);
  font-size: 12px;
  white-space: nowrap;
}

.sx-breadcrumb i {
  color: var(--sx-line);
  font-style: normal;
}

.sx-breadcrumb b {
  color: var(--sx-text);
  font-weight: 650;
}

.sx-tabs {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 3px;
  overflow-x: auto;
  scrollbar-width: none;
}

.sx-tabs::-webkit-scrollbar { display: none; }

.sx-tab {
  display: flex;
  height: 30px;
  align-items: center;
  padding: 0 10px;
  border: 1px solid transparent;
  border-radius: 6px;
  color: var(--sx-text-2);
  font-size: 11px;
  font-weight: 600;
  text-decoration: none;
  white-space: nowrap;
  transition: color var(--transition-fast), background var(--transition-fast), border-color var(--transition-fast);
}

.sx-tab:hover {
  background: var(--sx-surface-3);
  color: var(--sx-accent);
}

.sx-tab.active {
  border-color: var(--sx-accent-line);
  background: var(--sx-accent-soft);
  color: var(--sx-accent);
  font-weight: 700;
}

.sx-subbar-meta {
  display: flex;
  margin-left: auto;
  align-items: center;
  gap: 12px;
  color: var(--sx-text-3);
  font-size: 12px;
  white-space: nowrap;
}

.sx-subbar-meta .sx-live em {
  display: inline-block;
  width: 5px;
  height: 5px;
  margin-right: 4px;
  border-radius: 50%;
  background: var(--sx-success);
  animation: sx-pulse 1.8s infinite;
}

.sx-main {
  min-width: 0;
  min-height: 0;
  padding: var(--sx-page-pad);
  background:
    radial-gradient(circle at 88% -10%, rgb(11 107 203 / 7%), transparent 32%),
    radial-gradient(circle at 8% 0%, rgb(10 157 187 / 5%), transparent 26%),
    var(--sx-canvas);
}

.sx-main > * {
  min-width: 0;
}

.sx-view-enter-active,
.sx-view-leave-active {
  transition: opacity 0.16s ease, transform 0.16s ease;
}

.sx-view-enter-from {
  opacity: 0;
  transform: translateY(4px);
}

.sx-view-leave-to {
  opacity: 0;
  transform: translateY(-2px);
}

@media (max-width: 1180px) {
  .sx-brand { min-width: 150px; }
  .sx-brand-copy small { display: none; }
  .sx-global-search { width: 210px; }
  .sx-subbar-meta { display: none; }
}

@media (max-width: 900px) {
  .sx-topbar { gap: 10px; padding: 0 10px; }
  .sx-brand { min-width: 0; }
  .sx-brand-copy { display: none; }
  .sx-groups { overflow-x: auto; scrollbar-width: none; }
  .sx-groups::-webkit-scrollbar { display: none; }
  .sx-group-link { padding: 0 9px; font-size: 12px; }
  .sx-global-search { display: none; }
  .sx-clock,
  .sx-account-copy { display: none; }
  .sx-subbar { gap: 10px; padding: 0 10px; }
  .sx-breadcrumb { display: none; }
  .sx-tabs { flex: 1; }
}

@media (max-width: 620px) {
  .sx-status-chip { display: none; }
  .sx-logout { display: none; }
  .sx-main { padding: 10px; }
}
</style>
