<template>
  <div class="ly2-shell">
    <header class="ly2-topnav">
      <RouterLink class="ly2-brand" to="/dashboard" aria-label="流影首页">
        <XdrLogo :size="30" />
        <span class="ly2-brand-copy">
          <strong>流影安全</strong>
          <small>态势感知平台</small>
        </span>
      </RouterLink>

      <nav class="ly2-menu" aria-label="一级导航">
        <RouterLink
          v-for="group in groups"
          :key="group.title"
          :to="group.items[0].path"
          class="ly2-menu-item"
          :class="{ active: activeGroup && group.title === activeGroup.title }"
        >
          {{ group.title }}
        </RouterLink>
      </nav>

      <form class="ly2-search" role="search" @submit.prevent="submitSearch">
        <input v-model="searchText" type="search" placeholder="搜索 IP、域名、哈希、进程" aria-label="统一搜索" />
      </form>

      <div class="ly2-actions">
        <span class="ly2-clock">{{ currentTime }}</span>
        <span class="ly2-user">{{ userInitial }}</span>
        <button class="ly2-logout" type="button" @click="handleLogout">退出</button>
      </div>
    </header>

    <nav v-if="activeGroup" class="ly2-tabs" aria-label="二级导航">
      <RouterLink
        v-for="item in activeGroup.items"
        :key="item.path"
        :to="item.path"
        class="ly2-tab"
        :class="{ active: isActive(item.path) }"
      >
        {{ item.label }}
      </RouterLink>
    </nav>

    <main class="ly2-content">
      <RouterView v-slot="{ Component, route }">
        <component :is="Component" :key="route.fullPath" />
      </RouterView>
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
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
let timer = null

const groups = computed(() => visibleGroups(authStore.user?.role || 'viewer'))
const activeGroup = computed(() => activeGroupForPath(route.path, groups.value))
const userInitial = computed(() => String(authStore.user?.username || 'A').slice(0, 1).toUpperCase())

function isActive(path) {
  return route.path === path || route.path.startsWith(`${path}/`)
}

function submitSearch() {
  const query = searchText.value.trim()
  if (!query) return
  router.push({ path: '/events', query: { q: query } })
}

async function handleLogout() {
  await authStore.logout()
  router.push('/login')
}

onMounted(() => {
  refreshPlatformTimeOffset(overviewClient.systemTime).catch(() => {})
  timer = setInterval(() => { currentTime.value = formatChinaTime() }, 1000)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
.ly2-shell {
  display: flex;
  min-height: 100vh;
  flex-direction: column;
  background: #f3f6fb;
  color: #1f2a37;
}
.ly2-topnav {
  position: sticky;
  top: 0;
  z-index: 20;
  display: flex;
  height: 50px;
  flex: 0 0 50px;
  align-items: center;
  gap: 18px;
  padding: 0 16px;
  border-bottom: 1px solid #d8e1ec;
  background: #fff;
}
.ly2-brand {
  display: flex;
  min-width: 150px;
  align-items: center;
  gap: 8px;
  color: #172b4d;
  text-decoration: none;
}
.ly2-brand-copy strong,
.ly2-brand-copy small {
  display: block;
  line-height: 1.15;
}
.ly2-brand-copy strong { font-size: 15px; }
.ly2-brand-copy small { color: #7b8798; font-size: 10px; }
.ly2-menu {
  display: flex;
  height: 50px;
  align-items: stretch;
  gap: 2px;
  overflow-x: auto;
}
.ly2-menu-item {
  display: flex;
  height: 50px;
  align-items: center;
  padding: 0 14px;
  color: #475467;
  font-size: 14px;
  text-decoration: none;
  white-space: nowrap;
  border-bottom: 2px solid transparent;
}
.ly2-menu-item:hover { color: #1769ba; }
.ly2-menu-item.active {
  color: #1268bd;
  font-weight: 600;
  border-bottom-color: #1976d2;
}
.ly2-search {
  flex: 1;
  min-width: 140px;
  max-width: 420px;
  margin-left: auto;
}
.ly2-search input {
  width: 100%;
  height: 32px;
  padding: 0 12px;
  border: 1px solid #d8e1ec;
  border-radius: 6px;
  background: #f7faff;
  color: #1f2a37;
  font-size: 12px;
  outline: none;
}
.ly2-search input:focus { border-color: #1976d2; box-shadow: 0 0 0 2px #e8f3ff; }
.ly2-actions {
  display: flex;
  align-items: center;
  gap: 12px;
  white-space: nowrap;
}
.ly2-clock { color: #667085; font-size: 12px; font-variant-numeric: tabular-nums; }
.ly2-user {
  display: grid;
  width: 28px;
  height: 28px;
  place-items: center;
  border-radius: 50%;
  background: #e8f3ff;
  color: #1268bd;
  font-size: 12px;
  font-weight: 600;
}
.ly2-logout {
  height: 28px;
  padding: 0 10px;
  border: 1px solid #d8e1ec;
  border-radius: 6px;
  background: #fff;
  color: #475467;
  font-size: 12px;
  cursor: pointer;
}
.ly2-logout:hover { border-color: #1976d2; color: #1268bd; }
.ly2-tabs {
  position: sticky;
  top: 50px;
  z-index: 19;
  display: flex;
  height: 45px;
  flex: 0 0 45px;
  align-items: center;
  gap: 4px;
  padding: 0 20px;
  overflow-x: auto;
  border-bottom: 1px solid #e6ebf1;
  background: #fff;
}
.ly2-tab {
  display: flex;
  height: 30px;
  align-items: center;
  padding: 0 12px;
  border-radius: 5px;
  color: #475467;
  font-size: 13px;
  text-decoration: none;
  white-space: nowrap;
}
.ly2-tab:hover { background: #f1f6fc; color: #1769ba; }
.ly2-tab.active { background: #e8f3ff; color: #1268bd; font-weight: 600; }
.ly2-content {
  flex: 1;
  min-width: 0;
  padding: 20px;
}
@media (max-width: 900px) {
  .ly2-brand-copy small { display: none; }
  .ly2-clock { display: none; }
  .ly2-search { max-width: 220px; }
}
@media (max-width: 640px) {
  .ly2-topnav { gap: 10px; padding: 0 10px; }
  .ly2-brand { min-width: 0; }
  .ly2-menu-item { padding: 0 10px; font-size: 13px; }
  .ly2-search { display: none; }
  .ly2-content { padding: 12px; }
}
</style>
