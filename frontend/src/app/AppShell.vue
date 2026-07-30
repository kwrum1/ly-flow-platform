<template>
  <div class="ly-shell">
    <aside class="ly-sidebar">
      <RouterLink class="ly-brand" to="/dashboard" aria-label="流影首页">
        <span class="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 64 64" role="img" focusable="false">
            <circle class="mark-orbit mark-orbit-wide" cx="34" cy="30" r="25" />
            <circle class="mark-orbit" cx="34" cy="30" r="16" />
            <path class="mark-shadow" d="M31 38c8-4 17-5 26-3-5 10-16 17-29 17-7 0-13-2-18-6 8 1 15-1 21-8Z" />
            <path class="mark-flow mark-flow-back" d="M4 42C14 28 27 27 36 31c-9 1-15 5-21 13-4 5-8 8-11 9 0-4 0-7 0-11Z" />
            <path class="mark-flow" d="M3 36c14-10 25-9 35-3-12 0-18 5-25 15-3 4-6 7-10 9 1-7 1-14 0-21Z" />
            <path class="mark-hotline" d="M6 39c11-7 20-7 29-3-10 1-15 5-21 13" />
            <path class="mark-glow" d="M21 42c9-7 18-9 34-7-11 0-20 4-29 13" />
            <circle class="mark-dot" cx="49" cy="22" r="3.4" />
            <circle class="mark-dot mark-dot-small" cx="35" cy="15" r="2.2" />
          </svg>
        </span>
        <span>
          <strong>流影</strong>
          <small>XDR Security Console</small>
        </span>
      </RouterLink>

      <nav class="ly-nav" aria-label="主导航">
        <section v-for="group in visibleGroups" :key="group.title" class="nav-group">
          <h2>{{ group.title }}</h2>
          <RouterLink
            v-for="item in group.items"
            :key="item.path"
            :to="item.path"
            class="nav-item"
          >
            <span class="nav-label">{{ item.label }}</span>
            <span class="nav-desc">{{ item.description }}</span>
          </RouterLink>
        </section>
      </nav>
    </aside>

    <section class="ly-main">
      <header class="ly-topbar">
        <div>
          <p class="route-kicker">LYFLOW COMMAND</p>
          <h1>{{ routeTitle }}</h1>
        </div>
        <div class="topbar-right">
          <div class="time-card">
            <span>中国时间</span>
            <strong>{{ currentTime }}</strong>
          </div>
          <button type="button" class="user-button" @click="handleLogout">
            {{ authStore.user?.username || '管理员' }} · 退出
          </button>
        </div>
      </header>

      <main class="ly-content">
        <RouterView v-slot="{ Component, route }">
          <Transition name="module-fade" mode="out-in">
            <component :is="Component" :key="route.fullPath" />
          </Transition>
        </RouterView>
      </main>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { overviewClient } from '../api/domain'
import { productNavigation, canAccessNavigationItem, flattenNavigation } from '../shared/navigation'
import { formatChinaTime, refreshPlatformTimeOffset } from '../shared/time'
import { useAuthStore } from '../stores/auth'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()
const currentTime = ref(formatChinaTime())
let timer = null

const visibleGroups = computed(() => productNavigation
  .map((group) => ({
    ...group,
    items: group.items.filter((item) => canAccessNavigationItem(item, authStore.user?.role || 'viewer')),
  }))
  .filter((group) => group.items.length > 0))

const routeTitle = computed(() => {
  const item = flattenNavigation().find((entry) => entry.path === route.path)
  return item?.label || '运营总览'
})

const handleLogout = async () => {
  await authStore.logout()
  router.push('/login')
}

onMounted(() => {
  refreshPlatformTimeOffset(overviewClient.systemTime).catch(() => {})
  timer = setInterval(() => {
    currentTime.value = formatChinaTime()
  }, 1000)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
.ly-shell {
  display: grid;
  grid-template-columns: 268px minmax(0, 1fr);
  height: 100vh;
  min-width: 0;
  color: var(--text-primary);
  background:
    linear-gradient(90deg, rgba(56,189,248,.05) 1px, transparent 1px),
    linear-gradient(0deg, rgba(56,189,248,.04) 1px, transparent 1px),
    radial-gradient(circle at 78% 0%, rgba(20,184,166,.14), transparent 30%),
    linear-gradient(135deg, #050b14 0%, #08111f 46%, #0c1728 100%);
  background-size: 44px 44px, 44px 44px, auto, auto;
}

.ly-sidebar {
  min-width: 0;
  padding: 18px 14px;
  background: linear-gradient(180deg, rgba(3, 10, 22, .98), rgba(6, 16, 32, .94));
  border-right: 1px solid rgba(56, 189, 248, .18);
  box-shadow: inset -1px 0 0 rgba(255,255,255,.04), 22px 0 80px rgba(0,0,0,.22);
  overflow-y: auto;
}

.ly-brand {
  display: flex;
  gap: 14px;
  align-items: center;
  padding: 10px 10px 16px;
  color: inherit;
  text-decoration: none;
}

.brand-mark {
  display: grid;
  place-items: center;
  width: 50px;
  height: 50px;
  border-radius: 50%;
  background:
    radial-gradient(circle at 42% 45%, rgba(56,189,248,.24), transparent 20%),
    radial-gradient(circle at 72% 32%, rgba(96,165,250,.34), transparent 24%),
    linear-gradient(145deg, #031127, #071d3c 58%, #03101d);
  border: 1px solid rgba(96,165,250,.62);
  box-shadow: 0 0 0 1px rgba(59,130,246,.18), 0 18px 52px rgba(37,99,235,.34), inset 0 0 28px rgba(14,165,233,.18);
  overflow: hidden;
}

.brand-mark svg {
  width: 48px;
  height: 48px;
  filter: drop-shadow(0 0 12px rgba(56,189,248,.42));
}

.mark-orbit {
  fill: none;
  stroke: rgba(59,130,246,.34);
  stroke-width: 1;
}

.mark-orbit-wide {
  stroke: rgba(96,165,250,.58);
  stroke-width: 1.35;
}

.mark-shadow {
  fill: rgba(148,197,255,.32);
  opacity: .68;
}

.mark-flow {
  fill: none;
  stroke: #dbeafe;
  stroke-width: 4.8;
  stroke-linecap: round;
  opacity: .96;
}

.mark-flow-back {
  stroke: #2563eb;
  stroke-width: 7.2;
  opacity: .66;
}

.mark-hotline, .mark-glow {
  fill: none;
  stroke-linecap: round;
}

.mark-hotline {
  stroke: #38bdf8;
  stroke-width: 2;
}

.mark-glow {
  stroke: rgba(147,197,253,.82);
  stroke-width: 1.2;
}

.mark-dot {
  fill: #ff4d5e;
  stroke: rgba(248,250,252,.82);
  stroke-width: .8;
}

.mark-dot-small {
  fill: #38bdf8;
  stroke: rgba(191,219,254,.75);
}

.ly-brand strong {
  display: block;
  font-size: 22px;
  letter-spacing: 0.08em;
  color: #f8fafc;
}

.ly-brand small {
  color: #7dd3fc;
  font-size: 11px;
  letter-spacing: .08em;
}

.ops-strip {
  margin: 4px 8px 18px;
  padding: 12px;
  border-radius: 14px;
  background: linear-gradient(135deg, rgba(14,165,233,.14), rgba(16,185,129,.08));
  border: 1px solid rgba(125,211,252,.18);
}

.ops-strip span {
  display: block;
  color: var(--text-muted);
  font-size: 10px;
  font-weight: 900;
  letter-spacing: .16em;
}

.ops-strip b {
  display: block;
  margin-top: 5px;
  color: #dff7ff;
  font-size: 12px;
  line-height: 1.45;
}

.ly-nav {
  display: grid;
  gap: 18px;
}

.nav-group h2 {
  margin: 0 0 8px;
  color: #5f7189;
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.14em;
  text-align: center;
}

.nav-item {
  min-height: 54px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 4px;
  padding: 10px 12px;
  color: #9aa8bb;
  text-align: center;
  text-decoration: none;
  border-radius: 12px;
  border: 1px solid transparent;
  transition: color .18s ease, background .18s ease, border-color .18s ease, transform .18s ease;
}

.nav-item:hover,
.nav-item.router-link-active {
  color: #f8fafc;
  background: linear-gradient(135deg, rgba(56,189,248,.14), rgba(34,197,94,.08));
  border-color: rgba(125,211,252,.28);
  box-shadow: 0 14px 34px rgba(2,8,23,.24);
  transform: translateX(2px);
}

.nav-label {
  width: 100%;
  font-size: 14px;
  font-weight: 850;
  line-height: 1.15;
}

.nav-desc {
  width: 100%;
  color: #64748b;
  font-size: 11px;
  line-height: 1.35;
}

.ly-main {
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-rows: clamp(64px, 7vh, 82px) minmax(0, 1fr);
}

.ly-topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  min-width: 0;
  padding: 0 clamp(16px, 2vw, 30px);
  background: rgba(5, 12, 24, .74);
  border-bottom: 1px solid rgba(125,211,252,.14);
  backdrop-filter: blur(22px);
}

.route-kicker {
  margin: 0 0 3px;
  color: var(--primary-light);
  font-size: 10px;
  font-weight: 900;
  letter-spacing: .18em;
}

.ly-topbar h1 {
  margin: 0;
  font-size: clamp(18px, 1.6vw, 24px);
  color: #f8fafc;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.topbar-right {
  display: flex;
  align-items: center;
  gap: 14px;
}

.time-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 3px;
  min-width: 136px;
  height: 50px;
  padding: 0 14px;
  border-radius: 12px;
  background: rgba(8,18,32,.72);
  border: 1px solid rgba(125,211,252,.16);
  backdrop-filter: blur(18px);
}

.time-card span {
  color: #718096;
  font-size: 12px;
  line-height: 1;
}

.time-card strong {
  font-variant-numeric: tabular-nums;
  line-height: 1;
  font-size: 17px;
  letter-spacing: .04em;
}

.user-button {
  height: 42px;
  padding: 0 16px;
  border: 1px solid rgba(125, 211, 252, 0.22);
  border-radius: 12px;
  color: #dff7ff;
  background: rgba(8,18,32,.72);
  backdrop-filter: blur(18px);
  cursor: pointer;
}

.ly-content {
  min-width: 0;
  min-height: 0;
  overflow: auto;
  overscroll-behavior: contain;
  background: radial-gradient(circle at 50% 0%, rgba(56,189,248,.08), transparent 34%);
}

.ly-content :deep(th),
.ly-content :deep(td),
.ly-content :deep(.panel-title),
.ly-content :deep(.detail-grid),
.ly-content :deep(.empty-cell) {
  text-align: center;
}

@media (max-width: 1180px) {
  .ly-shell {
    grid-template-columns: 220px minmax(0, 1fr);
  }

  .nav-desc,
  .time-card {
    display: none;
  }
}

.module-fade-enter-active,
.module-fade-leave-active {
  transition: opacity .36s ease, transform .36s cubic-bezier(.2,.78,.16,1);
}
.module-fade-enter-from,
.module-fade-leave-to {
  opacity: 0;
  transform: translateY(10px);
}

@media (max-width: 980px) {
  .ly-shell {
    grid-template-columns: 1fr;
  }

  .ly-sidebar {
    display: none;
  }

  .ly-topbar {
    flex-wrap: wrap;
    align-content: center;
    row-gap: 8px;
  }

  .topbar-right {
    min-width: 0;
  }

  .user-button {
    max-width: 48vw;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
}
</style>
