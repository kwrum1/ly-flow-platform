<template>
  <div class="ly-shell" :class="{ 'is-collapsed': collapsed, 'is-mobile-open': mobileOpen }">
    <button v-if="mobileOpen" class="nav-scrim" aria-label="关闭导航" @click="mobileOpen = false" />

    <aside class="ly-sidebar">
      <RouterLink class="ly-brand" to="/dashboard" aria-label="流影首页" @click="mobileOpen = false">
        <XdrLogo :size="38" />
        <span class="brand-copy"><strong>流影安全</strong><small>态势感知平台</small></span>
      </RouterLink>

      <nav class="ly-nav" aria-label="主导航">
        <section v-for="group in visibleGroups" :key="group.title" class="nav-group">
          <h2>{{ group.title }}</h2>
          <RouterLink
            v-for="item in group.items"
            :key="item.path"
            :to="item.path"
            class="nav-item"
            :title="collapsed ? item.label : undefined"
            @click="mobileOpen = false"
          >
            <el-icon><component :is="iconFor(item.path)" /></el-icon>
            <span class="nav-label">{{ item.label }}</span>
          </RouterLink>
        </section>
      </nav>

      <div class="sidebar-foot">
        <span class="status-dot online" />
        <span class="sidebar-foot-copy">服务运行正常</span>
      </div>
    </aside>

    <section class="ly-main">
      <header class="ly-topbar">
        <div class="topbar-title">
          <button class="icon-button mobile-trigger" type="button" aria-label="打开导航" @click="mobileOpen = true">
            <el-icon><Menu /></el-icon>
          </button>
          <button class="icon-button collapse-trigger" type="button" :aria-label="collapsed ? '展开导航' : '收起导航'" @click="collapsed = !collapsed">
            <el-icon><Fold v-if="!collapsed" /><Expand v-else /></el-icon>
          </button>
          <div><p>{{ routeGroup }}</p><h1>{{ routeTitle }}</h1></div>
        </div>
        <div class="topbar-right">
          <div class="system-chip"><span class="status-dot online" /><span>设备在线</span></div>
          <time class="system-time">{{ currentTime }}</time>
          <el-dropdown trigger="click">
            <button class="user-button" type="button">
              <span class="user-avatar">{{ userInitial }}</span>
              <span class="user-name">{{ authStore.user?.username || '管理员' }}</span>
              <el-icon><ArrowDown /></el-icon>
            </button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item @click="handleLogout"><el-icon><SwitchButton /></el-icon>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
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
import {
  Aim, ArrowDown, Collection, Connection, DataAnalysis, DataLine, Document,
  Expand, Fold, Key, Lock, Menu, Monitor, Operation, Setting, SwitchButton, User,
} from '@element-plus/icons-vue'
import { overviewClient } from '../api/domain'
import XdrLogo from '../components/XdrLogo.vue'
import { productNavigation, canAccessNavigationItem, flattenNavigation } from '../shared/navigation'
import { formatChinaTime, refreshPlatformTimeOffset } from '../shared/time'
import { useAuthStore } from '../stores/auth'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()
const currentTime = ref(formatChinaTime())
const collapsed = ref(false)
const mobileOpen = ref(false)
let timer = null

const icons = {
  '/dashboard': Monitor,
  '/incidents': Aim,
  '/assets': Connection,
  '/traffic-threats': DataLine,
  '/runtime': DataAnalysis,
  '/rasp': Lock,
  '/events': Document,
  '/rules': Collection,
  '/control-center': Operation,
  '/install-config': Setting,
  '/users': User,
}

const visibleGroups = computed(() => productNavigation
  .map((group) => ({ ...group, items: group.items.filter((item) => canAccessNavigationItem(item, authStore.user?.role || 'viewer')) }))
  .filter((group) => group.items.length > 0))

const activeItem = computed(() => flattenNavigation().find((entry) => entry.path === route.path))
const routeTitle = computed(() => activeItem.value?.label || '运营总览')
const routeGroup = computed(() => activeItem.value?.group || '核心运营')
const userInitial = computed(() => String(authStore.user?.username || 'A').slice(0, 1).toUpperCase())
const iconFor = (path) => icons[path] || Key

const handleLogout = async () => {
  await authStore.logout()
  router.push('/login')
}

onMounted(() => {
  refreshPlatformTimeOffset(overviewClient.systemTime).catch(() => {})
  timer = setInterval(() => { currentTime.value = formatChinaTime() }, 1000)
})
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.ly-shell{display:grid;grid-template-columns:216px minmax(0,1fr);height:100vh;min-width:0;background:#f3f6fa;color:#27364a;transition:grid-template-columns .18s ease}.ly-shell.is-collapsed{grid-template-columns:64px minmax(0,1fr)}
.ly-sidebar{position:relative;z-index:20;display:flex;min-width:0;flex-direction:column;overflow:hidden;background:#fff;border-right:1px solid #dce3ec}
.ly-brand{display:flex;height:64px;flex:0 0 64px;align-items:center;gap:10px;padding:0 13px;color:#172b4d;text-decoration:none;border-bottom:1px solid #e6ebf1;white-space:nowrap}.brand-copy{min-width:0}.brand-copy strong,.brand-copy small{display:block;letter-spacing:0}.brand-copy strong{font-size:16px}.brand-copy small{margin-top:1px;color:#7b8798;font-size:11px;font-weight:500}
.ly-nav{flex:1;overflow-x:hidden;overflow-y:auto;padding:10px 8px}.nav-group{margin-bottom:12px}.nav-group h2{height:24px;margin:0;padding:4px 10px;color:#98a2b3;font-size:11px;font-weight:600;line-height:16px;letter-spacing:0;white-space:nowrap}.nav-item{display:flex;height:40px;align-items:center;gap:10px;margin:2px 0;padding:0 10px;border-radius:5px;color:#475467;text-decoration:none;transition:background .15s ease,color .15s ease}.nav-item .el-icon{width:18px;flex:0 0 18px;font-size:18px}.nav-item:hover{background:#f1f6fc;color:#1769ba}.nav-item.router-link-active{background:#e8f3ff;color:#1268bd;font-weight:600;box-shadow:inset 3px 0 #1976d2}.nav-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sidebar-foot{display:flex;height:46px;align-items:center;gap:9px;padding:0 18px;border-top:1px solid #e6ebf1;color:#667085;font-size:12px;white-space:nowrap}.status-dot{display:inline-block;width:7px;height:7px;flex:0 0 7px;border-radius:50%;background:#98a2b3}.status-dot.online{background:#20a66a;box-shadow:0 0 0 3px #e3f5ed}
.is-collapsed .brand-copy,.is-collapsed .nav-label,.is-collapsed .nav-group h2,.is-collapsed .sidebar-foot-copy{display:none}.is-collapsed .ly-brand{padding:0 13px}.is-collapsed .nav-item{justify-content:center;padding:0}.is-collapsed .sidebar-foot{justify-content:center;padding:0}
.ly-main{display:grid;min-width:0;min-height:0;grid-template-rows:64px minmax(0,1fr)}.ly-topbar{display:flex;min-width:0;align-items:center;justify-content:space-between;gap:20px;padding:0 20px;background:#fff;border-bottom:1px solid #dce3ec}.topbar-title,.topbar-right,.user-button,.system-chip{display:flex;align-items:center}.topbar-title{min-width:0;gap:8px}.topbar-title p{margin:0;color:#8792a2;font-size:11px;line-height:16px}.topbar-title h1{margin:0;color:#1d2939;font-size:18px;line-height:24px;letter-spacing:0}.topbar-right{gap:14px}.icon-button{display:grid;width:36px;height:36px;place-items:center;border:0;border-radius:5px;background:transparent;color:#667085;cursor:pointer}.icon-button:hover{background:#f1f5f9;color:#1976d2}.mobile-trigger{display:none}.system-chip{gap:7px;color:#475467;font-size:12px}.system-time{color:#667085;font-size:12px;font-variant-numeric:tabular-nums}.user-button{height:38px;gap:8px;padding:0 8px;border:0;border-radius:5px;background:transparent;color:#344054;cursor:pointer}.user-button:hover{background:#f3f6fa}.user-avatar{display:grid;width:28px;height:28px;place-items:center;border-radius:50%;background:#e7f2ff;color:#1769ba;font-weight:700}.ly-content{min-width:0;min-height:0;overflow:auto;overscroll-behavior:contain;background:#f3f6fa}.nav-scrim{display:none}
.module-fade-enter-active,.module-fade-leave-active{transition:opacity .16s ease}.module-fade-enter-from,.module-fade-leave-to{opacity:0}
@media(max-width:900px){.ly-shell,.ly-shell.is-collapsed{grid-template-columns:1fr}.ly-sidebar{position:fixed;inset:0 auto 0 0;width:216px;transform:translateX(-100%);transition:transform .18s ease;box-shadow:8px 0 28px rgb(15 23 42 / 18%)}.is-mobile-open .ly-sidebar{transform:translateX(0)}.nav-scrim{position:fixed;z-index:15;inset:0;display:block;border:0;background:rgb(15 23 42 / 40%)}.collapse-trigger{display:none}.mobile-trigger{display:grid}.system-chip,.system-time{display:none}.ly-main{grid-column:1}.ly-topbar{padding:0 12px}.user-name{display:none}}
</style>
