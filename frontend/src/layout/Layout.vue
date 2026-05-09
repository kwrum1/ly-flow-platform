<template>
  <el-container class="layout">
    <el-aside width="200px">
      <div class="logo">流影安全平台</div>
      <el-menu :default-active="activeMenu" router>
        <el-menu-item index="/dashboard">
          <el-icon><DataAnalysis /></el-icon>
          <span>态势总览</span>
        </el-menu-item>
        <el-menu-item index="/assets">
          <el-icon><Monitor /></el-icon>
          <span>资产管理</span>
        </el-menu-item>
        <el-menu-item index="/events">
          <el-icon><Document /></el-icon>
          <span>流量事件</span>
        </el-menu-item>
        <el-menu-item index="/threat-intel">
          <el-icon><Connection /></el-icon>
          <span>威胁情报</span>
        </el-menu-item>
        <el-menu-item index="/vulnerabilities">
          <el-icon><Warning /></el-icon>
          <span>漏洞管理</span>
        </el-menu-item>
        <el-menu-item index="/reports">
          <el-icon><DataLine /></el-icon>
          <span>报告中心</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <span>系统设置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header>
        <div class="header-right">
          <el-badge :value="alertCount" :max="99">
            <el-button :icon="Bell">告警</el-button>
          </el-badge>
          <el-dropdown>
            <span>{{ username }}</span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item @click="handleLogout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>
      <el-main>
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'

const router = useRouter()
const route = useRoute()
const username = ref(localStorage.getItem('username') || 'Admin')
const alertCount = ref(0)
const activeMenu = ref(route.path)

const handleLogout = () => {
  localStorage.clear()
  ElMessage.success('已退出')
  router.push('/login')
}

let ws = null

const connectWS = () => {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
  ws = new WebSocket(`${protocol}//${location.host}/ws`)
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      if (data.type === 'new_alert') {
        alertCount.value++
      }
    } catch (e) {
      console.error('WebSocket message parse error:', e)
    }
  }
  ws.onerror = (error) => {
    console.error('WebSocket error:', error)
  }
}

onMounted(() => {
  activeMenu.value = route.path
  connectWS()
})

onUnmounted(() => ws?.close())
</script>

<style scoped>
.layout {
  height: 100vh;
}
.el-aside {
  background: #304156;
  color: #fff;
}
.logo {
  height: 60px;
  line-height: 60px;
  text-align: center;
  font-size: 18px;
  font-weight: bold;
}
.el-header {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  background: #fff;
  box-shadow: 0 1px 4px rgba(0,0,0,.1);
}
.header-right {
  display: flex;
  align-items: center;
  gap: 20px;
}
</style>
