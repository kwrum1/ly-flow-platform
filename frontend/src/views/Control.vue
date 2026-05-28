<template>
  <div class="control-page">
    <div class="page-header">
      <h1>控制中心</h1>
      <div class="header-actions">
        <el-input
          v-model="searchQuery"
          placeholder="搜索Agent名称、IP..."
          prefix-icon="Search"
          clearable
          style="width: 280px"
        />
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-icon total">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
          ><rect
            x="2"
            y="3"
            width="20"
            height="14"
            rx="2"
          /><line
            x1="8"
            y1="21"
            x2="16"
            y2="21"
          /><line
            x1="12"
            y1="17"
            x2="12"
            y2="21"
          /></svg>
        </div>
        <div class="stat-info">
          <span class="stat-value">{{ agents.length }}</span>
          <span class="stat-label">Agent总数</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon online">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
          ><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" /></svg>
        </div>
        <div class="stat-info">
          <span class="stat-value">{{ onlineCount }}</span>
          <span class="stat-label">在线</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon offline">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
          ><circle
            cx="12"
            cy="12"
            r="10"
          /><line
            x1="15"
            y1="9"
            x2="9"
            y2="15"
          /><line
            x1="9"
            y1="9"
            x2="15"
            y2="15"
          /></svg>
        </div>
        <div class="stat-info">
          <span class="stat-value">{{ agents.length - onlineCount }}</span>
          <span class="stat-label">离线</span>
        </div>
      </div>
    </div>

    <div class="filter-tabs">
      <button
        :class="{ active: filterStatus === 'all' }"
        @click="filterStatus = 'all'"
      >
        全部
      </button>
      <button
        :class="{ active: filterStatus === 'online' }"
        @click="filterStatus = 'online'"
      >
        在线
      </button>
      <button
        :class="{ active: filterStatus === 'offline' }"
        @click="filterStatus = 'offline'"
      >
        离线
      </button>
    </div>

    <div class="agents-table">
      <div class="table-header">
        <div class="th">
          Agent名称
        </div>
        <div class="th">
          IP地址
        </div>
        <div class="th">
          操作系统
        </div>
        <div class="th">
          状态
        </div>
        <div class="th">
          最后活跃
        </div>
        <div class="th">
          插件状态
        </div>
        <div class="th">
          RASP模式
        </div>
      </div>
      <div class="table-body">
        <div
          v-if="loading"
          class="table-state"
        >
          加载中...
        </div>
        <div
          v-else-if="error"
          class="table-state error"
        >
          {{ error }}
        </div>
        <div
          v-else-if="filteredAgents.length === 0"
          class="table-state"
        >
          暂无Agent数据
        </div>
        <div
          v-for="agent in filteredAgents"
          :key="agent.id"
          class="table-row"
        >
          <div class="td name">
            <span
              class="status-dot"
              :class="agent.status"
            />
            {{ agent.name }}
          </div>
          <div class="td ip">
            {{ agent.ip }}
          </div>
          <div class="td os">
            {{ agent.os }}
          </div>
          <div class="td">
            <span
              class="status-badge"
              :class="agent.status"
            >{{ agent.statusText }}</span>
          </div>
          <div class="td last-seen">
            {{ agent.lastSeen }}
          </div>
          <div class="td plugins">
            <span
              class="plugin-tag"
              :class="{ active: agent.plugins.traffic }"
            >流量</span>
            <span
              class="plugin-tag"
              :class="{ active: agent.plugins.hids }"
            >HIDS</span>
            <span
              class="plugin-tag"
              :class="{ active: agent.plugins.rasp }"
            >RASP</span>
            <span
              class="plugin-tag"
              :class="{ active: agent.plugins.asset }"
            >资产</span>
          </div>
          <div class="td">
            <button
              type="button"
              class="rasp-mode"
              :class="agent.raspMode"
              :disabled="!isAdmin || agent.modeLoading"
              @click="toggleAgentRASPMode(agent)"
            >{{ agent.raspMode === 'protect' ? '防护' : '检测' }}</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import api from '../api'

const searchQuery = ref('')
const filterStatus = ref('all')
const currentUserRole = ref(localStorage.getItem('role') || '')
const isAdmin = computed(() => currentUserRole.value === 'admin')
const loading = ref(false)
const error = ref('')
const agents = ref([])

const onlineCount = computed(() => agents.value.filter(a => a.status === 'online').length)
const unwrap = (payload) => payload?.data ?? payload ?? {}
const requestJSON = async (path, options = {}) => {
  const method = String(options.method || 'GET').toUpperCase()
  const body = typeof options.body === 'string' ? JSON.parse(options.body) : options.body

  if (method === 'GET') return api.get(path)
  if (method === 'POST') return api.post(path, body || {})
  if (method === 'PUT') return api.put(path, body || {})
  if (method === 'DELETE') return api.delete(path, body ? { data: body } : undefined)

  throw new Error(`Unsupported method: ${method}`)
}

const adaptAgent = (agent, index) => ({
  id: agent.id || agent.uuid || index,
  name: agent.name || agent.hostname || agent.host_name || '-',
  ip: agent.ip || agent.ip_addr || agent.address || '-',
  os: agent.os || agent.platform || agent.language || '-',
  status: String(agent.status || '').toLowerCase() === 'offline' ? 'offline' : 'online',
  statusText: String(agent.status || '').toLowerCase() === 'offline' ? '离线' : '在线',
  lastSeen: agent.last_seen || agent.lastSeen || agent.updated_at || '-',
  plugins: {
    traffic: Boolean(agent.plugins?.traffic ?? agent.protection),
    hids: Boolean(agent.plugins?.hids ?? agent.protection),
    rasp: Boolean(agent.plugins?.rasp ?? agent.protection),
    asset: Boolean(agent.plugins?.asset ?? true)
  },
  raspMode: (agent.rasp_mode || agent.raspMode || (agent.block_mode ? 'protect' : 'detect')) === 'protect' ? 'protect' : 'detect',
  modeLoading: false,
})

const loadAgents = async () => {
  loading.value = true
  error.value = ''
  try {
    const body = unwrap(await requestJSON('/rasp/agents'))
    const items = Array.isArray(body) ? body : (body.items || [])
    agents.value = items.map(adaptAgent)
  } catch (err) {
    error.value = err.message || '加载Agent失败'
    agents.value = []
  } finally {
    loading.value = false
  }
}

const toggleAgentRASPMode = async (agent) => {
  if (!isAdmin.value) {
    error.value = 'Permission denied: 仅管理员可切换防护模式。'
    return
  }

  const previous = agent.raspMode
  const desired = previous === 'protect' ? 'detect' : 'protect'
  agent.modeLoading = true
  error.value = ''
  try {
    const path = desired === 'protect' ? '/rasp/protection/enable' : '/rasp/protection/disable'
    const body = desired === 'protect' ? { agent_id: agent.id, block_mode: true } : { agent_id: agent.id }
    await requestJSON(path, { method: 'POST', body: JSON.stringify(body) })
    agent.raspMode = desired
  } catch (err) {
    agent.raspMode = previous
    error.value = err.message || 'Operation failed: 防护模式更新失败'
  } finally {
    agent.modeLoading = false
  }
}

const filteredAgents = computed(() => {
  let result = agents.value
  if (filterStatus.value !== 'all') {
    result = result.filter(a => a.status === filterStatus.value)
  }
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    result = result.filter(a => a.name.toLowerCase().includes(q) || a.ip.includes(q))
  }
  return result
})

onMounted(() => {
  loadAgents()
})
</script>

<style scoped>
.control-page { min-height: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.page-header h1 { font-size: 24px; font-weight: 700; color: var(--text-primary); }
.header-actions { display: flex; gap: 12px; }

.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }
.stat-card { display: flex; align-items: center; gap: 16px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; }
.stat-icon { width: 48px; height: 48px; border-radius: 10px; display: flex; align-items: center; justify-content: center; }
.stat-icon svg { width: 24px; height: 24px; }
.stat-icon.total { background: rgba(24, 144, 255, 0.15); color: var(--primary-color); }
.stat-icon.online { background: rgba(82, 196, 26, 0.15); color: var(--risk-low); }
.stat-icon.offline { background: rgba(255, 77, 79, 0.15); color: var(--risk-critical); }
.stat-info { display: flex; flex-direction: column; }
.stat-value { font-size: 24px; font-weight: 700; color: var(--text-primary); }
.stat-label { font-size: 12px; color: var(--text-secondary); }

.filter-tabs { display: flex; gap: 8px; margin-bottom: 16px; }
.filter-tabs button { padding: 8px 16px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-secondary); font-size: 13px; cursor: pointer; transition: all 0.15s; }
.filter-tabs button.active { background: var(--primary-color); border-color: var(--primary-color); color: white; }

.agents-table { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; }
.table-header { display: flex; background: var(--bg-secondary); border-bottom: 1px solid var(--border-color); }
.th { padding: 12px 16px; font-size: 12px; font-weight: 600; color: var(--text-secondary); text-align: left; }
.th:nth-child(1) { flex: 2; }
.th:nth-child(2) { width: 120px; }
.th:nth-child(3) { width: 140px; }
.th:nth-child(4) { width: 80px; }
.th:nth-child(5) { width: 100px; }
.th:nth-child(6) { flex: 1; }
.th:nth-child(7) { width: 90px; }

.table-body { max-height: 450px; overflow-y: auto; }
.table-state { padding: 24px; text-align: center; color: var(--text-secondary); }
.table-state.error { color: var(--risk-critical); }
.table-row { display: flex; align-items: center; border-bottom: 1px solid var(--border-color); }
.table-row:hover { background: var(--bg-hover); }
.table-row:last-child { border-bottom: none; }
.td { padding: 14px 16px; font-size: 13px; color: var(--text-primary); display: flex; align-items: center; }
.td.name { flex: 2; font-weight: 500; gap: 8px; }
.td.ip { width: 120px; font-family: monospace; }
.td.os { width: 140px; }
.td.last-seen { width: 100px; color: var(--text-secondary); }
.td.plugins { flex: 1; gap: 6px; }
.rasp-mode { min-width: 58px; border: 0; border-radius: 999px; padding: 5px 12px; color: #fff; cursor: pointer; }
.rasp-mode.protect { background: #22c55e; }
.rasp-mode.detect { background: #3b82f6; }
.rasp-mode:disabled { cursor: not-allowed; opacity: 0.6; }

.status-dot { width: 8px; height: 8px; border-radius: 50%; }
.status-dot.online { background: var(--risk-low); box-shadow: 0 0 8px var(--risk-low); }
.status-dot.offline { background: var(--text-muted); }

.status-badge { padding: 3px 10px; border-radius: 4px; font-size: 12px; }
.status-badge.online { background: var(--risk-low-bg); color: var(--risk-low); }
.status-badge.offline { background: var(--bg-hover); color: var(--text-muted); }

.plugin-tag { padding: 2px 8px; background: var(--bg-secondary); border-radius: 4px; font-size: 11px; color: var(--text-muted); }
.plugin-tag.active { background: var(--primary-glow); color: var(--primary-color); }
</style>
