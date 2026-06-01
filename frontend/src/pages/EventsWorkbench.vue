<template>
  <section class="events-page">
    <form class="query-panel surface-card" @submit.prevent="searchSessions">
      <label><span>关键字</span><input v-model="query" type="search" placeholder="IP、域名、协议、探针" aria-label="会话关键词"></label>
      <label><span>源 IP</span><input v-model="filters.src_ip"></label>
      <label><span>目的 IP</span><input v-model="filters.dst_ip"></label>
      <label><span>协议</span><input v-model="filters.protocol"></label>
      <button type="submit" class="primary" :disabled="loading">{{ loading ? '更新中' : '查询' }}</button>
      <button type="button" @click="loadSessions" :disabled="loading">刷新</button>
    </form>

    <div v-if="error" class="notice error">{{ error }}</div>

    <article class="events-panel surface-card">
      <div class="panel-title"><strong>会话查询</strong><span>{{ `${sessions.length} 条 / 当前页可显示 ${pageSize} 条` }}</span></div>
      <div ref="tableWrap" :class="['table-wrap', { updating: loading && hasLoaded }]">
        <table>
          <thead><tr><th>时间</th><th>探针</th><th>协议</th><th>源地址</th><th>目的地址</th><th>会话内容</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-if="loading && !hasLoaded"><td colspan="7" class="empty-cell">正在读取会话数据</td></tr>
            <tr v-else-if="sessions.length === 0"><td colspan="7" class="empty-cell">当前没有会话记录。</td></tr>
            <tr v-for="session in sessions" :key="`${session.message_id || session.id}-${timeVersion}`">
              <td>{{ formatChinaDateTime(session.timestamp || session.created_at || session.last_seen) }}</td>
              <td><b>{{ trafficSourceText(session) }}</b></td>
              <td><span class="engine-chip">{{ protocolText(session) }}</span></td>
              <td>{{ endpointText(session, 'src') }}</td>
              <td>{{ endpointText(session, 'dst') }}</td>
              <td><b>{{ sessionSummary(session) }}</b><small>{{ pickText(session.source || session.stream, 'sessions:semantic') }}</small></td>
              <td><button type="button" @click="selected = session">详情</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="pager">
        <button type="button" @click="prevPage" :disabled="loading || page === 1">上一页</button>
        <span>第 {{ page }} 页</span>
        <button type="button" @click="nextPage" :disabled="loading || sessions.length < pageSize">下一页</button>
      </div>
    </article>

    <div v-if="selected" class="drawer-mask">
      <aside class="drawer surface-card">
        <div class="drawer-title"><strong>会话详情</strong><button type="button" @click="selected = null">×</button></div>
        <div class="drawer-body">
          <div class="detail-grid">
            <template v-for="row in sessionRows(selected)" :key="row.label">
              <span>{{ row.label }}</span><b>{{ row.value }}</b>
            </template>
          </div>
          <section class="payload-block">
            <div class="payload-title"><strong>原始载荷 JSON</strong><span>Suricata / Session Payload</span></div>
            <pre>{{ rawPayload(selected) }}</pre>
          </section>
        </div>
      </aside>
    </div>
  </section>
</template>

<script setup>
import { nextTick, onMounted, onUnmounted, ref } from 'vue'
import { assetAgentClient, trafficClient } from '../api/domain'
import { normalizeItems, pickText } from '../shared/api-normalize'
import { formatChinaDateTime, getPlatformTimeVersion } from '../shared/time'

const loading = ref(false)
const hasLoaded = ref(false)
const error = ref('')
const query = ref('')
const filters = ref({ src_ip: '', dst_ip: '', protocol: '' })
const sessions = ref([])
const timeVersion = ref(0)
const page = ref(1)
const pageSize = ref(12)
const selected = ref(null)
const tableWrap = ref(null)
const agentNames = ref({})
let resizeObserver = null

function entity(item, key) {
  return item?.entities?.[key] || item?.[key] || ''
}

function display(value) {
  return value === undefined || value === null || value === '' ? '-' : String(value)
}

function trafficSourceName(item) {
  const id = entity(item, 'agent_id') || item.agent_id || ''
  if (isMirrorTraffic(item, id)) return '流量镜像分析'
  return agentNames.value[id] || item.agent_display_name || item.display_name || item.probe_name || item.hostname || id
}

function trafficSourceText(item) {
  return `流量来源:${trafficSourceName(item) || '-'}`
}

function isMirrorTraffic(item, id = '') {
  return item.capture_source === 'mirror' || item.probe_kind === '镜像接口' || item.probe_name === '流量镜像分析' || item.agent_display_name === '流量镜像分析' || item.display_name === '流量镜像分析'
}

function protocolText(item) {
  return [item.protocol, item.app_protocol, item.direction].filter(Boolean).join(' / ') || '未知协议'
}

function endpointText(item, side) {
  const ip = side === 'src' ? (entity(item, 'source_ip') || item.src_ip) : (entity(item, 'target_ip') || item.dst_ip)
  const port = side === 'src' ? item.src_port : item.dst_port
  return [ip || '-', port || ''].filter(Boolean).join(':')
}

function sessionSummary(item) {
  return item.summary || item.message || item.http_host || item.dns_query || item.tls_sni || [item.http_method, item.http_path].filter(Boolean).join(' ') || item.event_type || '会话记录'
}

function sessionRows(item) {
  return [
    { label: '时间', value: display(formatChinaDateTime(item.timestamp || item.created_at || item.last_seen)) },
    { label: '流量来源', value: trafficSourceName(item) },
    { label: '协议', value: protocolText(item) },
    { label: '源地址', value: endpointText(item, 'src') },
    { label: '目的地址', value: endpointText(item, 'dst') },
    { label: '会话内容', value: sessionSummary(item) },
    { label: '来源', value: pickText(item.source || item.stream, 'sessions:semantic') },
    { label: '消息 ID', value: display(item.message_id || item.id) },
    { label: '事件类型', value: display(item.event_type || item.type) },
  ]
}

function rawPayload(item) {
  return JSON.stringify(item || {}, null, 2)
}

async function loadAgents() {
  const map = {}
  try {
    const data = normalizeItems(await assetAgentClient.agents({ limit: 200 }))
    for (const agent of data.items) map[agent.agent_id || agent.id] = agent.display_name || agent.hostname || agent.agent_id || agent.id
  } catch { /* session query remains usable without agent names */ }
  agentNames.value = map
}

async function loadSessions() {
  timeVersion.value = getPlatformTimeVersion()
  loading.value = true
  error.value = ''
  try {
    const payload = await trafficClient.sessions({ ...filters.value, query: query.value.trim(), limit: pageSize.value, offset: (page.value - 1) * pageSize.value })
    const normalized = normalizeItems(payload)
    sessions.value = normalized.items
    hasLoaded.value = true
  } catch (requestError) {
    error.value = requestError?.message || '无法读取会话数据'
  } finally {
    loading.value = false
  }
}

function searchSessions() {
  page.value = 1
  loadSessions()
}

function prevPage() { if (page.value > 1) { page.value -= 1; loadSessions() } }
function nextPage() { if (sessions.value.length >= pageSize.value) { page.value += 1; loadSessions() } }
function updatePageSize({ reload = true } = {}) {
  const height = tableWrap.value?.clientHeight || 0
  if (!height) return
  const nextSize = Math.max(8, Math.floor((height - 36) / 38))
  if (nextSize !== pageSize.value) { pageSize.value = nextSize; if (reload) loadSessions() }
}

onMounted(async () => {
  await loadAgents()
  await nextTick()
  updatePageSize({ reload: false })
  await loadSessions()
  resizeObserver = new ResizeObserver(() => updatePageSize())
  if (tableWrap.value) resizeObserver.observe(tableWrap.value)
})

onUnmounted(() => resizeObserver?.disconnect())
</script>

<style scoped>
.events-page {
  position: relative;
  height: 100%;
  min-height: 0;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  gap: 12px;
  padding: 14px;
  color: var(--text-primary);
  box-sizing: border-box;
}

.query-panel,
.events-panel {
  border-color: var(--border-color);
}

.query-panel {
  display: grid;
  grid-template-columns: 1.4fr repeat(3, minmax(120px, 1fr)) auto auto;
  gap: 9px;
  align-items: end;
  padding: 12px;
  min-height: 0;
}

.query-panel label {
  position: relative;
  display: grid;
  gap: 5px;
  min-width: 0;
  color: var(--text-secondary);
  font-size: 12px;
}

input {
  height: 32px;
  min-width: 0;
  border: 1px solid var(--border-color);
  border-radius: var(--card-radius-sm);
  background: var(--bg-secondary);
  color: var(--text-primary);
  padding: 0 11px;
  font-size: 12px;
  outline: 0;
}

input::placeholder {
  color: var(--text-muted);
}

input:focus {
  border-color: var(--border-glow);
  box-shadow: 0 0 0 3px var(--primary-glow);
}

button {
  height: 32px;
  padding: 0 12px;
  border: 1px solid var(--border-color);
  border-radius: var(--card-radius-sm);
  background: var(--bg-elevated);
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 12px;
  transition: border-color var(--transition-fast), color var(--transition-fast), background var(--transition-fast);
}

button:hover:not(:disabled) {
  border-color: var(--border-glow);
  color: var(--text-primary);
  background: var(--bg-hover);
}

button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.primary {
  border: 0;
  background: linear-gradient(135deg, var(--primary-color), var(--risk-low));
  color: var(--text-inverse);
  font-weight: 900;
  box-shadow: 0 10px 28px rgba(56, 189, 248, 0.18);
}

.notice.error {
  padding: 10px 12px;
  border: 1px solid var(--risk-critical-border);
  border-radius: var(--card-radius-sm);
  color: #fecaca;
  background: var(--risk-critical-bg);
}

.events-panel {
  min-height: 0;
  display: grid;
  grid-template-rows: 44px minmax(0, 1fr) 40px;
}

.panel-title {
  position: relative;
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
  border-bottom: 1px solid var(--border-light);
  background: rgba(4, 12, 24, 0.38);
}

.panel-title strong {
  color: var(--text-primary);
  font-size: 14px;
}

.panel-title span {
  color: var(--text-muted);
  font-size: 12px;
}

.table-wrap {
  position: relative;
  min-height: 0;
  overflow: auto;
}

.table-wrap.updating {
  opacity: 0.72;
}

table {
  width: 100%;
  min-width: 960px;
  border-collapse: separate;
  border-spacing: 0;
  table-layout: fixed;
}

th,
td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border-light);
  text-align: left;
  vertical-align: middle;
}

th {
  position: sticky;
  top: 0;
  z-index: 1;
  height: 36px;
}

td {
  height: 38px;
  color: var(--text-primary);
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

td b {
  display: block;
  color: var(--text-primary);
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
}

td small {
  display: block;
  margin-top: 2px;
  color: var(--text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
}

.empty-cell {
  height: 96px;
  text-align: center;
  color: var(--text-secondary);
}

.engine-chip {
  display: inline-flex;
  max-width: 100%;
  padding: 3px 8px;
  border: 1px solid rgba(125, 211, 252, 0.24);
  border-radius: 999px;
  color: var(--primary-light);
  background: rgba(125, 211, 252, 0.09);
  overflow: hidden;
  text-overflow: ellipsis;
}

.pager {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 10px;
  padding: 4px 14px;
  border-top: 1px solid var(--border-light);
  background: rgba(4, 12, 24, 0.34);
}

.pager span {
  min-width: 72px;
  text-align: center;
  color: var(--text-secondary);
  font-size: 12px;
}

.drawer-mask {
  position: fixed;
  inset: 0;
  z-index: 40;
  display: flex;
  justify-content: flex-end;
  padding: 74px 24px 24px;
  background: rgba(2, 8, 23, 0.58);
}

.drawer {
  width: min(640px, 92vw);
  height: 100%;
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
}

.drawer-title {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 16px 18px;
  border-bottom: 1px solid var(--border-light);
}

.drawer-title strong {
  font-size: 16px;
}

.drawer-body {
  position: relative;
  min-height: 0;
  overflow: auto;
  padding: 18px;
}

.detail-grid {
  display: grid;
  grid-template-columns: 112px minmax(0, 1fr);
  gap: 10px 14px;
  padding: 14px;
  border: 1px solid var(--border-light);
  border-radius: var(--card-radius-sm);
  background: rgba(2, 8, 23, 0.24);
}

.detail-grid span {
  color: var(--text-muted);
  font-size: 12px;
}

.detail-grid b {
  min-width: 0;
  color: var(--text-primary);
  font-size: 12px;
  word-break: break-word;
}

.payload-block {
  margin-top: 14px;
}

.payload-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 8px;
}

.payload-title strong {
  color: var(--primary-light);
  font-size: 13px;
}

.payload-title span {
  color: var(--text-muted);
  font-size: 11px;
}

pre {
  max-height: 52vh;
  overflow: auto;
  padding: 14px;
  color: #bfe7ff;
  font-size: 11px;
  line-height: 1.55;
  white-space: pre-wrap;
  word-break: break-word;
}

@media (max-width: 1100px) {
  .query-panel {
    grid-template-columns: repeat(2, minmax(0, 1fr)) auto auto;
  }
}

@media (max-width: 760px) {
  .events-page {
    padding: 10px;
  }

  .query-panel {
    grid-template-columns: 1fr;
  }

  .drawer-mask {
    padding: 54px 10px 10px;
  }
}
</style>
