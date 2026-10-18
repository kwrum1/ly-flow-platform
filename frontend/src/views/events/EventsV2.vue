<template>
  <section class="events-v2">
    <header class="page-head">
      <div>
        <p>UNIFIED EVENTS</p>
        <h2>事件中心</h2>
      </div>
      <button type="button" :disabled="loading" @click="load(true)">刷新</button>
    </header>

    <form class="filter-bar" @submit.prevent="load(true)">
      <label><span>关键字</span><input v-model="filters.q" type="search" placeholder="IP、域名、哈希、进程、用户" /></label>
      <label><span>开始</span><input v-model="filters.from" type="datetime-local" /></label>
      <label><span>结束</span><input v-model="filters.to" type="datetime-local" /></label>
      <label><span>来源</span>
        <select v-model="filters.source">
          <option value="">全部</option>
          <option value="adapter.suricata">Suricata</option>
          <option value="dpi_engine">DPI</option>
          <option value="agent.runtime">主机运行时</option>
          <option value="agent.log_audit">日志审计</option>
          <option value="agent.rasp">RASP</option>
          <option value="adapter.wazuh">Wazuh</option>
          <option value="adapter.yara">YARA</option>
        </select>
      </label>
      <label><span>严重度</span>
        <select v-model="filters.severity">
          <option value="">全部</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
        </select>
      </label>
      <label><span>阶段</span>
        <select v-model="filters.stage">
          <option value="">全部</option>
          <option v-for="(label, key) in stageLabels" :key="key" :value="key">{{ label }}</option>
        </select>
      </label>
      <button type="submit" class="primary" :disabled="loading">{{ loading ? '查询中' : '查询' }}</button>
    </form>

    <div v-if="error" class="state-message">{{ error }}</div>

    <section class="table-panel">
      <div class="panel-head">
        <strong>事件列表</strong>
        <span>{{ items.length }} 条{{ nextCursor ? ' / 可继续加载' : '' }}</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>来源</th>
              <th>类型</th>
              <th>阶段</th>
              <th>严重度</th>
              <th>资产</th>
              <th>规则</th>
              <th>置信度</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading && items.length === 0"><td colspan="8" class="empty-cell">正在加载事件</td></tr>
            <tr v-else-if="items.length === 0"><td colspan="8" class="empty-cell">当前没有事件</td></tr>
            <tr v-for="event in items" :key="event.event_uid" class="event-row" @click="openDetail(event)">
              <td class="mono">{{ formatTime(event.event_at) }}</td>
              <td>{{ event.source || '-' }}</td>
              <td>{{ event.event_type || '-' }}</td>
              <td>{{ stageLabel(event.stage) }}</td>
              <td><span :class="['severity', event.severity]">{{ severityLabel(event.severity) }}</span></td>
              <td>{{ event.asset_id || '-' }}</td>
              <td>{{ event.rule_id || '-' }}</td>
              <td>{{ formatConfidence(event.confidence) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="pager">
        <button type="button" :disabled="loading || !nextCursor" @click="load(false)">加载更多</button>
      </div>
    </section>

    <div v-if="selected" class="drawer-scrim" @click.self="closeDetail">
      <aside class="detail-drawer" aria-label="事件详情">
        <header>
          <div><p>EVENT DETAIL</p><h3>{{ selected.event_uid }}</h3></div>
          <button type="button" aria-label="关闭详情" @click="closeDetail">×</button>
        </header>
        <div v-if="detailLoading" class="empty">正在加载详情</div>
        <div v-else-if="detailError" class="state-message">{{ detailError }}</div>
        <template v-else>
          <div class="detail-grid">
            <div><span>时间</span><b>{{ formatTime(selected.event_at) }}</b></div>
            <div><span>来源</span><b>{{ selected.source || '-' }}</b></div>
            <div><span>类型</span><b>{{ selected.event_type || '-' }}</b></div>
            <div><span>阶段</span><b>{{ stageLabel(selected.stage) }}</b></div>
            <div><span>严重度</span><b>{{ severityLabel(selected.severity) }}</b></div>
            <div><span>置信度</span><b>{{ formatConfidence(selected.confidence) }}</b></div>
            <div><span>资产</span><b>{{ selected.asset_id || '-' }}</b></div>
            <div><span>用户</span><b>{{ selected.user_id || '-' }}</b></div>
            <div><span>进程</span><b>{{ selected.process_exe || '-' }}</b></div>
            <div><span>文件哈希</span><b class="mono">{{ selected.file_hash || '-' }}</b></div>
            <div><span>源地址</span><b>{{ selected.src_ip || '-' }}{{ selected.src_port ? `:${selected.src_port}` : '' }}</b></div>
            <div><span>目的地址</span><b>{{ selected.dst_ip || '-' }}{{ selected.dst_port ? `:${selected.dst_port}` : '' }}</b></div>
            <div><span>规则</span><b>{{ selected.rule_id || '-' }}</b></div>
            <div><span>规则来源</span><b>{{ selected.rule_source || '-' }}</b></div>
            <div><span>技术</span><b>{{ selected.technique_id || '-' }}</b></div>
            <div><span>战术</span><b>{{ selected.tactic_id || '-' }}</b></div>
          </div>

          <section class="detail-section">
            <h4>证据</h4>
            <div v-if="selected.evidence?.length" class="evidence-list">
              <div v-for="(item, index) in selected.evidence" :key="`${item.type}-${index}`" class="evidence-row">
                <span class="evidence-type">{{ item.type }}</span>
                <div><b>{{ item.ref }}</b><small v-if="item.sha256">SHA-256 {{ item.sha256 }}</small></div>
                <span>{{ item.size ? `${item.size} B` : '-' }}</span>
              </div>
            </div>
            <div v-else class="empty">暂无证据</div>
          </section>

          <section class="detail-section">
            <h4>原始载荷</h4>
            <pre v-if="prettyPayload" class="payload">{{ prettyPayload }}</pre>
            <div v-else class="empty">暂无载荷</div>
          </section>

          <section class="detail-section">
            <h4>原始来源</h4>
            <div class="detail-grid">
              <div><span>Schema</span><b>{{ selected.raw?.native_schema || '-' }}</b></div>
              <div><span>事件 ID</span><b class="mono">{{ selected.raw?.native_event_id || '-' }}</b></div>
              <div><span>SHA-256</span><b class="mono">{{ selected.raw?.payload_sha256 || '-' }}</b></div>
            </div>
          </section>
        </template>
      </aside>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { eventsV2Client } from '../../api/v2'
import { severityLabel, stageLabel, stageLabels } from '../../domain/attack-labels'

const PAGE_SIZE = 50
const route = useRoute()
const loading = ref(false)
const error = ref('')
const items = ref([])
const nextCursor = ref('')
const selected = ref(null)
const detailLoading = ref(false)
const detailError = ref('')

const filters = reactive({ q: '', from: '', to: '', source: '', severity: '', stage: '' })

const prettyPayload = computed(() => {
  if (!selected.value?.payload) return ''
  try {
    return JSON.stringify(selected.value.payload, null, 2)
  } catch {
    return String(selected.value.payload)
  }
})

function pad(value) {
  return String(value).padStart(2, '0')
}

function toLocalInput(date) {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function toRFC3339(value) {
  if (!value) return ''
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '' : date.toISOString()
}

function formatTime(value) {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false })
}

function formatConfidence(value) {
  if (value === undefined || value === null) return '-'
  return `${Math.round(Number(value) * 100)}%`
}

function unwrap(response) {
  return response?.data?.data ?? response?.data ?? {}
}

async function load(reset) {
  loading.value = true
  error.value = ''
  if (reset) {
    items.value = []
    nextCursor.value = ''
  }
  const params = { limit: PAGE_SIZE }
  if (filters.q) params.q = filters.q
  if (filters.from) params.from = toRFC3339(filters.from)
  if (filters.to) params.to = toRFC3339(filters.to)
  if (filters.source) params.source = filters.source
  if (filters.severity) params.severity = filters.severity
  if (filters.stage) params.stage = filters.stage
  if (!reset && nextCursor.value) params.cursor = nextCursor.value
  try {
    const page = unwrap(await eventsV2Client.list(params))
    const batch = Array.isArray(page.items) ? page.items : []
    items.value = reset ? batch : [...items.value, ...batch]
    nextCursor.value = page.next_cursor || ''
  } catch (cause) {
    error.value = '事件查询失败，请检查时间范围和网络'
  } finally {
    loading.value = false
  }
}

async function openDetail(event) {
  selected.value = { ...event }
  detailLoading.value = true
  detailError.value = ''
  try {
    selected.value = unwrap(await eventsV2Client.detail(event.event_uid))
  } catch (cause) {
    detailError.value = '事件详情加载失败'
  } finally {
    detailLoading.value = false
  }
}

function closeDetail() {
  selected.value = null
  detailError.value = ''
}

onMounted(() => {
  filters.q = String(route.query.q || '')
  const to = new Date()
  const from = new Date(to.getTime() - 24 * 60 * 60 * 1000)
  filters.to = toLocalInput(to)
  filters.from = toLocalInput(from)
  load(true)
})
</script>

<style scoped>
.events-v2 { display: grid; gap: 14px; color: #1f2a37; }
.page-head { display: flex; align-items: flex-end; justify-content: space-between; }
.page-head p { margin: 0 0 2px; color: #98a2b3; font-size: 10px; letter-spacing: .08em; }
.page-head h2 { margin: 0; font-size: 20px; font-weight: 600; }
.page-head button, .filter-bar button { height: 32px; padding: 0 14px; border: 1px solid #d8e1ec; border-radius: 6px; background: #fff; color: #475467; cursor: pointer; }
.page-head button:hover, .filter-bar button:hover { border-color: #1976d2; color: #1268bd; }
.filter-bar { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 10px; padding: 12px; border: 1px solid #d8e1ec; border-radius: 8px; background: #fff; }
.filter-bar label { display: grid; gap: 4px; }
.filter-bar span { color: #667085; font-size: 11px; }
.filter-bar input, .filter-bar select { height: 30px; padding: 0 8px; border: 1px solid #d8e1ec; border-radius: 5px; background: #fff; color: #1f2a37; font-size: 12px; }
.filter-bar .primary { border-color: #1976d2; background: #1976d2; color: #fff; }
.state-message { padding: 10px 12px; border: 1px solid #f3c2c2; border-radius: 6px; background: #fff5f5; color: #c43838; font-size: 13px; }
.table-panel { padding: 12px 14px; border: 1px solid #d8e1ec; border-radius: 8px; background: #fff; }
.panel-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
.panel-head strong { font-size: 14px; }
.panel-head span { color: #98a2b3; font-size: 11px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th, td { padding: 8px 10px; border-bottom: 1px solid #eef2f6; text-align: left; white-space: nowrap; }
th { background: #f8fafc; color: #667085; font-weight: 500; }
.event-row { cursor: pointer; }
.event-row:hover { background: #f7fbff; }
.empty-cell { padding: 24px; color: #98a2b3; text-align: center; }
.mono { font-family: Consolas, monospace; color: #475467; }
.severity { padding: 2px 6px; border-radius: 4px; background: #f1f5f9; font-size: 11px; }
.severity.critical { background: #fdecec; color: #c43838; }
.severity.high { background: #fff3e6; color: #ad6800; }
.severity.medium { background: #fff8db; color: #8a6d00; }
.severity.low { background: #eef7f1; color: #168a55; }
.pager { display: flex; justify-content: center; padding-top: 10px; }
.pager button { height: 30px; padding: 0 14px; border: 1px solid #d8e1ec; border-radius: 6px; background: #fff; color: #475467; cursor: pointer; }
.drawer-scrim { position: fixed; inset: 0; z-index: 100; display: flex; justify-content: flex-end; background: rgba(15, 23, 42, .28); }
.detail-drawer { display: flex; width: min(680px, 92vw); height: 100%; flex-direction: column; overflow-y: auto; background: #fff; box-shadow: -8px 0 24px rgba(15, 23, 42, .12); }
.detail-drawer > header { position: sticky; top: 0; z-index: 1; display: flex; align-items: flex-start; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid #e6ebf1; background: #fff; }
.detail-drawer header p { margin: 0 0 2px; color: #98a2b3; font-size: 10px; letter-spacing: .08em; }
.detail-drawer header h3 { margin: 0; font-size: 16px; word-break: break-all; }
.detail-drawer header button { border: 0; background: transparent; color: #667085; font-size: 22px; cursor: pointer; }
.detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 16px; padding: 16px 20px; }
.detail-grid div { min-width: 0; }
.detail-grid span { display: block; color: #98a2b3; font-size: 10px; }
.detail-grid b { display: block; overflow-wrap: anywhere; font-size: 12px; font-weight: 500; }
.detail-section { padding: 0 20px 16px; }
.detail-section h4 { margin: 0 0 8px; font-size: 13px; }
.evidence-list { display: grid; gap: 8px; }
.evidence-row { display: grid; grid-template-columns: 70px minmax(0, 1fr) 70px; gap: 10px; align-items: center; padding: 8px 10px; border: 1px solid #e6ebf1; border-radius: 6px; }
.evidence-type { padding: 2px 6px; border-radius: 4px; background: #e8f3ff; color: #1268bd; font-size: 10px; text-align: center; }
.evidence-row b { display: block; overflow: hidden; font-size: 12px; text-overflow: ellipsis; white-space: nowrap; }
.evidence-row small { display: block; overflow: hidden; color: #98a2b3; font-family: Consolas, monospace; font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.evidence-row > span:last-child { color: #667085; font-size: 11px; text-align: right; }
.payload { max-height: 320px; overflow: auto; margin: 0; padding: 12px; border-radius: 6px; background: #0f172a; color: #dbeafe; font-family: Consolas, monospace; font-size: 11px; line-height: 1.5; }
.empty { padding: 18px 0; color: #98a2b3; font-size: 12px; text-align: center; }
@media (max-width: 760px) { .detail-grid { grid-template-columns: 1fr; } }
</style>
