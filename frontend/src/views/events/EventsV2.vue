<template>
  <section class="sx-page events-page">
    <header class="sx-page-head">
      <div>
        <p class="sx-kicker">UNIFIED EVENT EXPLORER</p>
        <h2 class="sx-title">事件中心</h2>
        <p class="sx-subtitle">统一检索流量、运行时、应用防护与日志审计告警；默认最近 10 分钟，历史保留至少 30 天。</p>
      </div>
      <div class="sx-head-actions">
        <span class="sx-live"><i />LIVE</span>
        <button class="sx-btn" type="button" :disabled="loading" @click="load(true)">刷新</button>
      </div>
    </header>

    <section class="event-stats">
      <article class="event-stat">
        <span>当前结果</span>
        <strong>{{ formatNumber(items.length) }}</strong>
        <small>{{ total > items.length ? `共 ${formatNumber(total)} 条 · 可继续加载` : '当前时间窗已加载完' }}</small>
      </article>
      <article class="event-stat">
        <span>高危 / 严重</span>
        <strong class="danger">{{ formatNumber(highRiskCount) }}</strong>
        <small>当前样本</small>
      </article>
      <article class="event-stat">
        <span>来源数</span>
        <strong>{{ sourceCount }}</strong>
        <small>已完成归一化</small>
      </article>
      <article class="event-stat">
        <span>阶段数</span>
        <strong>{{ stageCount }}</strong>
        <small>来自事件阶段字段</small>
      </article>
    </section>

    <form class="sx-filter" @submit.prevent="load(true)">
      <label class="wide"><span>关键字</span><input v-model="filters.q" class="sx-input" type="search" placeholder="IP、域名、哈希、进程、用户" /></label>
      <label><span>时间范围</span>
        <select v-model="windowPreset" class="sx-select" @change="applyWindowPreset()">
          <option value="10m">最近 10 分钟</option>
          <option value="1h">最近 1 小时</option>
          <option value="24h">最近 24 小时</option>
          <option value="30d">最近 30 天</option>
        </select>
      </label>
      <label><span>开始</span><input v-model="filters.from" class="sx-input" type="datetime-local" /></label>
      <label><span>结束</span><input v-model="filters.to" class="sx-input" type="datetime-local" /></label>
      <label><span>分类</span>
        <select v-model="filters.source" class="sx-select">
          <option value="">全部分类</option>
          <option value="traffic">流量检测</option>
          <option value="runtime">主机运行时</option>
          <option value="rasp">应用防护</option>
          <option value="log_audit">日志审计</option>
        </select>
      </label>
      <label><span>严重度</span>
        <select v-model="filters.severity" class="sx-select">
          <option value="">全部</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
        </select>
      </label>
      <label><span>阶段</span>
        <select v-model="filters.stage" class="sx-select">
          <option value="">全部</option>
          <option v-for="(label, key) in stageLabels" :key="key" :value="key">{{ label }}</option>
        </select>
      </label>
      <button type="submit" class="sx-btn primary" :disabled="loading">{{ loading ? '查询中…' : '查询' }}</button>
      <button type="button" class="sx-btn ghost" :disabled="loading" @click="resetFilters">重置</button>
    </form>

    <div v-if="error" class="sx-error">{{ error }}</div>

    <section class="sx-panel">
      <div class="sx-panel-head">
        <div class="sx-panel-title">事件列表</div>
        <span class="sx-panel-meta">{{ items.length }}{{ total > items.length ? ` / 共 ${total}` : '' }} 条 · 最近 10 分钟起</span>
      </div>
      <div class="sx-table-wrap sx-scroll">
        <table class="sx-table event-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>严重度</th>
              <th>来源</th>
              <th>事件类型</th>
              <th>阶段</th>
              <th>资产</th>
              <th>规则</th>
              <th>置信度</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading && items.length === 0"><td colspan="8" class="sx-empty">正在加载事件…</td></tr>
            <tr v-else-if="items.length === 0"><td colspan="8" class="sx-empty"><div><strong>当前时间窗没有检测事件</strong>默认查看最近 10 分钟；可切换 1 小时、24 小时或 30 天。</div></td></tr>
            <tr v-for="event in items" :key="event.event_uid" class="event-row" @click="openDetail(event)">
              <td class="sx-mono">{{ formatTime(event.event_at) }}</td>
              <td><span class="sx-badge" :class="event.severity">{{ severityLabel(event.severity) }}</span></td>
              <td><span class="source-chip">{{ event.source || '-' }}</span></td>
              <td>{{ event.event_type || '-' }}</td>
              <td><span class="stage-chip" :class="event.stage">{{ stageLabel(event.stage) }}</span></td>
              <td>{{ event.asset_id || '-' }}</td>
              <td class="rule-cell">{{ event.rule_id || '-' }}</td>
              <td>{{ formatConfidence(event.confidence) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="event-pager">
        <span>{{ loading ? '同步中' : nextCursor ? '还有更多事件' : '已经到底' }}</span>
        <button class="sx-btn" type="button" :disabled="loading || !nextCursor" @click="load(false)">加载更多</button>
      </div>
    </section>

    <Teleport to="body">
      <div v-if="selected" class="sx-drawer-scrim" @click.self="closeDetail">
        <aside class="sx-drawer" aria-label="事件详情">
        <header class="sx-drawer-head">
          <div>
            <p class="sx-kicker">EVENT DETAIL</p>
            <h3 class="drawer-title">{{ selected.event_uid }}</h3>
          </div>
          <button class="sx-icon-btn" type="button" aria-label="关闭详情" @click="closeDetail">×</button>
        </header>
        <div class="sx-drawer-body">
          <div v-if="detailLoading" class="sx-empty">正在加载事件详情…</div>
          <div v-else-if="detailError" class="sx-error">{{ detailError }}</div>
          <template v-else>
            <div class="event-detail-hero">
              <div class="event-detail-score">
                <span>SEVERITY</span>
                <strong :class="selected.severity">{{ severityLabel(selected.severity) }}</strong>
              </div>
              <div class="event-detail-summary">
                <b>{{ selected.rule_id || selected.event_type || '检测事件' }}</b>
                <p>{{ selected.rule_source || selected.source || '未知来源' }} · {{ formatTime(selected.event_at) }} · 置信度 {{ formatConfidence(selected.confidence) }}</p>
              </div>
            </div>

            <section class="detail-section">
              <h4>检测上下文</h4>
              <div class="detail-grid">
                <div><span>来源</span><b>{{ selected.source || '-' }}</b></div>
                <div><span>类型</span><b>{{ selected.event_type || '-' }}</b></div>
                <div><span>阶段</span><b>{{ stageLabel(selected.stage) }}</b></div>
                <div><span>资产</span><b>{{ selected.asset_id || '-' }}</b></div>
                <div><span>用户</span><b>{{ selected.user_id || '-' }}</b></div>
                <div><span>进程</span><b>{{ selected.process_exe || '-' }}</b></div>
                <div><span>文件哈希</span><b class="sx-mono">{{ selected.file_hash || '-' }}</b></div>
                <div><span>战术 / 技术</span><b>{{ selected.tactic_id || '-' }} / {{ selected.technique_id || '-' }}</b></div>
                <div><span>源地址</span><b class="sx-mono">{{ selected.src_ip || '-' }}{{ selected.src_port ? `:${selected.src_port}` : '' }}</b></div>
                <div><span>目的地址</span><b class="sx-mono">{{ selected.dst_ip || '-' }}{{ selected.dst_port ? `:${selected.dst_port}` : '' }}</b></div>
              </div>
            </section>

            <section class="detail-section">
              <h4>证据引用 <span>{{ selected.evidence?.length || 0 }}</span></h4>
              <div v-if="selected.evidence?.length" class="evidence-list">
                <div v-for="(item, index) in selected.evidence" :key="`${item.type}-${index}`" class="evidence-row">
                  <span class="sx-badge info">{{ item.type }}</span>
                  <div><b>{{ item.ref }}</b><small v-if="item.sha256" class="sx-mono">SHA-256 {{ item.sha256 }}</small></div>
                  <span>{{ item.size ? `${item.size} B` : '-' }}</span>
                </div>
              </div>
              <div v-else class="sx-empty">该事件没有附加证据引用。</div>
            </section>

            <section class="detail-section">
              <h4>原始载荷</h4>
              <pre v-if="prettyPayload" class="payload sx-scroll">{{ prettyPayload }}</pre>
              <div v-else class="sx-empty">无载荷字段。</div>
            </section>

            <section class="detail-section">
              <h4>原始来源</h4>
              <div class="detail-grid">
                <div><span>Schema</span><b>{{ selected.raw?.native_schema || '-' }}</b></div>
                <div><span>事件 ID</span><b class="sx-mono">{{ selected.raw?.native_event_id || '-' }}</b></div>
                <div><span>Payload SHA-256</span><b class="sx-mono">{{ selected.raw?.payload_sha256 || '-' }}</b></div>
              </div>
            </section>
          </template>
          </div>
        </aside>
      </div>
    </Teleport>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { attackWorkbenchClient } from '../../api/domain'
import { severityLabel, stageLabel, stageLabels } from '../../domain/attack-labels'

const PAGE_SIZE = 50
const route = useRoute()
const loading = ref(false)
const error = ref('')
const items = ref([])
const total = ref(0)
const nextCursor = ref('')
const selected = ref(null)
const detailLoading = ref(false)
const detailError = ref('')
const windowPreset = ref('10m')
const filters = reactive({ q: '', from: '', to: '', source: '', severity: '', stage: '' })
const highRiskCount = computed(() => items.value.filter((item) => ['critical', 'high'].includes(String(item.severity || '').toLowerCase())).length)
const sourceCount = computed(() => new Set(items.value.map((item) => item.source).filter(Boolean)).size)
const stageCount = computed(() => new Set(items.value.map((item) => item.stage).filter(Boolean)).size)
const prettyPayload = computed(() => {
  if (!selected.value?.payload) return ''
  try { return JSON.stringify(selected.value.payload, null, 2) } catch { return String(selected.value.payload) }
})

function pad(value) { return String(value).padStart(2, '0') }
function toLocalInput(date) { return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}` }
function toRFC3339(value) { if (!value) return ''; const date = new Date(value); return Number.isNaN(date.getTime()) ? '' : date.toISOString() }
function formatTime(value) { if (!value) return '-'; const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false }) }
function formatConfidence(value) { if (value === undefined || value === null || value === '') return '-'; return `${Math.round(Number(value) * 100)}%` }
function formatNumber(value) { return Number(value || 0).toLocaleString('zh-CN') }
function unwrap(response) { return response?.data?.data ?? response?.data ?? response ?? {} }

async function load(reset) {
  loading.value = true
  error.value = ''
  if (reset) { items.value = []; total.value = 0; nextCursor.value = '' }
  const params = { limit: PAGE_SIZE, offset: reset ? 0 : items.value.length }
  if (filters.q) params.q = filters.q
  if (filters.from) params.from = toRFC3339(filters.from)
  if (filters.to) params.to = toRFC3339(filters.to)
  if (filters.source) params.category = filters.source
  if (filters.severity) params.severity = filters.severity
  if (filters.stage) params.stage = filters.stage
  try {
    const page = unwrap(await attackWorkbenchClient.events(params))
    const batch = Array.isArray(page.items) ? page.items : []
    items.value = reset ? batch : [...items.value, ...batch]
    total.value = Number(page.total ?? items.value.length) || items.value.length
    nextCursor.value = items.value.length < total.value ? 'more' : ''
  } catch {
    error.value = '事件查询失败，请检查时间范围和后端连接。'
  } finally {
    loading.value = false
  }
}

async function openDetail(event) {
  selected.value = { ...event }
  detailLoading.value = false
  detailError.value = ''
}

function closeDetail() { selected.value = null; detailError.value = '' }

function resetFilters() {
  Object.assign(filters, { q: '', from: '', to: '', source: '', severity: '', stage: '' })
  windowPreset.value = '10m'
  applyDefaultWindow()
  load(true)
}

function applyDefaultWindow() {
  applyWindowPreset('10m')
}

function applyWindowPreset(value = windowPreset.value) {
  const minutes = { '10m': 10, '1h': 60, '24h': 24 * 60, '30d': 30 * 24 * 60 }[value] || 10
  const to = new Date()
  const from = new Date(to.getTime() - minutes * 60 * 1000)
  windowPreset.value = ['10m', '1h', '24h', '30d'].includes(value) ? value : '10m'
  filters.to = toLocalInput(to)
  filters.from = toLocalInput(from)
}

onMounted(async () => {
  filters.q = String(route.query.q || '')
  filters.stage = String(route.query.stage || '')
  applyDefaultWindow()
  await load(true)
  const uid = String(route.params.uid || route.query.uid || '')
  if (uid) {
    let match = items.value.find((item) => item.event_uid === uid)
    if (!match) {
      filters.q = uid
      await load(true)
      match = items.value.find((item) => item.event_uid === uid)
    }
    if (match) openDetail(match)
    else error.value = `未找到事件 ${uid}，链接可能已归档或超出保留期。`
  }
})
</script>

<style scoped>
.events-page { min-height: 100%; grid-template-rows: auto auto auto minmax(0, 1fr); }
.events-page > .sx-panel { display: flex; min-height: 0; flex-direction: column; }
.events-page .sx-table-wrap { flex: 1; }

.event-stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
}

.event-stat {
  padding: 11px 14px;
  border: 1px solid var(--sx-line);
  border-radius: var(--sx-radius-sm);
  background: var(--sx-surface);
  box-shadow: var(--sx-shadow-sm);
}

.event-stat span { color: var(--sx-text-3); font-size: 12px; }
.event-stat strong { display: block; margin-top: 4px; color: var(--sx-text); font-size: 22px; font-weight: 750; letter-spacing: -0.04em; }
.event-stat strong.danger { color: var(--sx-danger); }
.event-stat small { display: block; margin-top: 1px; color: var(--sx-text-3); font-size: 11px; }

.event-table { min-width: 980px; }
.event-row { cursor: pointer; }
.rule-cell { max-width: 250px; overflow: hidden; text-overflow: ellipsis; }
.source-chip { display: inline-block; max-width: 150px; overflow: hidden; padding: 2px 6px; border: 1px solid var(--sx-accent-line); border-radius: 4px; background: var(--sx-accent-soft); color: var(--sx-accent); font-size: 11px; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; vertical-align: middle; }
.stage-chip { display: inline-block; padding: 2px 6px; border-radius: 4px; background: var(--sx-surface-3); color: var(--sx-text-2); font-size: 11px; }
.event-pager { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 9px 14px; border-top: 1px solid var(--sx-line-soft); color: var(--sx-text-3); font-size: 12px; }

.drawer-title { margin: 3px 0 0; color: var(--sx-text); font-size: 17px; font-weight: 720; word-break: break-all; }
.event-detail-hero { display: flex; align-items: center; gap: 14px; margin-bottom: 16px; padding: 12px; border: 1px solid var(--sx-line-soft); border-radius: var(--sx-radius); background: var(--sx-surface-2); }
.event-detail-score { min-width: 72px; padding-right: 14px; border-right: 1px solid var(--sx-line); text-align: center; }
.event-detail-score span { display: block; color: var(--sx-text-3); font-size: 12px; letter-spacing: 0.1em; }
.event-detail-score strong { display: block; margin-top: 4px; font-size: 17px; }
.event-detail-score strong.critical { color: var(--sx-critical); }
.event-detail-score strong.high { color: var(--sx-high); }
.event-detail-score strong.medium { color: var(--sx-medium); }
.event-detail-score strong.low { color: var(--sx-success); }
.event-detail-summary { min-width: 0; }
.event-detail-summary b { display: block; color: var(--sx-text); font-size: 12px; }
.event-detail-summary p { margin: 4px 0 0; color: var(--sx-text-3); font-size: 12px; }

.detail-section { margin-top: 16px; }
.detail-section h4 { display: flex; align-items: center; gap: 7px; margin: 0 0 8px; color: var(--sx-text); font-size: 12px; font-weight: 700; }
.detail-section h4 span { padding: 1px 5px; border-radius: 3px; background: var(--sx-accent-soft); color: var(--sx-accent); font-size: 11px; }
.detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 14px; }
.detail-grid div { min-width: 0; padding: 7px 9px; border-radius: 5px; background: var(--sx-surface-2); }
.detail-grid span { display: block; color: var(--sx-text-3); font-size: 11px; }
.detail-grid b { display: block; overflow-wrap: anywhere; margin-top: 2px; color: var(--sx-text); font-size: 11px; font-weight: 600; }
.evidence-list { display: grid; gap: 6px; }
.evidence-row { display: grid; grid-template-columns: 58px minmax(0, 1fr) 58px; align-items: center; gap: 8px; padding: 7px 9px; border: 1px solid var(--sx-line-soft); border-radius: 5px; }
.evidence-row b { display: block; overflow: hidden; color: var(--sx-text); font-size: 12px; text-overflow: ellipsis; white-space: nowrap; }
.evidence-row small { display: block; overflow: hidden; margin-top: 1px; color: var(--sx-text-3); font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.evidence-row > span:last-child { color: var(--sx-text-3); font-size: 11px; text-align: right; }
.payload { max-height: 300px; margin: 0; padding: 11px; overflow: auto; border: 1px solid #193b5b; border-radius: 6px; background: #071a2d; color: #c7e7ff; font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px; line-height: 1.55; }

@media (max-width: 900px) {
  .event-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .detail-grid { grid-template-columns: 1fr; }
}
</style>
