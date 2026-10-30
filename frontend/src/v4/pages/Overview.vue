<template>
  <section class="v-page">
    <header class="v-head">
      <div>
        <p class="v-eyebrow">SECURITY OPERATIONS</p>
        <h1>态势总览</h1>
        <p>最近 {{ windowLabel }} 的检测样本与未闭环 Incident。事件是告警聚合记录，1 条可代表多次命中；Incident 只统计未闭环项，两者不是同一计数单位。</p>
      </div>
      <div class="v-head-actions">
        <div class="v-tabs window-tabs">
          <button v-for="w in windows" :key="w.key" type="button" class="v-tab" :class="{ active: activeWindow === w.key }" @click="setWindow(w.key)">{{ w.label }}</button>
        </div>
        <button class="v-btn" type="button" :disabled="loading" @click="load">{{ loading ? '同步中…' : '刷新' }}</button>
      </div>
    </header>

    <div v-if="error" class="v-error">{{ error }}</div>

    <section class="v-grid c4">
      <article class="v-stat">
        <span class="v-stat-label"><i />未闭环 Incident</span>
        <strong class="v-stat-value" :class="openIncidents.length ? 'warning' : 'success'">{{ incidentsReady ? openIncidents.length : '—' }}</strong>
        <span class="v-stat-note">{{ incidentsReady ? `全部 ${totalIncidents} 条 · 高/严重 ${highRiskCount} 条` : '正在读取 Incident' }}</span>
        <RouterLink class="v-stat-link" to="/incidents">进入处置队列</RouterLink>
      </article>
      <article class="v-stat">
        <span class="v-stat-label"><i />窗口内命中</span>
        <strong class="v-stat-value">{{ eventsReady ? formatNumber(occurrences) : '—' }}</strong>
        <span class="v-stat-note">{{ eventsReady ? `${events.length} 条聚合记录 · 样本上限 500` : '正在读取检测样本' }}</span>
        <RouterLink class="v-stat-link" to="/events">查看事件</RouterLink>
      </article>
      <article class="v-stat">
        <span class="v-stat-label"><i />高 / 严重命中</span>
        <strong class="v-stat-value danger">{{ eventsReady ? formatNumber(highOccurrences) : '—' }}</strong>
        <span class="v-stat-note">{{ eventsReady ? `占窗口命中 ${percent(highOccurrences, occurrences)}` : '正在汇总严重度' }}</span>
      </article>
      <article class="v-stat">
        <span class="v-stat-label"><i />采集覆盖</span>
        <strong class="v-stat-value">{{ agentsReady ? `${onlineAgents}/${agents.length}` : '—' }}</strong>
        <span class="v-stat-note">{{ agentsReady ? `资产 ${assetTotal} 台 · 离线 ${agents.length - onlineAgents} 台` : '正在读取 Agent 心跳' }}</span>
        <RouterLink class="v-stat-link" to="/assets">资产运维</RouterLink>
      </article>
    </section>

    <section class="v-grid main-side">
      <article class="v-panel">
        <div class="v-panel-head">
          <div class="v-panel-title">检测活动趋势</div>
          <span class="v-panel-meta">{{ windowLabel }} · 按命中次数</span>
        </div>
        <div class="v-panel-body">
          <div v-if="eventsReady && trend.length" ref="chartEl" class="chart" />
          <div v-else class="v-empty"><div><strong>{{ eventsReady ? '窗口内没有检测样本' : '正在读取样本' }}</strong>{{ eventsReady ? '可切换更长的时间窗口。' : '' }}</div></div>
        </div>
      </article>

      <article class="v-panel">
        <div class="v-panel-head">
          <div class="v-panel-title">处置态势</div>
          <span class="v-panel-meta">等级取未闭环 Incident 的最高严重度</span>
        </div>
        <div class="v-panel-body posture">
          <div class="posture-grade" :data-tone="posture.tone">
            <span>当前态势</span>
            <strong>{{ incidentsReady ? posture.label : '—' }}</strong>
            <small>{{ incidentsReady ? posture.note : '正在读取' }}</small>
          </div>
          <div class="sev-bar">
            <i v-for="row in severityRows" :key="row.key" :style="{ width: row.percent + '%', background: row.color }" :title="`${row.label} ${row.count}`" />
          </div>
          <div class="sev-legend">
            <span v-for="row in severityRows" :key="row.key"><i :style="{ background: row.color }" />{{ row.label }} <b>{{ row.count }}</b></span>
          </div>
          <dl class="v-kv posture-facts">
            <dt>分诊</dt><dd>{{ countStatus(['new', 'open', 'triaged']) }}</dd>
            <dt>处理中</dt><dd>{{ countStatus(['processing']) }}</dd>
            <dt>闭环</dt><dd>{{ countStatus(['resolved', 'closed']) }}</dd>
          </dl>
        </div>
      </article>
    </section>

    <section class="v-grid c2">
      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">高频命中规则</div><span class="v-panel-meta">Top 8 · 按命中次数</span></div>
        <div class="v-panel-body"><div v-if="topRules.length" class="ranks"><div v-for="r in topRules" :key="r.key" class="rank"><span class="rank-label" :title="r.key">{{ r.label }}</span><span class="rank-track"><i :style="{ width: r.percent + '%' }" /></span><b>{{ formatNumber(r.count) }}</b></div></div><div v-else class="v-empty"><div><strong>{{ eventsReady ? '窗口内没有命中' : '正在读取样本' }}</strong></div></div></div>
      </article>
      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">情报源 → 受害服务器</div><span class="v-panel-meta">Top 8 · 按命中次数</span></div>
        <div class="v-panel-body"><div v-if="topPairs.length" class="ranks"><div v-for="r in topPairs" :key="r.key" class="rank"><span class="rank-label" :title="r.key">{{ r.label }}</span><span class="rank-track"><i :style="{ width: r.percent + '%' }" /></span><b>{{ formatNumber(r.count) }}</b></div></div><div v-else class="v-empty"><div><strong>{{ eventsReady ? '暂无可归因的情报源' : '正在读取样本' }}</strong></div></div></div>
      </article>
    </section>

    <section class="v-grid main-side">
      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">优先处置</div><RouterLink class="v-panel-meta" to="/incidents">全部 {{ totalIncidents }} 条</RouterLink></div>
        <div v-if="!incidentsReady" class="v-empty">正在加载 Incident</div>
        <div v-else-if="!activeQueue.length" class="v-empty"><div><strong>暂无待处置 Incident</strong>当前队列为空。</div></div>
        <div v-else class="queue">
          <RouterLink v-for="i in activeQueue" :key="i.id" class="queue-row" :to="{ path: '/incidents', query: { id: i.id } }">
            <span class="v-badge" :class="i.severity">{{ severityLabel(i.severity) }}</span>
            <span class="queue-main"><b>{{ i.title }}</b><small>{{ i.affectedAsset || i.entityId || '未绑定资产' }} · {{ shortTime(i.updatedAt || i.createdAt) }}</small></span>
            <span class="v-badge muted">{{ statusLabel(i.status) }}</span>
          </RouterLink>
        </div>
      </article>

      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">实时事件</div><RouterLink class="v-panel-meta" to="/events">事件检索</RouterLink></div>
        <div v-if="!recentEvents.length" class="v-empty"><div><strong>{{ eventsReady ? '暂无事件' : '正在读取' }}</strong></div></div>
        <div v-else class="stream">
          <RouterLink v-for="e in recentEvents" :key="e.event_uid" class="stream-row" :to="{ path: '/events', query: { uid: e.event_uid } }">
            <span class="dot" :data-sev="e.severity" />
            <time>{{ shortTime(e.event_at || e.timestamp) }}</time>
            <span class="stream-main"><b>{{ e.event_type || e.rule_id || '检测事件' }}</b><small>{{ e.source || 'unknown' }} · {{ e.asset_id || e.src_ip || '-' }}</small></span>
          </RouterLink>
        </div>
      </article>
    </section>
  </section>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from 'vue'
import { RouterLink } from 'vue-router'
import * as echarts from 'echarts/core'
import { BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

// Tree-shaken ECharts: only the bar chart, grid, tooltip and canvas renderer
// are shipped. The full build was ~1 MB in the overview route chunk.
echarts.use([BarChart, GridComponent, TooltipComponent, CanvasRenderer])
import { attackWorkbenchClient, opsClient } from '../../api/domain'
import { normalizeIncidents } from '../../domain/incidents'
import { severityLabel } from '../../domain/attack-labels'
import { formatChinaDateTime } from '../../shared/time'

const windows = [
  { key: '10m', label: '10 分钟', ms: 600000 },
  { key: '1h', label: '1 小时', ms: 3600000 },
  { key: '24h', label: '24 小时', ms: 86400000 },
  { key: '7d', label: '7 天', ms: 604800000 },
]

const activeWindow = ref('1h')
const loading = ref(false)
const error = ref('')
const events = ref([])
const incidents = ref({ items: [], total: 0 })
const agents = ref([])
const assetTotal = ref(0)
const ready = reactive({ events: false, incidents: false, agents: false })
const chartEl = ref(null)
let chart = null
let timer = null

const windowLabel = computed(() => windows.find((w) => w.key === activeWindow.value)?.label || '1 小时')
const eventsReady = computed(() => ready.events)
const incidentsReady = computed(() => ready.incidents)
const agentsReady = computed(() => ready.agents)

function unwrap(r) { return r?.data?.data ?? r?.data ?? r ?? {} }
function count(v) { const n = Number(v); return Number.isFinite(n) ? n : 0 }
function formatNumber(v) { return count(v).toLocaleString('zh-CN') }
function percent(a, b) { return b ? `${Math.round((a / b) * 100)}%` : '0%' }
function weight(e) { const n = Number(e?.count); return Number.isFinite(n) && n > 0 ? n : 1 }
function shortTime(v) { if (!v) return '-'; const d = new Date(v); if (Number.isNaN(d.getTime())) return '-'; return d.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) }

const occurrences = computed(() => events.value.reduce((s, e) => s + weight(e), 0))
const highOccurrences = computed(() => events.value.filter((e) => ['high', 'critical'].includes(String(e.severity))).reduce((s, e) => s + weight(e), 0))

const normalized = computed(() => normalizeIncidents(incidents.value.items || []))
const totalIncidents = computed(() => Number(incidents.value.total || normalized.value.length || 0))
const openIncidents = computed(() => normalized.value.filter((i) => ['new', 'open', 'triaged', 'processing', 'resolved'].includes(i.status) && i.status !== 'resolved'))
const highRiskCount = computed(() => openIncidents.value.filter((i) => ['critical', 'high'].includes(i.severity)).length)
const activeQueue = computed(() => normalized.value.filter((i) => ['new', 'open', 'triaged', 'processing'].includes(i.status)).slice(0, 6))

function countStatus(list) { return normalized.value.filter((i) => list.includes(i.status)).length }

const severityDefs = [
  { key: 'critical', label: '严重', color: '#dc2626' },
  { key: 'high', label: '高危', color: '#ea580c' },
  { key: 'medium', label: '中危', color: '#ca8a04' },
  { key: 'low', label: '低危', color: '#0e7490' },
]

const severityRows = computed(() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const i of openIncidents.value) {
    const k = String(i.severity || 'low')
    if (counts[k] !== undefined) counts[k] += 1
  }
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1
  return severityDefs.map((d) => ({ ...d, count: counts[d.key], percent: Math.round((counts[d.key] / total) * 100) }))
})

const posture = computed(() => {
  if (!openIncidents.value.length) return { tone: 'low', label: '无未闭环', note: '历史告警保留在事件检索中' }
  if (openIncidents.value.some((i) => i.severity === 'critical')) return { tone: 'critical', label: '严重', note: '存在严重级未闭环 Incident' }
  if (openIncidents.value.some((i) => i.severity === 'high')) return { tone: 'high', label: '高', note: '存在高危未闭环 Incident' }
  if (openIncidents.value.some((i) => i.severity === 'medium')) return { tone: 'medium', label: '中', note: '存在中危未闭环 Incident' }
  return { tone: 'low', label: '低', note: '未闭环 Incident 均为低危' }
})

function rank(map, limit, label = (k) => k) {
  const rows = [...map.entries()].map(([key, n]) => ({ key, label: label(key), count: n })).sort((a, b) => b.count - a.count).slice(0, limit)
  const max = rows[0]?.count || 1
  return rows.map((r) => ({ ...r, percent: Math.max(3, Math.round((r.count / max) * 100)) }))
}

const topRules = computed(() => {
  const m = new Map()
  for (const e of events.value) { const k = e.event_type || e.rule_id || '未知规则'; m.set(k, (m.get(k) || 0) + weight(e)) }
  return rank(m, 8)
})

function agentDisplayName(agent) {
  return agent?.display_name || agent?.hostname || agent?.agent_id || ''
}

const agentNameById = computed(() => {
  const map = new Map()
  for (const agent of agents.value) {
    const name = agentDisplayName(agent)
    if (agent?.agent_id && name) map.set(String(agent.agent_id), name)
  }
  return map
})

const agentNameByIP = computed(() => {
  const map = new Map()
  for (const agent of agents.value) {
    const name = agentDisplayName(agent)
    if (agent?.ip && name) map.set(String(agent.ip), name)
  }
  return map
})

const agentNameByHost = computed(() => {
  const map = new Map()
  for (const agent of agents.value) {
    const name = agentDisplayName(agent)
    if (!name) continue
    if (agent?.hostname) map.set(String(agent.hostname), name)
    if (agent?.display_name) map.set(String(agent.display_name), name)
    if (agent?.agent_id) map.set(String(agent.agent_id), name)
  }
  return map
})

function intelSourceLabel(category) {
  return ({ rasp: 'RASP', runtime: '运行时', log_audit: '日志', traffic: '流量' })[category] || '未知来源'
}

function resolveAgentName(event) {
  const payload = event.payload || {}
  return agentNameById.value.get(String(event.agent_id || payload.agent_id || '')) ||
    agentNameByHost.value.get(String(event.asset_id || event.hostname || payload.agent_display_name || payload.hostname || '')) ||
    event.agent_display_name || payload.agent_display_name || event.hostname || event.display_name || event.asset_id || ''
}

function pairSource(event, category) {
  if (['rasp', 'runtime', 'log_audit'].includes(category)) return intelSourceLabel(category)
  const src = String(event.src_ip || '')
  if (!src) return '未知来源'
  return agentNameByIP.value.get(src) || src
}

function pairDestination(event, category) {
  if (['rasp', 'runtime', 'log_audit'].includes(category)) {
    return resolveAgentName(event) || String(event.dst_ip || '') || '未知服务器'
  }
  const dst = String(event.dst_ip || '')
  if (dst) return agentNameByIP.value.get(dst) || dst
  return resolveAgentName(event) || '未知服务器'
}

const topPairs = computed(() => {
  const m = new Map()
  for (const e of events.value) {
    const category = String(e.component_category || e.category || e.persisted_category || '')
    const key = `${pairSource(e, category)} → ${pairDestination(e, category)}`
    m.set(key, (m.get(key) || 0) + weight(e))
  }
  return rank(m, 8)
})

const recentEvents = computed(() => [...events.value].sort((a, b) => new Date(b.event_at || b.timestamp) - new Date(a.event_at || a.timestamp)).slice(0, 8))
const onlineAgents = computed(() => agents.value.filter((a) => String(a.status || '').toLowerCase() === 'online').length)

function statusLabel(v) { return ({ new: '新发', open: '新发', triaged: '已分诊', processing: '处理中', resolved: '已解决', closed: '已关闭' })[v] || v || '-' }

const trend = computed(() => {
  const rows = events.value.filter((e) => e.event_at || e.timestamp)
  if (!rows.length) return []
  const sorted = [...rows].sort((a, b) => new Date(a.event_at || a.timestamp) - new Date(b.event_at || b.timestamp))
  const first = new Date(sorted[0].event_at || sorted[0].timestamp).getTime()
  const last = new Date(sorted[sorted.length - 1].event_at || sorted[sorted.length - 1].timestamp).getTime()
  const span = Math.max(last - first, 60000)
  const bucket = span > 43200000 ? 7200000 : span > 10800000 ? 1800000 : 300000
  const n = 12
  const start = last - bucket * (n - 1)
  const buckets = Array.from({ length: n }, (_, i) => ({ label: new Date(start + bucket * i).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }), critical: 0, high: 0, medium: 0, low: 0 }))
  for (const e of sorted) {
    const idx = Math.max(0, Math.min(n - 1, Math.floor((new Date(e.event_at || e.timestamp).getTime() - start) / bucket)))
    const k = String(e.severity || 'low')
    if (buckets[idx][k] !== undefined) buckets[idx][k] += weight(e)
  }
  return buckets
})

function render() {
  if (!chartEl.value || !trend.value.length) { chart?.dispose(); chart = null; return }
  if (!chart || chart.getDom() !== chartEl.value) { chart?.dispose(); chart = echarts.init(chartEl.value) }
  const s = getComputedStyle(document.documentElement)
  const line = s.getPropertyValue('--v-line').trim() || '#e5e8ec'
  const text = s.getPropertyValue('--v-ink-3').trim() || '#6b7280'
  chart.setOption({
    animationDuration: 300,
    grid: { left: 34, right: 8, top: 12, bottom: 26 },
    tooltip: { trigger: 'axis' },
    xAxis: { type: 'category', data: trend.value.map((r) => r.label), axisLine: { lineStyle: { color: line } }, axisTick: { show: false }, axisLabel: { color: text, fontSize: 10, interval: 1 } },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: line } }, axisLabel: { color: text, fontSize: 10 } },
    series: severityDefs.map((d) => ({ name: d.label, type: 'bar', stack: 't', barMaxWidth: 22, itemStyle: { color: d.color }, data: trend.value.map((r) => r[d.key]) })),
  }, true)
}

async function load(silent = false) {
  if (!silent) loading.value = true
  error.value = ''
  const ms = windows.find((w) => w.key === activeWindow.value)?.ms || 3600000
  const to = new Date()
  const from = new Date(to.getTime() - ms)
  const [e, i, a, ast] = await Promise.allSettled([
    opsClient.eventSample({ from: from.toISOString(), to: to.toISOString(), limit: 200 }),
    attackWorkbenchClient.incidents({ limit: 100, live: 1 }),
    opsClient.agents({ limit: 200 }),
    opsClient.assets({ limit: 200 }),
  ])
  if (e.status === 'fulfilled') { events.value = unwrap(e.value).items || []; ready.events = true } else { ready.events = true }
  if (i.status === 'fulfilled') { const p = unwrap(i.value); incidents.value = { items: p.items || [], total: p.total || 0 }; ready.incidents = true }
  if (a.status === 'fulfilled') { agents.value = unwrap(a.value).items || []; ready.agents = true }
  if (ast.status === 'fulfilled') assetTotal.value = Number(unwrap(ast.value).total || 0)
  const failed = [e, i, a, ast].filter((x) => x.status === 'rejected').length
  if (failed === 4) error.value = '所有数据接口不可达。'
  else if (failed) error.value = `${failed} 个接口读取失败，相关面板显示为未知。`
  if (!silent) loading.value = false
  await nextTick()
  render()
}

function setWindow(k) { if (activeWindow.value !== k) { activeWindow.value = k; load() } }

onMounted(() => { load(); timer = setInterval(() => load(true), 60000); window.addEventListener('resize', onResize) })
onUnmounted(() => { if (timer) clearInterval(timer); chart?.dispose(); window.removeEventListener('resize', onResize) })
function onResize() { chart?.resize() }
</script>

<style scoped>
.window-tabs { border-bottom: 0; }
.chart { width: 100%; height: 260px; }
.posture { display: grid; gap: 14px; }
.posture-grade { display: grid; gap: 2px; padding: 14px 16px; border-left: 3px solid var(--v-ink-4); background: var(--v-surface-2); border-radius: var(--v-radius-sm); }
.posture-grade[data-tone='critical'] { border-left-color: var(--v-critical); }
.posture-grade[data-tone='high'] { border-left-color: var(--v-high); }
.posture-grade[data-tone='medium'] { border-left-color: var(--v-medium); }
.posture-grade[data-tone='low'] { border-left-color: var(--v-success); }
.posture-grade span { color: var(--v-ink-3); font-size: 11px; }
.posture-grade strong { color: var(--v-ink); font-size: 20px; font-weight: 650; }
.posture-grade small { color: var(--v-ink-3); font-size: 11px; }
.sev-bar { display: flex; height: 6px; overflow: hidden; border-radius: 3px; background: var(--v-surface-3); }
.sev-bar i { display: block; height: 100%; }
.sev-legend { display: flex; flex-wrap: wrap; gap: 14px; color: var(--v-ink-3); font-size: 11px; }
.sev-legend span { display: inline-flex; align-items: center; gap: 5px; }
.sev-legend i { width: 7px; height: 7px; border-radius: 50%; }
.sev-legend b { color: var(--v-ink); font-family: var(--v-mono); }
.posture-facts { grid-template-columns: 110px minmax(0, 1fr); }

.ranks { display: grid; gap: 10px; }
.rank { display: grid; grid-template-columns: minmax(0, 1fr) 90px 48px; align-items: center; gap: 12px; }
.rank-label { overflow: hidden; color: var(--v-ink-2); font-size: 12px; text-overflow: ellipsis; white-space: nowrap; }
.rank-track { height: 5px; overflow: hidden; border-radius: 3px; background: var(--v-surface-3); }
.rank-track i { display: block; height: 100%; background: var(--v-accent); opacity: 0.7; }
.rank b { color: var(--v-ink); font-family: var(--v-mono); font-size: 11.5px; text-align: right; }

.queue { display: grid; }
.queue-row { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 12px; padding: 11px 18px; border-bottom: 1px solid var(--v-line); color: inherit; }
.queue-row:last-child { border-bottom: 0; }
.queue-row:hover { background: var(--v-surface-2); }
.queue-main { display: grid; gap: 2px; min-width: 0; }
.queue-main b { overflow: hidden; color: var(--v-ink); font-size: 12.5px; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
.queue-main small { color: var(--v-ink-3); font-size: 10.5px; }

.stream { display: grid; }
.stream-row { display: grid; grid-template-columns: 8px 62px minmax(0, 1fr); align-items: center; gap: 10px; padding: 9px 18px; border-bottom: 1px solid var(--v-line); color: inherit; }
.stream-row:last-child { border-bottom: 0; }
.stream-row:hover { background: var(--v-surface-2); }
.dot { width: 6px; height: 6px; border-radius: 50%; background: var(--v-low); }
.dot[data-sev='critical'] { background: var(--v-critical); }
.dot[data-sev='high'] { background: var(--v-high); }
.dot[data-sev='medium'] { background: var(--v-medium); }
.stream-row time { color: var(--v-ink-3); font-family: var(--v-mono); font-size: 10px; }
.stream-main { display: grid; gap: 1px; min-width: 0; }
.stream-main b { overflow: hidden; color: var(--v-ink); font-size: 11.5px; font-weight: 550; text-overflow: ellipsis; white-space: nowrap; }
.stream-main small { overflow: hidden; color: var(--v-ink-3); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }

@media (max-width: 720px) {
  .rank { grid-template-columns: minmax(0, 1fr) 48px; }
  .rank-track { display: none; }
}
</style>
