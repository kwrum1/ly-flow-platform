<template>
  <section class="sx-page ov-page">
    <header class="sx-page-head">
      <div>
        <p class="sx-kicker">SECURITY OPERATIONS · LIVE POSTURE</p>
        <h2 class="sx-title">运营总览</h2>
        <p class="sx-subtitle">
          基于最近 {{ windowLabel }} 的检测样本与未闭环 Incident 聚合。统计口径：事件为告警聚合记录（1 条记录可代表多次命中），
          Incident 仅统计未闭环项；两者不是同一计数单位。
        </p>
      </div>
      <div class="sx-head-actions">
        <div class="ov-window" role="group" aria-label="时间窗口">
          <button
            v-for="item in windows"
            :key="item.key"
            type="button"
            class="ov-window-btn"
            :class="{ active: item.key === activeWindow }"
            @click="setWindow(item.key)"
          >{{ item.label }}</button>
        </div>
        <button class="sx-btn" type="button" :disabled="loading" @click="load">
          {{ loading ? '同步中…' : '刷新' }}
        </button>
      </div>
    </header>

    <div v-if="error" class="sx-error">{{ error }}</div>

    <!-- KPI -->
    <section class="ov-kpis">
      <article class="sx-metric ov-kpi">
        <span class="sx-metric-label"><i />未闭环 Incident</span>
        <strong class="sx-metric-value" :class="openIncidentCount ? 'warning' : 'success'">{{ incidentsReady ? formatNumber(openIncidentCount) : '—' }}</strong>
        <span class="sx-metric-note">
          {{ incidentsReady ? `共 ${formatNumber(totalIncidents)} 条，其中高/严重 ${formatNumber(openHighRiskCount)} 条` : '正在读取 Incident' }}
        </span>
        <RouterLink class="ov-kpi-link" to="/incidents">进入处置队列 →</RouterLink>
      </article>

      <article class="sx-metric ov-kpi">
        <span class="sx-metric-label"><i />窗口内命中</span>
        <strong class="sx-metric-value">{{ eventsReady ? formatNumber(occurrenceTotal) : '—' }}</strong>
        <span class="sx-metric-note">
          {{ eventsReady ? `来自 ${formatNumber(eventSampleCount)} 条聚合记录 · 样本上限 500` : '正在读取检测样本' }}
        </span>
        <RouterLink class="ov-kpi-link" to="/events">查看事件中心 →</RouterLink>
      </article>

      <article class="sx-metric ov-kpi">
        <span class="sx-metric-label"><i />高危命中</span>
        <strong class="sx-metric-value danger">{{ eventsReady ? formatNumber(highOccurrence) : '—' }}</strong>
        <span class="sx-metric-note">
          {{ eventsReady ? `占窗口命中 ${percent(highOccurrence, occurrenceTotal)}` : '正在汇总严重度' }}
        </span>
        <RouterLink class="ov-kpi-link" to="/events">按严重度筛选 →</RouterLink>
      </article>

      <article class="sx-metric ov-kpi">
        <span class="sx-metric-label"><i />采集覆盖</span>
        <strong class="sx-metric-value">{{ agentsReady ? `${formatNumber(onlineAgents)}/${formatNumber(agentTotal)}` : '—' }}</strong>
        <span class="sx-metric-note">
          {{ agentsReady ? `资产 ${formatNumber(assetTotal)} · 离线 Agent ${formatNumber(offlineAgents)}` : '正在读取 Agent 心跳' }}
        </span>
        <RouterLink class="ov-kpi-link" to="/assets">资产与 Agent →</RouterLink>
      </article>
    </section>

    <!-- posture + attack stages -->
    <section class="ov-main">
      <article class="sx-panel ov-posture">
        <div class="sx-panel-head">
          <div class="sx-panel-title">处置态势</div>
          <span class="sx-panel-meta">规则：等级取未闭环 Incident 的最高严重度</span>
        </div>
        <div class="sx-panel-body">
          <div class="ov-posture-top">
            <div class="ov-radar" :data-tone="posture.tone" aria-hidden="true">
              <span class="ov-radar-ring" />
              <span class="ov-radar-ring r2" />
              <span class="ov-radar-ring r3" />
              <span class="ov-radar-cross" />
              <span class="ov-radar-sweep" />
              <i
                v-for="(blip, index) in blips"
                :key="index"
                :style="{ left: blip.x + '%', top: blip.y + '%', background: blip.color }"
              />
            </div>
            <div class="ov-posture-grade" :data-tone="posture.tone">
              <span>当前态势</span>
              <strong>{{ incidentsReady ? posture.label : '计算中' }}</strong>
              <small>{{ incidentsReady ? posture.note : '正在读取未闭环 Incident' }}</small>
            </div>
            <div class="ov-posture-facts">
              <div><span>待分诊</span><b>{{ incidentsReady ? formatNumber(countByStatus('new') + countByStatus('open')) : '—' }}</b></div>
              <div><span>处理中</span><b>{{ incidentsReady ? formatNumber(countByStatus('triaged') + countByStatus('processing')) : '—' }}</b></div>
              <div><span>已解决</span><b>{{ incidentsReady ? formatNumber(countByStatus('resolved')) : '—' }}</b></div>
              <div><span>已闭环</span><b>{{ incidentsReady ? formatNumber(countByStatus('closed')) : '—' }}</b></div>
            </div>
          </div>

          <div class="ov-sev-bar" :class="{ empty: !incidentsReady || !openIncidentCount }">
            <i
              v-for="row in severityRows"
              :key="row.key"
              :style="{ width: row.percent + '%', background: row.color }"
              :title="`${row.label} ${row.count}`"
            />
          </div>
          <div class="ov-sev-legend">
            <span v-for="row in severityRows" :key="row.key">
              <i :style="{ background: row.color }" />{{ row.label }} <b>{{ row.count }}</b>
            </span>
            <em v-if="!openIncidentCount">当前没有未闭环 Incident</em>
          </div>
        </div>
      </article>

      <article class="sx-panel ov-attack">
        <div class="sx-panel-head">
          <div class="sx-panel-title">ATT&CK 阶段覆盖</div>
          <span class="sx-panel-meta">{{ incidentsReady ? `来自 ${formatNumber(totalIncidents)} 条 Incident 的阶段证据` : '加载中' }}</span>
        </div>
        <div class="sx-panel-body">
          <div class="sx-stage-ribbon">
            <button
              v-for="stage in stageRows"
              :key="stage.key"
              class="sx-stage"
              :class="{ active: stage.count > 0 }"
              type="button"
              @click="openStage(stage.key)"
            >
              <span>{{ stage.label }}</span>
              <strong>{{ stage.count }}</strong>
              <i :style="{ width: `${stage.percent}%` }" />
            </button>
          </div>
        </div>
      </article>
    </section>

    <!-- trend + sources -->
    <section class="ov-grid-2">
      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">检测活动趋势</div>
          <span class="sx-panel-meta">{{ windowLabel }} · {{ formatNumber(eventSampleCount) }} 条样本 · 按命中次数</span>
        </div>
        <div class="sx-panel-body">
          <div v-if="eventsReady && trendRows.length" ref="trendElement" class="ov-chart" />
          <div v-else class="sx-empty">
            <div><strong>{{ eventsReady ? '窗口内没有检测样本' : '正在读取检测样本' }}</strong>{{ eventsReady ? '可切换更长的时间窗口。' : '事件接口返回后绘制。' }}</div>
          </div>
        </div>
      </article>

      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">数据来源覆盖</div>
          <span class="sx-panel-meta">{{ sourcesReady ? `${sourceRows.length} 个来源` : '加载中' }}</span>
        </div>
        <div class="sx-panel-body">
          <div v-if="sourcesReady && sourceRows.length" class="ov-ranks">
            <div v-for="row in sourceRows" :key="row.key" class="ov-rank">
              <span class="ov-rank-label">{{ row.label }}</span>
              <span class="ov-rank-track"><i :style="{ width: row.percent + '%' }" /></span>
              <b>{{ formatNumber(row.count) }}</b>
            </div>
          </div>
          <div v-else class="sx-empty"><div><strong>{{ sourcesReady ? '暂无来源数据' : '正在读取来源覆盖' }}</strong>{{ sourcesReady ? '' : '统一告警聚合返回后展示。' }}</div></div>
        </div>
      </article>
    </section>

    <!-- top rules + top pairs -->
    <section class="ov-grid-2">
      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">高频命中规则</div>
          <span class="sx-panel-meta">按命中次数 · Top 8</span>
        </div>
        <div class="sx-panel-body">
          <div v-if="eventsReady && topRules.length" class="ov-ranks">
            <div v-for="row in topRules" :key="row.key" class="ov-rank">
              <span class="ov-rank-label" :title="row.key">{{ row.label }}</span>
              <span class="ov-rank-track"><i :style="{ width: row.percent + '%' }" /></span>
              <b>{{ formatNumber(row.count) }}</b>
            </div>
          </div>
          <div v-else class="sx-empty"><div><strong>{{ eventsReady ? '窗口内没有命中' : '正在读取检测样本' }}</strong></div></div>
        </div>
      </article>

      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">热源 → 目标</div>
          <span class="sx-panel-meta">按命中次数 · Top 8</span>
        </div>
        <div class="sx-panel-body">
          <div v-if="eventsReady && topPairs.length" class="ov-ranks">
            <div v-for="row in topPairs" :key="row.key" class="ov-rank">
              <span class="ov-rank-label sx-mono" :title="row.key">{{ row.label }}</span>
              <span class="ov-rank-track"><i :style="{ width: row.percent + '%' }" /></span>
              <b>{{ formatNumber(row.count) }}</b>
            </div>
          </div>
          <div v-else class="sx-empty"><div><strong>{{ eventsReady ? '暂无地址对' : '正在读取检测样本' }}</strong></div></div>
        </div>
      </article>
    </section>

    <!-- incident queue + live stream -->
    <section class="ov-grid-2 wide-left">
      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">优先处置</div>
          <RouterLink class="sx-panel-meta" to="/incidents">全部 {{ formatNumber(totalIncidents) }} 条 →</RouterLink>
        </div>
        <div v-if="!incidentsReady" class="sx-empty"><div><strong>正在加载 Incident</strong>列表返回后立即展示处置队列。</div></div>
        <div v-else-if="activeIncidents.length" class="ov-queue">
          <RouterLink
            v-for="incident in activeIncidents"
            :key="incident.id"
            class="ov-queue-row"
            :to="{ path: '/incidents', query: { id: incident.id } }"
          >
            <span class="sx-badge" :class="incident.severity">{{ severityLabel(incident.severity) }}</span>
            <span class="ov-queue-main">
              <b>{{ incident.title }}</b>
              <small>{{ incident.affectedAsset || incident.entityId || '未绑定资产' }} · {{ formatTime(incident.updatedAt || incident.createdAt) }}</small>
            </span>
            <span class="ov-queue-stages">
              <em v-for="stage in incident.stages.slice(0, 3)" :key="stage.id">{{ stage.name }}</em>
            </span>
            <span class="ov-queue-status">{{ statusLabel(incident.status) }}</span>
          </RouterLink>
        </div>
        <div v-else class="sx-empty"><div><strong>暂无待处置 Incident</strong>当前队列为空。</div></div>
      </article>

      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">实时事件流</div>
          <RouterLink class="sx-panel-meta" to="/events">事件中心 →</RouterLink>
        </div>
        <div v-if="eventsReady && recentEvents.length" class="ov-stream">
          <RouterLink
            v-for="event in recentEvents"
            :key="event.event_uid"
            class="ov-stream-row"
            :to="{ path: '/events', query: { uid: event.event_uid } }"
          >
            <span class="ov-stream-dot" :data-sev="event.severity" />
            <time>{{ formatShortTime(event.timestamp || event.event_at) }}</time>
            <span class="ov-stream-main">
              <b>{{ event.rule_name || event.rule_id || event.event_type || '检测事件' }}</b>
              <small>{{ event.source || event.source_engine || 'unknown' }} · {{ event.hostname || event.agent_id || event.src_ip || '未绑定资产' }}</small>
            </span>
            <span class="sx-badge" :class="event.severity">{{ severityLabel(event.severity) }}</span>
          </RouterLink>
        </div>
        <div v-else class="sx-empty"><div><strong>{{ eventsReady ? '暂无实时事件' : '正在读取实时事件' }}</strong></div></div>
      </article>
    </section>

    <!-- engines + data quality -->
    <section class="ov-grid-2">
      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">检测引擎</div>
          <RouterLink class="sx-panel-meta" to="/engines">引擎健康 →</RouterLink>
        </div>
        <div class="sx-panel-body">
          <div v-if="enginesReady && engineRows.length" class="ov-engines">
            <div v-for="engine in engineRows" :key="engine.key" class="ov-engine">
              <span class="ov-engine-mark">{{ engine.short }}</span>
              <span class="ov-engine-copy"><b>{{ engine.label }}</b><small>{{ engine.note }}</small></span>
              <span class="sx-state" :data-state="engine.state">{{ engine.status }}</span>
            </div>
          </div>
          <div v-else class="sx-empty"><div><strong>{{ enginesReady ? '暂无引擎心跳' : '正在读取引擎健康' }}</strong></div></div>
        </div>
      </article>

      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">数据质量</div>
          <RouterLink class="sx-panel-meta" to="/data-quality">完整报告 →</RouterLink>
        </div>
        <div class="sx-panel-body">
          <div class="ov-quality">
            <div><span>五元组完整率</span><b :class="quality.missingRate > 0 ? 'warn' : 'ok'">{{ quality.completeRate }}</b><small>样本 {{ quality.sample }} 条</small></div>
            <div><span>端口未知率</span><b :class="quality.portUnknownRate > 0 ? 'warn' : 'ok'">{{ quality.portUnknownRate }}</b><small>dst_port 为空或 0</small></div>
            <div><span>可查询跨度</span><b>{{ quality.span }}</b><small>最早样本至今</small></div>
            <div><span>时间源</span><b :class="quality.timeTone">{{ quality.timeSource }}</b><small>{{ quality.timeNote }}</small></div>
          </div>
          <p class="ov-quality-note">
            完整率只统计本次样本；缺失值不会以 0 补齐，端口 0 视为未知。
          </p>
        </div>
      </article>
    </section>
  </section>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import * as echarts from 'echarts'
import { attackWorkbenchClient, assetAgentClient, opsClient, overviewClient, ruleClient } from '../../api/domain'
import { normalizeIncidents } from '../../domain/incidents'
import { severityLabel } from '../../domain/attack-labels'
import { formatChinaDateTime } from '../../shared/time'

const router = useRouter()

const windows = [
  { key: '10m', label: '10 分钟', ms: 10 * 60 * 1000 },
  { key: '1h', label: '1 小时', ms: 60 * 60 * 1000 },
  { key: '24h', label: '24 小时', ms: 24 * 60 * 60 * 1000 },
  { key: '7d', label: '7 天', ms: 7 * 24 * 60 * 60 * 1000 },
]

const activeWindow = ref('1h')
const loading = ref(false)
const error = ref('')

const events = ref({ items: [], total: 0, window: null })
const incidents = ref({ items: [], total: 0 })
const unified = ref({})
const stats = ref({})
const assetStats = ref({})
const agents = ref({ items: [] })
const engines = ref({ items: [] })
const ruleStats = ref({})
const components = ref(null)
const systemTime = ref(null)

const ready = reactive({
  events: false,
  incidents: false,
  unified: false,
  assets: false,
  agents: false,
  engines: false,
  rules: false,
  components: false,
  time: false,
})

const trendElement = ref(null)
let trendChart = null
let pollTimer = null

const stageDefinitions = [
  ['detection', '检测命中'],
  ['recon', '侦察'],
  ['initial_access', '初始访问'],
  ['execution', '执行'],
  ['persistence', '持久化'],
  ['privilege_escalation', '提权'],
  ['lateral_movement', '横向移动'],
  ['command_and_control', '命令控制'],
  ['exfiltration', '外传'],
  ['impact', '影响'],
]

const severityDefinitions = [
  { key: 'critical', label: '严重', color: '#b42318' },
  { key: 'high', label: '高危', color: '#b5470b' },
  { key: 'medium', label: '中危', color: '#8a6100' },
  { key: 'low', label: '低危', color: '#0b6e8a' },
]

const windowLabel = computed(() => windows.find((item) => item.key === activeWindow.value)?.label || '1 小时')

function setWindow(key) {
  if (activeWindow.value === key) return
  activeWindow.value = key
  load()
}

/* ---------------- derived: events ---------------- */

const eventItems = computed(() => (Array.isArray(events.value.items) ? events.value.items : []))
const eventSampleCount = computed(() => eventItems.value.length)
const occurrence = (item) => {
  const n = Number(item?.count)
  return Number.isFinite(n) && n > 0 ? n : 1
}
const occurrenceTotal = computed(() => eventItems.value.reduce((sum, item) => sum + occurrence(item), 0))
const highOccurrence = computed(() => eventItems.value
  .filter((item) => ['critical', 'high'].includes(String(item.severity || '').toLowerCase()))
  .reduce((sum, item) => sum + occurrence(item), 0))

const eventsReady = computed(() => ready.events)

const recentEvents = computed(() => [...eventItems.value]
  .sort((a, b) => timestampMs(b) - timestampMs(a))
  .slice(0, 8))

function rankRows(map, limit, labeler = (key) => key) {
  const entries = [...map.entries()]
    .map(([key, count]) => ({ key, label: labeler(key), count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit)
  const max = entries[0]?.count || 1
  return entries.map((row) => ({ ...row, percent: Math.max(3, Math.round((row.count / max) * 100)) }))
}

const topRules = computed(() => {
  const map = new Map()
  for (const item of eventItems.value) {
    const key = item.rule_name || item.rule_id || item.event_type || '未知规则'
    map.set(key, (map.get(key) || 0) + occurrence(item))
  }
  return rankRows(map, 8, (key) => String(key))
})

const topPairs = computed(() => {
  const map = new Map()
  for (const item of eventItems.value) {
    const src = item.src_ip || '(空)'
    const dst = item.dst_ip || '(空)'
    const key = `${src} → ${dst}`
    map.set(key, (map.get(key) || 0) + occurrence(item))
  }
  return rankRows(map, 8, (key) => key)
})

/* ---------------- derived: incidents ---------------- */

const normalizedIncidents = computed(() => normalizeIncidents(incidents.value.items || []))
const totalIncidents = computed(() => Number(incidents.value.total || normalizedIncidents.value.length || 0))
const openStatuses = ['new', 'open', 'triaged', 'processing', 'resolved']
const openIncidentList = computed(() => normalizedIncidents.value.filter((item) => openStatuses.includes(item.status)))
const openIncidentCount = computed(() => openIncidentList.value.filter((item) => item.status !== 'resolved').length)
const openHighRiskCount = computed(() => openIncidentList.value.filter((item) => ['critical', 'high'].includes(item.severity)).length)
const incidentsReady = computed(() => ready.incidents)

const activeIncidents = computed(() => normalizedIncidents.value
  .filter((item) => ['new', 'open', 'triaged', 'processing'].includes(item.status))
  .slice(0, 6))

function countByStatus(status) {
  return normalizedIncidents.value.filter((item) => item.status === status).length
}

const severityRows = computed(() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const item of openIncidentList.value) {
    if (item.status === 'resolved') continue
    const key = String(item.severity || 'low').toLowerCase()
    if (counts[key] !== undefined) counts[key] += 1
  }
  const total = Object.values(counts).reduce((sum, n) => sum + n, 0) || 1
  return severityDefinitions.map((item) => ({
    ...item,
    count: counts[item.key] || 0,
    percent: Math.round(((counts[item.key] || 0) / total) * 100),
  }))
})

const severityColor = (key) => severityDefinitions.find((item) => item.key === key)?.color || '#22d3ee'

/**
 * Radar blips are a deterministic visualisation of the open-incident
 * severity mix. They carry no information beyond `severityRows`, and the
 * accessible text lives in the legend, not in this decoration.
 */
const blips = computed(() => {
  const out = []
  severityRows.value.forEach((row, rowIndex) => {
    const count = Math.min(row.count, 6)
    for (let i = 0; i < count; i += 1) {
      const angle = rowIndex * 1.35 + i * 1.1
      const radius = 7 + i * 5 + rowIndex * 3
      out.push({
        x: 50 + Math.cos(angle) * radius,
        y: 50 + Math.sin(angle) * radius,
        color: severityColor(row.key),
      })
    }
  })
  return out
})

const posture = computed(() => {
  const list = openIncidentList.value.filter((item) => item.status !== 'resolved')
  if (!list.length) return { tone: 'low', label: '无未闭环', note: '没有未闭环 Incident，历史告警保留在事件中心' }
  if (list.some((item) => item.severity === 'critical')) return { tone: 'critical', label: '严重', note: '存在严重级未闭环 Incident，立即进入处置' }
  if (list.some((item) => item.severity === 'high')) return { tone: 'high', label: '高', note: '存在高危未闭环 Incident，优先核查证据链' }
  if (list.some((item) => item.severity === 'medium')) return { tone: 'medium', label: '中', note: '存在中危未闭环 Incident，按队列处置' }
  return { tone: 'low', label: '低', note: '未闭环 Incident 均为低危' }
})

const stageRows = computed(() => {
  const counts = Object.fromEntries(stageDefinitions.map(([key]) => [key, 0]))
  for (const incident of normalizedIncidents.value) {
    for (const stage of incident.stages || []) {
      const key = normalizeStageKey(stage.stageKey || stage.name || stage.tactic)
      if (key && counts[key] !== undefined) counts[key] += 1
    }
  }
  const max = Math.max(1, ...Object.values(counts))
  return stageDefinitions.map(([key, label]) => ({
    key,
    label,
    count: counts[key],
    percent: counts[key] ? Math.max(8, Math.round((counts[key] / max) * 100)) : 0,
  }))
})

function openStage(key) {
  if (!key) return
  router.push({ path: '/events', query: { stage: key } })
}

/* ---------------- derived: coverage ---------------- */

const agentsReady = computed(() => ready.agents)
const agentList = computed(() => agents.value.items || [])
const agentTotal = computed(() => agentList.value.length)
const onlineAgents = computed(() => agentList.value.filter((a) => String(a.status || '').toLowerCase() === 'online').length)
const offlineAgents = computed(() => Math.max(0, agentTotal.value - onlineAgents.value))
const assetTotal = computed(() => Number(assetStats.value.total ?? stats.value.total_assets ?? 0))

const sourceRows = computed(() => {
  // Derive sources from the same windowed sample so this panel cannot
  // disagree with the KPI above it. Platform-wide /unified/stats is only
  // used as a fallback when the sample is empty.
  const fromSample = new Map()
  for (const item of eventItems.value) {
    const key = String(item.source || item.source_engine || 'unknown')
    fromSample.set(key, (fromSample.get(key) || 0) + occurrence(item))
  }
  if (fromSample.size) return rankRows(fromSample, 6, sourceLabel)

  const source = unified.value.by_source || {}
  const map = new Map()
  for (const [key, count] of Object.entries(source)) map.set(key, Number(count || 0))
  return rankRows(map, 6, sourceLabel)
})
const sourcesReady = computed(() => ready.unified)

const engineRows = computed(() => {
  const groups = new Map()
  for (const item of engines.value.items || []) {
    const key = item.engine || 'unknown'
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(item)
  }
  return [...groups.entries()].map(([key, items]) => {
    const item = items[0] || {}
    const offline = String(item.agent_status || '').toLowerCase() === 'offline'
    const installed = item.installed !== false
    const running = Boolean(item.running) && !offline
    return {
      key,
      short: ({ 'security-engine': 'LY', lyprobe: 'LP', suricata: 'SU', wazuh: 'WA', yara: 'YA', rasp: 'RA' })[key] || key.slice(0, 2).toUpperCase(),
      label: ({ 'security-engine': 'LyFlow 安全引擎', lyprobe: 'LyFlow 探针', suricata: 'Suricata', wazuh: 'Wazuh', yara: 'YARA', rasp: 'OpenRASP' })[key] || key,
      state: !installed ? 'not_configured' : offline ? 'failed' : running ? 'online' : 'degraded',
      status: !installed ? '未安装' : offline ? 'Agent 离线' : running ? '运行中' : '未运行',
      note: [item.rule_pack_version || '', items.length > 1 ? `${items.length} 个探针` : item.hostname || ''].filter(Boolean).join(' · ') || '无心跳详情',
    }
  })
})
const enginesReady = computed(() => ready.engines)

/* ---------------- derived: data quality ---------------- */

const quality = computed(() => {
  const items = eventItems.value
  const sample = items.length
  const missing = items.filter((item) => !item.src_ip || !item.dst_ip).length
  const portUnknown = items.filter((item) => item.dst_port === 0 || item.dst_port === null || item.dst_port === undefined || item.dst_port === '').length
  const earliest = items
    .map((item) => item.first_seen || item.event_at || item.timestamp)
    .filter(Boolean)
    .sort()[0]
  const spanDays = earliest ? Math.max(0, (Date.now() - new Date(earliest).getTime()) / 86400000) : null
  const source = systemTime.value?.source || 'unknown'
  const offset = Number(systemTime.value?.offset_ms)
  return {
    sample,
    completeRate: sample ? `${Math.round(((sample - missing) / sample) * 100)}%` : '—',
    missingRate: sample ? missing : 0,
    portUnknownRate: sample ? `${Math.round((portUnknown / sample) * 100)}%` : '—',
    span: spanDays === null ? '—' : `${spanDays.toFixed(1)} 天`,
    timeSource: source === 'ntp' ? 'NTP' : source === 'manual' ? '手动' : source === 'unknown' ? '未知' : source,
    timeNote: Number.isFinite(offset) ? `偏移 ${Math.round(offset / 1000)}s` : '未读取',
    timeTone: source === 'ntp' || source === 'system' ? 'ok' : source === 'unknown' ? 'muted' : 'warn',
  }
})

/* ---------------- trend chart ---------------- */

const trendRows = computed(() => buildTrendRows(eventItems.value))

function renderTrend() {
  if (!trendElement.value || !trendRows.value.length) {
    trendChart?.dispose()
    trendChart = null
    return
  }
  if (!trendChart || trendChart.getDom() !== trendElement.value) {
    trendChart?.dispose()
    trendChart = echarts.init(trendElement.value)
  }
  const styles = getComputedStyle(document.documentElement)
  const text = styles.getPropertyValue('--lyf-ink-3').trim() || '#6d7684'
  const line = styles.getPropertyValue('--lyf-line').trim() || '#e3ded4'
  const surface = styles.getPropertyValue('--lyf-surface').trim() || '#fff'
  trendChart.setOption({
    animationDuration: 420,
    grid: { left: 36, right: 12, top: 14, bottom: 26 },
    tooltip: {
      trigger: 'axis',
      backgroundColor: surface,
      borderColor: line,
      borderWidth: 1,
      textStyle: { color: styles.getPropertyValue('--lyf-ink').trim() || '#14181d', fontSize: 11 },
    },
    legend: { show: false },
    xAxis: {
      type: 'category',
      data: trendRows.value.map((row) => row.label),
      axisLine: { lineStyle: { color: line } },
      axisTick: { show: false },
      axisLabel: { color: text, fontSize: 9, interval: 1 },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      splitLine: { lineStyle: { color: line } },
      axisLabel: { color: text, fontSize: 9 },
    },
    series: severityDefinitions.map((item) => ({
      name: item.label,
      type: 'bar',
      stack: 'total',
      barMaxWidth: 18,
      itemStyle: { color: item.color, borderRadius: item.key === 'low' ? [2, 2, 0, 0] : 0 },
      data: trendRows.value.map((row) => row[item.key]),
    })),
  }, true)
}

/* ---------------- helpers ---------------- */

function unwrap(response) {
  return response?.data?.data ?? response?.data ?? response ?? {}
}

function number(value) {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : 0
}

function formatNumber(value) {
  return number(value).toLocaleString('zh-CN')
}

function percent(part, whole) {
  if (!whole) return '0%'
  return `${Math.round((part / whole) * 100)}%`
}

function timestampMs(item) {
  const value = item?.timestamp || item?.event_at || item?.first_seen || item?.created_at
  const parsed = new Date(value).getTime()
  return Number.isFinite(parsed) ? parsed : 0
}

function formatTime(value) {
  return value ? formatChinaDateTime(value) : '-'
}

function formatShortTime(value) {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function statusLabel(value) {
  return ({ new: '新发', open: '新发', triaged: '已分诊', processing: '处理中', resolved: '已解决', closed: '已关闭', suppressed: '已抑制' })[value] || value || '-'
}

function sourceLabel(value) {
  return ({ 'g5-real-agent': 'Agent 采集', wazuh: 'Wazuh', suricata: 'Suricata', 'ly-security-engine': '安全引擎', sshd: 'SSH 日志', rasp: 'RASP', runtime: '主机运行时', log_audit: '日志审计', traffic: '流量检测', yara: 'YARA', dpi_engine: '历史流量', lyprobe: 'LyFlow 探针' })[value] || value || '未知'
}

function normalizeStageKey(value) {
  const key = String(value || '').toLowerCase().replace(/[\s-]+/g, '_')
  return stageDefinitions.some(([candidate]) => candidate === key) ? key : ''
}

function buildTrendRows(items) {
  const rows = items.filter((item) => timestampMs(item) > 0)
  if (!rows.length) return []
  const sorted = [...rows].sort((a, b) => timestampMs(a) - timestampMs(b))
  const first = timestampMs(sorted[0])
  const last = timestampMs(sorted[sorted.length - 1])
  const span = Math.max(last - first, 60 * 1000)
  const bucketMs = span > 12 * 60 * 60 * 1000 ? 2 * 60 * 60 * 1000 : span > 3 * 60 * 60 * 1000 ? 30 * 60 * 1000 : 5 * 60 * 1000
  const bucketCount = 12
  const start = last - bucketMs * (bucketCount - 1)
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    label: new Date(start + bucketMs * index).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }),
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  }))
  for (const item of sorted) {
    const index = Math.max(0, Math.min(bucketCount - 1, Math.floor((timestampMs(item) - start) / bucketMs)))
    const key = String(item.severity || 'low').toLowerCase()
    if (buckets[index][key] !== undefined) buckets[index][key] += occurrence(item)
  }
  return buckets
}

/* ---------------- loading ---------------- */

async function load(silent = false) {
  if (!silent) loading.value = true
  error.value = ''
  const ms = windows.find((item) => item.key === activeWindow.value)?.ms || 3600000
  const to = new Date()
  const from = new Date(to.getTime() - ms)

  const jobs = [
    opsClient.eventSample({ from: from.toISOString(), to: to.toISOString(), limit: 500 })
      .then((value) => { events.value = normalizePage(value); ready.events = true })
      .catch(() => { ready.events = false }),
    attackWorkbenchClient.incidents({ limit: 100 })
      .then((value) => { incidents.value = normalizePage(value); ready.incidents = true })
      .catch(() => { ready.incidents = false }),
    attackWorkbenchClient.stats()
      .then((value) => { unified.value = unwrap(value); ready.unified = true })
      .catch(() => { ready.unified = false }),
    overviewClient.stats()
      .then((value) => { stats.value = unwrap(value) })
      .catch(() => {}),
    assetAgentClient.assetStats()
      .then((value) => { assetStats.value = unwrap(value); ready.assets = true })
      .catch(() => { ready.assets = false }),
    assetAgentClient.agents({ limit: 200 })
      .then((value) => { agents.value = normalizePage(value); ready.agents = true })
      .catch(() => { ready.agents = false }),
    assetAgentClient.engineHealth()
      .then((value) => { engines.value = unwrap(value); ready.engines = true })
      .catch(() => { ready.engines = false }),
    ruleClient.stats()
      .then((value) => { ruleStats.value = unwrap(value); ready.rules = true })
      .catch(() => { ready.rules = false }),
    opsClient.components()
      .then((value) => { components.value = value; ready.components = true })
      .catch(() => { ready.components = false }),
    opsClient.systemTime()
      .then((value) => { systemTime.value = value; ready.time = true })
      .catch(() => { ready.time = false }),
  ]

  const results = await Promise.allSettled(jobs)
  const failed = results.filter((item) => item.status === 'rejected').length
  if (failed && failed === results.length) error.value = '所有数据接口均不可达，请检查网络或登录状态。'
  else if (failed) error.value = `${failed} 个数据接口读取失败，相关面板显示为未就绪而不是 0。`

  if (!silent) loading.value = false
  await nextTick()
  renderTrend()
}
function normalizePage(response) {
  const payload = unwrap(response)
  const items = Array.isArray(payload) ? payload : (payload.items || payload.events || [])
  return { ...(Array.isArray(payload) ? {} : payload), items: Array.isArray(items) ? items : [], total: payload.total ?? (Array.isArray(items) ? items.length : 0) }
}

function onResize() {
  trendChart?.resize()
}

onMounted(() => {
  load()
  pollTimer = setInterval(() => load(true), 60000)
  window.addEventListener('resize', onResize)
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
  trendChart?.dispose()
  trendChart = null
  window.removeEventListener('resize', onResize)
})
</script>

<style scoped>
.ov-page { gap: 14px; }

.ov-window {
  display: inline-flex;
  overflow: hidden;
  border: var(--lyf-hairline-strong);
  border-radius: var(--lyf-radius-sm);
  background: var(--lyf-surface);
}

.ov-window-btn {
  height: 32px;
  padding: 0 11px;
  border: 0;
  border-right: var(--lyf-hairline);
  background: transparent;
  color: var(--lyf-ink-3);
  font: inherit;
  font-size: 11.5px;
  font-weight: 500;
  cursor: pointer;
}

.ov-window-btn:last-child { border-right: 0; }
.ov-window-btn:hover { color: var(--lyf-accent); background: var(--lyf-accent-soft); }
.ov-window-btn.active { background: var(--lyf-ink); color: var(--lyf-surface); font-weight: 600; }
[data-theme='dark'] .ov-window-btn.active { background: var(--lyf-accent); color: #06120f; }

/* KPI */
.ov-kpis {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.ov-kpi { display: flex; flex-direction: column; }
.ov-kpi-link {
  margin-top: auto;
  padding-top: 10px;
  color: var(--lyf-accent);
  font-size: 11px;
  font-weight: 550;
  text-decoration: none;
}
.ov-kpi-link:hover { text-decoration: underline; }

/* posture */
.ov-main { display: grid; grid-template-columns: minmax(0, 6fr) minmax(0, 6fr); gap: 12px; }
.ov-posture .sx-panel-body { display: grid; gap: 14px; }

.ov-posture-top { display: flex; gap: 14px; align-items: stretch; }

/* HUD radar: decoration for the severity mix, not a data source. */
.ov-radar {
  position: relative;
  width: 96px;
  height: 96px;
  flex: 0 0 96px;
  align-self: center;
  overflow: hidden;
  border: 1px solid var(--lyf-accent-line);
  border-radius: 50%;
  background:
    radial-gradient(circle, rgb(34 211 238 / 12%), transparent 70%),
    var(--lyf-surface-2);
  box-shadow: inset 0 0 24px -12px var(--lyf-accent);
}

.ov-radar[data-tone='critical'] { border-color: var(--lyf-critical-line); box-shadow: inset 0 0 24px -12px var(--lyf-critical); }
.ov-radar[data-tone='high'] { border-color: var(--lyf-high-line); }
.ov-radar[data-tone='medium'] { border-color: var(--lyf-medium-line); }

.ov-radar-ring { position: absolute; inset: 8%; border: 1px solid rgb(34 211 238 / 18%); border-radius: 50%; }
.ov-radar-ring.r2 { inset: 26%; }
.ov-radar-ring.r3 { inset: 42%; }

.ov-radar-cross {
  position: absolute;
  inset: 0;
  background:
    linear-gradient(90deg, transparent 49.5%, rgb(34 211 238 / 20%) 49.5%, rgb(34 211 238 / 20%) 50.5%, transparent 50.5%),
    linear-gradient(0deg, transparent 49.5%, rgb(34 211 238 / 20%) 49.5%, rgb(34 211 238 / 20%) 50.5%, transparent 50.5%);
}

.ov-radar-sweep {
  position: absolute;
  inset: 0;
  border-radius: 50%;
  background: conic-gradient(from 0deg, rgb(34 211 238 / 42%), transparent 28%);
  animation: sx-sweep 5s linear infinite;
}

.ov-radar i {
  position: absolute;
  width: 5px;
  height: 5px;
  margin: -2.5px 0 0 -2.5px;
  border-radius: 50%;
  box-shadow: 0 0 9px currentColor;
}

.ov-posture-grade {
  display: grid;
  align-content: center;
  gap: 2px;
  min-width: 128px;
  padding: 10px 14px;
  border-left: 3px solid var(--lyf-ink-3);
  background: var(--lyf-surface-2);
}

.ov-posture-grade[data-tone='critical'] { border-left-color: var(--lyf-critical); }
.ov-posture-grade[data-tone='high'] { border-left-color: var(--lyf-high); }
.ov-posture-grade[data-tone='medium'] { border-left-color: var(--lyf-medium); }
.ov-posture-grade[data-tone='low'] { border-left-color: var(--lyf-success); }

.ov-posture-grade span { color: var(--lyf-ink-3); font-size: 10.5px; }
.ov-posture-grade strong { font-size: 20px; font-weight: 650; letter-spacing: -0.02em; }
.ov-posture-grade small { color: var(--lyf-ink-3); font-size: 10.5px; line-height: 1.45; }

.ov-posture-facts { display: grid; flex: 1; min-width: 132px; grid-template-columns: repeat(2, minmax(46px, 1fr)); gap: 8px 14px; align-content: center; }
.ov-posture-facts div { display: flex; min-width: 0; flex-direction: column; gap: 1px; }
.ov-posture-facts span { color: var(--lyf-ink-3); font-size: 10.5px; white-space: nowrap; }
.ov-posture-facts b { font-family: var(--lyf-font-data); font-size: 16px; font-weight: 600; }

.ov-sev-bar { display: flex; height: 6px; overflow: hidden; border-radius: 3px; background: var(--lyf-surface-3); }
.ov-sev-bar i { display: block; height: 100%; }
.ov-sev-bar.empty { opacity: 0.45; }

.ov-sev-legend { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 8px; color: var(--lyf-ink-3); font-size: 11px; }
.ov-sev-legend span { display: inline-flex; align-items: center; gap: 5px; }
.ov-sev-legend i { width: 6px; height: 6px; border-radius: 50%; }
.ov-sev-legend b { color: var(--lyf-ink); font-family: var(--lyf-font-data); font-weight: 600; }
.ov-sev-legend em { font-style: normal; }

/* grids */
.ov-grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.ov-grid-2.wide-left { grid-template-columns: minmax(0, 7fr) minmax(0, 5fr); }

.ov-chart { width: 100%; height: 230px; }

/* ranked bars */
.ov-ranks { display: grid; gap: 9px; }
.ov-rank { display: grid; grid-template-columns: minmax(0, 1fr) 72px 46px; align-items: center; gap: 10px; }
.ov-rank-label { overflow: hidden; color: var(--lyf-ink-2); font-size: 11.5px; text-overflow: ellipsis; white-space: nowrap; }
.ov-rank-track { height: 4px; overflow: hidden; border-radius: 2px; background: var(--lyf-surface-3); }
.ov-rank-track i { display: block; height: 100%; background: var(--lyf-accent); opacity: 0.75; }
.ov-rank b { color: var(--lyf-ink); font-family: var(--lyf-font-data); font-size: 11.5px; font-weight: 600; text-align: right; }

/* queue */
.ov-queue { display: grid; }
.ov-queue-row {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto auto;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  border-bottom: var(--lyf-hairline);
  color: inherit;
  text-decoration: none;
}
.ov-queue-row:last-child { border-bottom: 0; }
.ov-queue-row:hover { background: var(--lyf-surface-2); }
.ov-queue-main { display: grid; gap: 2px; min-width: 0; }
.ov-queue-main b { overflow: hidden; color: var(--lyf-ink); font-size: 12.5px; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
.ov-queue-main small { color: var(--lyf-ink-3); font-size: 10.5px; }
.ov-queue-stages { display: flex; gap: 4px; }
.ov-queue-stages em {
  padding: 1px 6px;
  border: var(--lyf-hairline);
  border-radius: 3px;
  color: var(--lyf-ink-3);
  font-size: 10px;
  font-style: normal;
  white-space: nowrap;
}
.ov-queue-status { color: var(--lyf-ink-3); font-size: 10.5px; white-space: nowrap; }

/* stream */
.ov-stream { display: grid; }
.ov-stream-row {
  display: grid;
  grid-template-columns: 8px 62px minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px;
  padding: 8px 16px;
  border-bottom: var(--lyf-hairline);
  color: inherit;
  text-decoration: none;
}
.ov-stream-row:last-child { border-bottom: 0; }
.ov-stream-row:hover { background: var(--lyf-surface-2); }
.ov-stream-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--lyf-low); }
.ov-stream-dot[data-sev='critical'] { background: var(--lyf-critical); }
.ov-stream-dot[data-sev='high'] { background: var(--lyf-high); }
.ov-stream-dot[data-sev='medium'] { background: var(--lyf-medium); }
.ov-stream-row time { color: var(--lyf-ink-3); font-family: var(--lyf-font-data); font-size: 10px; }
.ov-stream-main { display: grid; gap: 1px; min-width: 0; }
.ov-stream-main b { overflow: hidden; color: var(--lyf-ink); font-size: 11.5px; font-weight: 550; text-overflow: ellipsis; white-space: nowrap; }
.ov-stream-main small { overflow: hidden; color: var(--lyf-ink-3); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }

/* engines */
.ov-engines { display: grid; gap: 8px; }
.ov-engine { display: grid; grid-template-columns: 28px minmax(0, 1fr) auto; align-items: center; gap: 10px; }
.ov-engine-mark {
  display: grid;
  width: 28px;
  height: 28px;
  place-items: center;
  border: var(--lyf-hairline);
  border-radius: var(--lyf-radius-sm);
  color: var(--lyf-accent);
  font-family: var(--lyf-font-data);
  font-size: 10px;
  font-weight: 700;
}
.ov-engine-copy { display: grid; gap: 1px; min-width: 0; }
.ov-engine-copy b { font-size: 12px; font-weight: 600; }
.ov-engine-copy small { overflow: hidden; color: var(--lyf-ink-3); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }

/* quality */
.ov-quality { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.ov-quality div { display: grid; gap: 2px; padding: 10px; border: var(--lyf-hairline); border-radius: var(--lyf-radius-sm); background: var(--lyf-surface-2); }
.ov-quality span { color: var(--lyf-ink-3); font-size: 10.5px; }
.ov-quality b { font-family: var(--lyf-font-data); font-size: 17px; font-weight: 600; }
.ov-quality b.warn { color: var(--lyf-high); }
.ov-quality b.ok { color: var(--lyf-success); }
.ov-quality b.muted { color: var(--lyf-unknown); }
.ov-quality small { color: var(--lyf-ink-3); font-size: 10px; }
.ov-quality-note { margin: 10px 0 0; color: var(--lyf-ink-3); font-size: 10.5px; }

@media (max-width: 1280px) {
  .ov-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ov-main,
  .ov-grid-2,
  .ov-grid-2.wide-left { grid-template-columns: minmax(0, 1fr); }
}

@media (max-width: 720px) {
  .ov-kpis { grid-template-columns: minmax(0, 1fr); }
  .ov-posture-top { flex-direction: column; }
  .ov-quality { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ov-queue-stages { display: none; }
  .ov-rank { grid-template-columns: minmax(0, 1fr) 46px; }
  .ov-rank-track { display: none; }
}
</style>
