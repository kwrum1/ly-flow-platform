<template>
  <section class="sx-page overview-page">
    <header class="sx-page-head">
      <div>
        <p class="sx-kicker">LIVE SECURITY OPERATIONS</p>
        <h2 class="sx-title">态势总览</h2>
        <p class="sx-subtitle">从真实事件、攻击链与资产心跳中聚合当前安全态势；每个数字都可以下钻到对应事件或 Incident。</p>
      </div>
      <div class="sx-head-actions">
        <span class="sx-live"><i />LIVE</span>
        <span class="overview-updated">最近同步 {{ lastUpdated }}</span>
        <button class="sx-btn" type="button" :disabled="loading" @click="load">
          {{ loading ? '同步中…' : '刷新态势' }}
        </button>
      </div>
    </header>

    <div v-if="error" class="sx-error">{{ error }}</div>

    <section class="overview-hero">
      <article class="posture-card" :class="`risk-${riskTone}`">
        <div class="posture-card-top">
          <div>
            <span class="posture-eyebrow"><i />XDR POSTURE</span>
            <h3>{{ riskLabel }}</h3>
            <p>{{ postureNote }}</p>
          </div>
          <span class="sx-badge" :class="riskTone">{{ riskToneLabel }}</span>
        </div>

        <div class="posture-score-row">
          <div class="score-ring" :style="scoreRingStyle">
            <div>
              <strong>{{ riskScore }}</strong>
              <span>态势评分</span>
            </div>
          </div>
          <div class="posture-facts">
            <div><span>活跃攻击链</span><b>{{ postureActiveChains }}</b></div>
            <div><span>Incident 总量</span><b>{{ incidentsReady ? formatNumber(incidentTotal) : '…' }}</b></div>
            <div><span>在线 Agent</span><b>{{ formatNumber(onlineAgents) }}<em>/{{ formatNumber(totalAssets) }}</em></b></div>
            <div><span>待审批处置</span><b class="warning">{{ formatNumber(pendingApprovalCount) }}</b></div>
          </div>
        </div>

        <div class="posture-card-foot">
          <span><i class="dot ok" />检测引擎 {{ engineOnline }}/{{ engineTotal }}</span>
          <span><i class="dot" :class="platformOnline ? 'ok' : 'bad'" />平台{{ platformOnline ? '在线' : '异常' }}</span>
          <span>规则 {{ formatNumber(ruleTotal) }} 条</span>
        </div>
      </article>

      <div class="hero-metrics">
        <article class="sx-metric metric-live">
          <span class="sx-metric-label"><i />24h 检测事件</span>
          <strong class="sx-metric-value">{{ formatNumber(todayEvents) }}</strong>
          <span class="sx-metric-note">累计 {{ formatNumber(totalEvents) }} 条 · 样本 {{ eventItems.length }} 条</span>
        </article>
        <article class="sx-metric">
          <span class="sx-metric-label"><i />高危 / 严重</span>
          <strong class="sx-metric-value danger">{{ formatNumber(highRiskCount) }}</strong>
          <span class="sx-metric-note">{{ highRiskNote }}</span>
        </article>
        <article class="sx-metric">
          <span class="sx-metric-label"><i />处置队列</span>
          <strong class="sx-metric-value warning">{{ incidentsReady ? formatNumber(openIncidentCount) : '…' }}</strong>
          <span class="sx-metric-note">{{ incidentsReady ? `最近 ${normalizedIncidents.length} 条样本中的待处置` : '正在加载 Incident' }}</span>
        </article>
        <article class="sx-metric">
          <span class="sx-metric-label"><i />资产覆盖</span>
          <strong class="sx-metric-value success">{{ formatNumber(totalAssets) }}</strong>
          <span class="sx-metric-note">在线 {{ formatNumber(onlineAgents) }} · 离线 {{ formatNumber(offlineAgents) }}</span>
        </article>
      </div>
    </section>

    <section class="sx-panel stage-panel">
      <div class="sx-panel-head">
        <div class="sx-panel-title">ATT&CK 攻击阶段</div>
        <div class="sx-panel-meta">{{ incidentsReady ? `来自 ${incidentSampleLabel} Incident` : 'Incident 加载中' }} + {{ chains.items.length }} 条活跃链 · 点击阶段筛选事件</div>
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
    </section>

    <section class="overview-main-grid">
      <article class="sx-panel trend-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">检测活动趋势</div>
          <div class="sx-panel-meta">按严重度堆叠 · 最近 {{ eventItems.length }} 条事件</div>
        </div>
        <div class="sx-panel-body trend-body">
          <div v-if="trendRows.length" ref="trendElement" class="chart-box trend-chart" />
          <div v-else class="sx-empty"><div><strong>暂无可绘制的检测样本</strong>当前时间窗内没有事件返回。</div></div>
          <div class="trend-legend">
            <span v-for="item in severityRows" :key="item.key"><i :style="{ background: item.color }" />{{ item.label }} <b>{{ item.count }}</b></span>
          </div>
        </div>
      </article>

      <div class="overview-side">
        <article class="sx-panel severity-panel">
          <div class="sx-panel-head">
            <div class="sx-panel-title">告警等级构成</div>
            <span class="sx-panel-meta">有等级告警</span>
          </div>
          <div class="sx-panel-body severity-body">
            <div v-if="severityTotal" ref="severityElement" class="chart-box severity-chart" />
            <div v-else class="sx-empty"><div><strong>暂无告警等级数据</strong>等待检测引擎上报。</div></div>
            <div class="severity-list">
              <div v-for="item in severityRows" :key="item.key">
                <span><i :style="{ background: item.color }" />{{ item.label }}</span>
                <b>{{ formatNumber(item.count) }}</b>
              </div>
            </div>
          </div>
        </article>

        <article class="sx-panel source-panel">
          <div class="sx-panel-head">
            <div class="sx-panel-title">数据来源覆盖</div>
            <span class="sx-panel-meta">{{ sourceRows.length }} 个来源</span>
          </div>
          <div class="sx-panel-body source-body">
            <div v-if="sourceRows.length" class="source-list">
              <div v-for="item in sourceRows" :key="item.key" class="source-row">
                <span>{{ item.label }}</span>
                <div><i :style="{ width: `${item.percent}%` }" /></div>
                <b>{{ formatNumber(item.count) }}</b>
              </div>
            </div>
            <div v-else class="sx-empty"><div><strong>暂无来源数据</strong></div></div>
          </div>
        </article>
      </div>
    </section>

    <section class="overview-lower-grid">
      <article class="sx-panel incident-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">优先处置</div>
          <RouterLink class="sx-panel-meta" to="/incidents">全部 {{ formatNumber(incidentTotal) }} 条 →</RouterLink>
        </div>
        <div v-if="!incidentsReady" class="sx-empty"><div><strong>正在加载 Incident</strong>列表返回后立即展示处置队列。</div></div>
        <div v-else-if="activeIncidents.length" class="incident-list">
          <RouterLink
            v-for="incident in activeIncidents"
            :key="incident.id"
            class="incident-row"
            :to="{ path: '/incidents', query: { id: incident.id } }"
          >
            <span class="sx-badge" :class="incident.severity">{{ severityLabel(incident.severity) }}</span>
            <div class="incident-copy">
              <b>{{ incident.title }}</b>
              <small>{{ incident.affectedAsset || incident.entityId || '未绑定资产' }} · {{ formatTime(incident.updatedAt || incident.createdAt) }}</small>
            </div>
            <div class="incident-stages">
              <span v-for="stage in incident.stages.slice(0, 3)" :key="stage.id">{{ stage.name }}</span>
            </div>
            <span class="incident-status">{{ statusLabel(incident.status) }}</span>
          </RouterLink>
        </div>
        <div v-else class="sx-empty"><div><strong>暂无待处置 Incident</strong>当前队列为空。</div></div>
      </article>

      <article class="sx-panel event-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">实时事件流</div>
          <RouterLink class="sx-panel-meta" to="/events">事件中心 →</RouterLink>
        </div>
        <div v-if="recentEvents.length" class="event-stream">
          <RouterLink
            v-for="event in recentEvents"
            :key="event.id || event.event_uid"
            class="event-stream-row"
            :to="{ path: '/events', query: { uid: event.id || event.event_uid } }"
          >
            <span class="stream-dot" :class="event.severity" />
            <time>{{ formatShortTime(event.timestamp || event.event_at || event.created_at) }}</time>
            <div>
              <b>{{ event.rule_name || event.rule_id || event.event_type || '检测事件' }}</b>
              <small>{{ event.source || event.source_engine || 'unknown' }} · {{ event.hostname || event.agent_id || event.src_ip || '未绑定资产' }}</small>
            </div>
            <span class="sx-badge" :class="event.severity">{{ severityLabel(event.severity) }}</span>
          </RouterLink>
        </div>
        <div v-else class="sx-empty"><div><strong>暂无实时事件</strong>等待采集面上报。</div></div>
      </article>

      <article class="sx-panel engine-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">检测引擎</div>
          <RouterLink class="sx-panel-meta" to="/engines">引擎健康 →</RouterLink>
        </div>
        <div v-if="engineRows.length" class="engine-list">
          <div v-for="engine in engineRows" :key="engine.key" class="engine-row">
            <span class="engine-icon" :class="engine.tone">{{ engine.short }}</span>
            <div>
              <b>{{ engine.label }}</b>
              <small>{{ engine.note }}</small>
            </div>
            <span class="sx-badge" :class="engine.tone">{{ engine.status }}</span>
          </div>
        </div>
        <div v-else class="sx-empty"><div><strong>暂无引擎心跳</strong></div></div>
        <div class="asset-mini">
          <div class="asset-mini-head"><span>资产风险</span><RouterLink to="/assets">资产中心 →</RouterLink></div>
          <div v-for="asset in topAssets" :key="asset.id || asset.agent_id || asset.hostname" class="asset-mini-row">
            <span>{{ asset.hostname || asset.display_name || asset.id }}</span>
            <i :class="asset.status === 'online' ? 'ok' : 'bad'" />
            <b>{{ asset.ip || '未上报 IP' }}</b>
          </div>
          <div v-if="!topAssets.length" class="sx-muted">暂无资产心跳</div>
        </div>
      </article>
    </section>
  </section>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { RouterLink, useRouter } from 'vue-router'
import * as echarts from 'echarts'
import { attackWorkbenchClient, assetAgentClient, overviewClient, ruleClient } from '../../api/domain'
import { normalizeIncidents } from '../../domain/incidents'
import { severityLabel } from '../../domain/attack-labels'
import { formatChinaDateTime, formatChinaTime } from '../../shared/time'

const router = useRouter()
const loading = ref(false)
const error = ref('')
const lastUpdated = ref('-')
const stats = ref({})
const unified = ref({})
const posture = ref({})
const chains = ref({ items: [], total: 0 })
const incidents = ref({ items: [], total: 0 })
const assetStats = ref({})
const assets = ref({ items: [] })
const engines = ref({ items: [] })
const events = ref({ items: [], total: 0 })
const responseActions = ref({ items: [], total: 0 })
const ruleStats = ref({})
const platformOnline = ref(true)
const incidentsReady = ref(false)

const trendElement = ref(null)
const severityElement = ref(null)
let trendChart = null
let severityChart = null
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
  { key: 'critical', label: '严重', color: '#d92d20' },
  { key: 'high', label: '高危', color: '#e26a00' },
  { key: 'medium', label: '中危', color: '#c58b00' },
  { key: 'low', label: '低危', color: '#0f9f6e' },
]

const normalizedIncidents = computed(() => normalizeIncidents(incidents.value.items || []))
const incidentTotal = computed(() => Number(incidents.value.total || normalizedIncidents.value.length || 0))
const eventItems = computed(() => (Array.isArray(events.value.items) ? events.value.items : []))
const totalEvents = computed(() => Number(unified.value.total_events || stats.value.total_events || 0))
const todayEvents = computed(() => Number(unified.value.today_events || stats.value.recent_events_24h || 0))
const highRiskCount = computed(() => Number(unified.value.by_severity?.critical || 0) + Number(unified.value.by_severity?.high || 0) || Number(stats.value.critical_events || 0) + Number(stats.value.high_events || 0))
const onlineAgents = computed(() => Number(assetStats.value.online ?? stats.value.online_agents ?? 0))
const offlineAgents = computed(() => Number(assetStats.value.offline ?? 0))
const totalAssets = computed(() => Number(assetStats.value.total ?? stats.value.total_assets ?? 0))
const ruleTotal = computed(() => Number(ruleStats.value.totalRules || ruleStats.value.total_rules || 0))
const pendingApprovalCount = computed(() => (responseActions.value.items || []).filter((item) => ['pending_approval', 'approved'].includes(item.status)).length)
const postureActiveChains = computed(() => Number(posture.value.active_chains ?? posture.value.active_v2_chains ?? 0))
const riskScore = computed(() => Math.max(0, Math.min(100, Number(posture.value.risk_score || 0))))
const riskTone = computed(() => ['critical', 'high', 'medium', 'low'].includes(posture.value.risk_level) ? posture.value.risk_level : 'low')
const riskToneLabel = computed(() => severityLabel(riskTone.value))
const riskLabel = computed(() => ({ critical: '严重风险', high: '高风险', medium: '中风险', low: '低风险' })[riskTone.value] || '低风险')
const postureNote = computed(() => {
  if (riskTone.value === 'low') return '当前未发现需要立即升级的活跃攻击链，保持持续监测。'
  if (riskTone.value === 'medium') return '存在需要关注的关联活动，建议优先核查高严重度事件。'
  return '检测到高风险关联活动，请进入攻击链处置队列。'
})
const highRiskNote = computed(() => {
  const total = Number(unified.value.total_alerts || unified.value.total_events || 0)
  if (!total) return '等待统一告警聚合'
  const ratio = (highRiskCount.value / total) * 100
  return `占全部告警 ${ratio > 0 && ratio < 0.1 ? '<0.1' : ratio.toFixed(1)}% · 建议优先研判`
})
const openIncidentCount = computed(() => normalizedIncidents.value.filter((item) => ['new', 'open', 'triaged', 'processing'].includes(item.status)).length || incidentTotal.value)
const incidentSampleLabel = computed(() => `${normalizedIncidents.value.length} 条样本`)
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
    const running = item.running && !offline
    const installed = item.installed !== false
    return {
      key,
      short: ({ suricata: 'SU', wazuh: 'WA', yara: 'YA', rasp: 'RA', dpi: 'DP' })[key] || key.slice(0, 2).toUpperCase(),
      label: ({ suricata: 'Suricata', wazuh: 'Wazuh', yara: 'YARA', rasp: 'OpenRASP', dpi: 'DPI Engine' })[key] || key,
      status: !installed ? '未安装' : running ? '运行中' : offline ? 'Agent 离线' : '待连接',
      tone: !installed ? 'muted' : running ? 'low' : 'medium',
      note: [item.rule_pack_version || '', items.length > 1 ? `${items.length} 个探针` : item.hostname || ''].filter(Boolean).join(' · ') || '无心跳详情',
      running,
      offline,
    }
  })
})
const engineOnline = computed(() => engineRows.value.filter((item) => item.running).length)
const engineTotal = computed(() => engineRows.value.length)
const activeIncidents = computed(() => normalizedIncidents.value.filter((item) => ['new', 'open', 'triaged', 'processing'].includes(item.status)).slice(0, 5))
const topAssets = computed(() => (assets.value.items || []).slice(0, 4))
const recentEvents = computed(() => [...eventItems.value].sort((a, b) => timestampMs(b) - timestampMs(a)).slice(0, 7))
const severityRows = computed(() => {
  const source = unified.value.by_severity || {}
  return severityDefinitions.map((item) => ({ ...item, count: Number(source[item.key] || 0) })).filter((item) => item.count > 0)
})
const severityTotal = computed(() => severityRows.value.reduce((sum, item) => sum + item.count, 0))
const sourceRows = computed(() => {
  const source = unified.value.by_source || {}
  const rows = Object.entries(source)
    .map(([key, count]) => ({ key, label: sourceLabel(key), count: Number(count || 0) }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6)
  const max = rows[0]?.count || 1
  return rows.map((item) => ({ ...item, percent: Math.max(4, Math.round((item.count / max) * 100)) }))
})
const stageRows = computed(() => {
  const counts = Object.fromEntries(stageDefinitions.map(([key]) => [key, 0]))
  for (const incident of normalizedIncidents.value) {
    for (const stage of incident.stages || []) {
      const key = normalizeStageKey(stage.stageKey || stage.name || stage.tactic)
      if (key && counts[key] !== undefined) counts[key] += 1
    }
  }
  for (const chain of chains.value.items || []) {
    for (const stage of chain.stages || []) {
      const key = normalizeStageKey(typeof stage === 'string' ? stage : stage?.stage || stage?.name || stage?.stage_hint)
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
const trendRows = computed(() => buildTrendRows(eventItems.value))
const scoreRingStyle = computed(() => {
  const tone = severityDefinitions.find((item) => item.key === riskTone.value)?.color || '#0f9f6e'
  const degrees = Math.max(6, Math.round((riskScore.value / 100) * 360))
  return { background: `conic-gradient(${tone} ${degrees}deg, var(--sx-surface-3) ${degrees}deg)` }
})
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

function timestampMs(item) {
  const value = item?.timestamp || item?.event_at || item?.occurred_at || item?.created_at
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
  return ({ new: '新发', open: '新发', triaged: '已分诊', processing: '处理中', resolved: '已解决', closed: '已关闭' })[value] || value || '-'
}

function sourceLabel(value) {
  return ({ 'g5-real-agent': 'Agent 采集', wazuh: 'Wazuh', suricata: 'Suricata', 'ly-security-engine': '安全引擎', sshd: 'SSH 日志', rasp: 'RASP', yara: 'YARA', dpi_engine: 'DPI' })[value] || value || '未知'
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
    time: start + bucketMs * index,
    label: new Date(start + bucketMs * index).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }),
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  }))
  for (const item of sorted) {
    const index = Math.max(0, Math.min(bucketCount - 1, Math.floor((timestampMs(item) - start) / bucketMs)))
    const key = String(item.severity || 'low').toLowerCase()
    if (buckets[index][key] !== undefined) buckets[index][key] += 1
  }
  return buckets
}

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
  const text = styles.getPropertyValue('--sx-text-3').trim() || '#8493a6'
  const line = styles.getPropertyValue('--sx-line-soft').trim() || '#e8eef6'
  trendChart.setOption({
    animationDuration: 500,
    grid: { left: 34, right: 10, top: 12, bottom: 24 },
    tooltip: { trigger: 'axis', backgroundColor: 'rgba(8, 26, 45, .92)', borderWidth: 0, textStyle: { color: '#e8f3ff', fontSize: 11 } },
    xAxis: { type: 'category', boundaryGap: false, data: trendRows.value.map((row) => row.label), axisLine: { lineStyle: { color: line } }, axisTick: { show: false }, axisLabel: { color: text, fontSize: 9, interval: 1 } },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: line } }, axisLabel: { color: text, fontSize: 9 } },
    series: severityDefinitions.map((item) => ({
      name: item.label,
      type: 'line',
      stack: 'total',
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 1.5, color: item.color },
      itemStyle: { color: item.color },
      areaStyle: { color: item.color, opacity: 0.1 },
      data: trendRows.value.map((row) => row[item.key]),
    })),
  }, true)
}

function renderSeverity() {
  if (!severityElement.value || !severityRows.value.length) {
    severityChart?.dispose()
    severityChart = null
    return
  }
  if (!severityChart || severityChart.getDom() !== severityElement.value) {
    severityChart?.dispose()
    severityChart = echarts.init(severityElement.value)
  }
  const styles = getComputedStyle(document.documentElement)
  const text = styles.getPropertyValue('--sx-text-3').trim() || '#8493a6'
  severityChart.setOption({
    animationDuration: 500,
    tooltip: { trigger: 'item', backgroundColor: 'rgba(8, 26, 45, .92)', borderWidth: 0, textStyle: { color: '#e8f3ff', fontSize: 11 } },
    series: [{
      type: 'pie',
      radius: ['62%', '80%'],
      center: ['50%', '50%'],
      avoidLabelOverlap: true,
      itemStyle: { borderColor: styles.getPropertyValue('--sx-surface').trim() || '#fff', borderWidth: 2 },
      label: { show: false },
      data: severityRows.value.map((item) => ({ name: item.label, value: item.count, itemStyle: { color: item.color } })),
    }],
    graphic: [
      { type: 'text', left: 'center', top: '42%', style: { text: severityTotal.value.toLocaleString('zh-CN'), fill: styles.getPropertyValue('--sx-text').trim() || '#17283d', fontSize: 18, fontWeight: 750, textAlign: 'center' } },
      { type: 'text', left: 'center', top: '56%', style: { text: '有等级告警', fill: text, fontSize: 10, textAlign: 'center' } },
    ],
  }, true)
}

function renderCharts() {
  renderTrend()
  renderSeverity()
}

async function load() {
  loading.value = true
  error.value = ''
  let succeeded = 0
  const refreshCharts = () => nextTick(renderCharts)
  const jobs = [
    overviewClient.health().then(() => { platformOnline.value = true; succeeded++ }).catch(() => { platformOnline.value = false }),
    overviewClient.stats().then((value) => { stats.value = unwrap(value); succeeded++ }),
    attackWorkbenchClient.stats().then((value) => { unified.value = unwrap(value); succeeded++ }),
    attackWorkbenchClient.xdrPosture().then((value) => { posture.value = unwrap(value); succeeded++ }),
    attackWorkbenchClient.xdrChains({ limit: 30 }).then((value) => { chains.value = normalizePage(value); succeeded++ }),
    attackWorkbenchClient.incidents({ limit: 10, live: 0 }).then((value) => { incidents.value = normalizePage(value); incidentsReady.value = true; succeeded++ }),
    assetAgentClient.assetStats().then((value) => { assetStats.value = unwrap(value); succeeded++ }),
    assetAgentClient.assets({ limit: 8 }).then((value) => { assets.value = normalizePage(value); succeeded++ }),
    assetAgentClient.engineHealth().then((value) => { engines.value = normalizePage(value); succeeded++ }),
    attackWorkbenchClient.events({ limit: 160 }).then((value) => { events.value = normalizePage(value); succeeded++; refreshCharts() }),
    ruleClient.responseActions({ limit: 100 }).then((value) => { responseActions.value = normalizePage(value); succeeded++ }),
    ruleClient.stats().then((value) => { ruleStats.value = unwrap(value); succeeded++ }),
  ]
  try {
    await Promise.allSettled(jobs)
    if (succeeded === 0) error.value = '态势数据加载失败，请检查后端连接。'
  } catch (panic) {
    error.value = '态势数据加载失败，请检查后端连接。'
  } finally {
    lastUpdated.value = formatChinaTime()
    loading.value = false
    await refreshCharts()
  }
}

function normalizePage(value) {
  const data = unwrap(value)
  const items = Array.isArray(data) ? data : Array.isArray(data.items) ? data.items : []
  return { items, total: Number(data.total ?? items.length) || items.length }
}

function openStage(stage) {
  router.push({ path: '/events', query: { stage } })
}

function onResize() {
  trendChart?.resize()
  severityChart?.resize()
}

function onThemeChange() {
  trendChart?.dispose()
  severityChart?.dispose()
  trendChart = null
  severityChart = null
  nextTick(renderCharts)
}

onMounted(async () => {
  await load()
  pollTimer = setInterval(load, 30000)
  window.addEventListener('resize', onResize)
  window.addEventListener('lyflow-theme-changed', onThemeChange)
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
  window.removeEventListener('resize', onResize)
  window.removeEventListener('lyflow-theme-changed', onThemeChange)
  trendChart?.dispose()
  severityChart?.dispose()
  trendChart = null
  severityChart = null
})
</script>

<style scoped>
.overview-page {
  gap: 14px;
}

.overview-updated {
  color: var(--sx-text-3);
  font-size: 10px;
  white-space: nowrap;
}

.overview-hero {
  display: grid;
  grid-template-columns: minmax(340px, 1.15fr) minmax(0, 1.85fr);
  gap: 14px;
}

.posture-card {
  position: relative;
  display: flex;
  min-height: 238px;
  overflow: hidden;
  flex-direction: column;
  justify-content: space-between;
  padding: 18px;
  border: 1px solid rgb(84 166 228 / 22%);
  border-radius: var(--sx-radius-lg);
  background:
    radial-gradient(circle at 95% 0%, rgb(46 180 255 / 25%), transparent 42%),
    radial-gradient(circle at 0% 110%, rgb(109 93 252 / 22%), transparent 48%),
    linear-gradient(135deg, #071a2d 0%, #0b2a45 58%, #0c3552 100%);
  box-shadow: 0 20px 44px -28px rgb(4 30 54 / 72%);
  color: #e9f7ff;
}

.posture-card::after {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background-image: linear-gradient(rgb(120 200 255 / 5%) 1px, transparent 1px), linear-gradient(90deg, rgb(120 200 255 / 5%) 1px, transparent 1px);
  background-size: 26px 26px;
  mask-image: linear-gradient(120deg, black, transparent 62%);
}

.posture-card.risk-critical { border-color: rgb(255 122 112 / 45%); }
.posture-card.risk-high { border-color: rgb(255 174 69 / 38%); }
.posture-card.risk-medium { border-color: rgb(255 209 102 / 34%); }

.posture-card-top,
.posture-score-row,
.posture-card-foot {
  position: relative;
  z-index: 1;
}

.posture-card-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 14px;
}

.posture-eyebrow {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: #75c7f6;
  font-size: 9px;
  font-weight: 750;
  letter-spacing: 0.12em;
}

.posture-eyebrow i {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: #43ddad;
  box-shadow: 0 0 0 3px rgb(67 221 173 / 14%);
}

.posture-card h3 {
  margin: 7px 0 0;
  color: #f2fbff;
  font-size: 22px;
  font-weight: 720;
  letter-spacing: -0.035em;
}

.posture-card p {
  max-width: 320px;
  margin: 5px 0 0;
  color: #9ebbd3;
  font-size: 11px;
  line-height: 1.55;
}

.posture-card .sx-badge {
  border-color: rgb(126 202 255 / 22%);
  background: rgb(255 255 255 / 8%);
  color: #d7efff;
}

.posture-card .sx-badge.low { color: #83f0c9; }
.posture-card .sx-badge.high { color: #ffca82; }
.posture-card .sx-badge.critical { color: #ffaaa3; }

.posture-score-row {
  display: flex;
  align-items: center;
  gap: 20px;
  margin-top: 12px;
}

.score-ring {
  display: grid;
  width: 116px;
  height: 116px;
  flex: 0 0 116px;
  place-items: center;
  border-radius: 50%;
  box-shadow: 0 0 38px -18px rgb(60 186 255 / 75%);
}

.score-ring > div {
  display: grid;
  width: 88px;
  height: 88px;
  place-items: center;
  align-content: center;
  border: 1px solid rgb(91 179 239 / 22%);
  border-radius: 50%;
  background: #0a2239;
}

.score-ring strong {
  color: #f2fbff;
  font-size: 30px;
  font-weight: 780;
  letter-spacing: -0.07em;
  line-height: 1;
}

.score-ring span {
  margin-top: 4px;
  color: #84a7c1;
  font-size: 9px;
}

.posture-facts {
  display: grid;
  flex: 1;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 9px 16px;
}

.posture-facts span {
  display: block;
  color: #86a8c2;
  font-size: 9px;
}

.posture-facts b {
  display: block;
  margin-top: 2px;
  color: #eaf8ff;
  font-size: 17px;
  font-weight: 700;
}

.posture-facts b em {
  margin-left: 3px;
  color: #7f9eb6;
  font-size: 10px;
  font-style: normal;
  font-weight: 500;
}

.posture-facts b.warning { color: #ffca82; }

.posture-card-foot {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  padding-top: 12px;
  border-top: 1px solid rgb(128 196 241 / 14%);
  color: #87a8c0;
  font-size: 9px;
}

.posture-card-foot span {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}

.dot {
  display: inline-block;
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: #7893a9;
}

.dot.ok { background: #43ddad; box-shadow: 0 0 0 3px rgb(67 221 173 / 12%); }
.dot.bad { background: #ff7a70; box-shadow: 0 0 0 3px rgb(255 122 112 / 12%); }

.hero-metrics {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.metric-live .sx-metric-value { color: var(--sx-accent); }

.stage-panel .sx-panel-body {
  padding: 12px;
}

.stage-panel .sx-stage {
  appearance: none;
  border: 1px solid var(--sx-line-soft);
  text-align: left;
  cursor: pointer;
}

.overview-main-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.7fr) minmax(280px, 0.8fr);
  gap: 14px;
}

.trend-body {
  display: flex;
  min-height: 250px;
  flex-direction: column;
  gap: 6px;
}

.chart-box { width: 100%; min-width: 0; }

.trend-chart { flex: 1; min-height: 210px; }

.trend-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  color: var(--sx-text-3);
  font-size: 10px;
}

.trend-legend span { display: inline-flex; align-items: center; gap: 5px; }
.trend-legend i { width: 7px; height: 7px; border-radius: 2px; }
.trend-legend b { color: var(--sx-text); font-weight: 650; }

.overview-side {
  display: grid;
  gap: 14px;
}

.severity-body {
  display: grid;
  grid-template-columns: 130px minmax(0, 1fr);
  align-items: center;
  gap: 8px;
}

.severity-chart { height: 132px; }

.severity-list {
  display: grid;
  gap: 6px;
}

.severity-list > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 5px 7px;
  border-radius: 5px;
  background: var(--sx-surface-2);
  font-size: 10px;
}

.severity-list span { display: inline-flex; align-items: center; gap: 6px; color: var(--sx-text-2); }
.severity-list i { width: 6px; height: 6px; border-radius: 50%; }
.severity-list b { color: var(--sx-text); font-weight: 700; }

.source-body { padding-top: 12px; }

.source-list { display: grid; gap: 9px; }

.source-row {
  display: grid;
  grid-template-columns: 80px minmax(0, 1fr) 44px;
  align-items: center;
  gap: 8px;
  font-size: 10px;
}

.source-row > span { overflow: hidden; color: var(--sx-text-2); text-overflow: ellipsis; white-space: nowrap; }
.source-row > div { height: 6px; overflow: hidden; border-radius: 4px; background: var(--sx-surface-3); }
.source-row > div i { display: block; height: 100%; border-radius: inherit; background: linear-gradient(90deg, var(--sx-accent), var(--sx-accent-2)); }
.source-row > b { color: var(--sx-text); font-weight: 700; text-align: right; }

.overview-lower-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(0, 1.15fr) minmax(240px, 0.85fr);
  gap: 14px;
}

.incident-list { display: grid; }

.incident-row {
  display: grid;
  grid-template-columns: 48px minmax(0, 1fr) auto 48px;
  align-items: center;
  gap: 9px;
  padding: 9px 14px;
  border-bottom: 1px solid var(--sx-line-soft);
  color: inherit;
  text-decoration: none;
  transition: background var(--transition-fast);
}

.incident-row:last-child { border-bottom: 0; }
.incident-row:hover { background: var(--sx-surface-3); }

.incident-copy { min-width: 0; }
.incident-copy b { display: block; overflow: hidden; color: var(--sx-text); font-size: 11px; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
.incident-copy small { display: block; overflow: hidden; margin-top: 2px; color: var(--sx-text-3); font-size: 9px; text-overflow: ellipsis; white-space: nowrap; }

.incident-stages { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 3px; }
.incident-stages span { padding: 2px 5px; border-radius: 3px; background: var(--sx-surface-3); color: var(--sx-text-2); font-size: 8px; }
.incident-status { color: var(--sx-text-3); font-size: 9px; text-align: right; }

.event-stream { display: grid; }

.event-stream-row {
  display: grid;
  grid-template-columns: 7px 54px minmax(0, 1fr) auto;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--sx-line-soft);
  color: inherit;
  text-decoration: none;
}

.event-stream-row:last-child { border-bottom: 0; }
.event-stream-row:hover { background: var(--sx-surface-3); }

.stream-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--sx-text-3); }
.stream-dot.critical { background: var(--sx-critical); box-shadow: 0 0 0 3px rgb(217 45 32 / 10%); }
.stream-dot.high { background: var(--sx-high); }
.stream-dot.medium { background: var(--sx-medium); }
.stream-dot.low { background: var(--sx-success); }

.event-stream-row time { color: var(--sx-text-3); font-family: var(--sx-font-mono); font-size: 9px; }
.event-stream-row div { min-width: 0; }
.event-stream-row b { display: block; overflow: hidden; color: var(--sx-text); font-size: 10px; font-weight: 620; text-overflow: ellipsis; white-space: nowrap; }
.event-stream-row small { display: block; overflow: hidden; margin-top: 1px; color: var(--sx-text-3); font-size: 9px; text-overflow: ellipsis; white-space: nowrap; }
.event-stream-row .sx-badge { font-size: 8px; }

.engine-list { display: grid; padding: 4px 0; }

.engine-row {
  display: grid;
  grid-template-columns: 27px minmax(0, 1fr) auto;
  align-items: center;
  gap: 8px;
  padding: 7px 14px;
}

.engine-icon {
  display: grid;
  width: 25px;
  height: 25px;
  place-items: center;
  border-radius: 6px;
  background: var(--sx-accent-soft);
  color: var(--sx-accent);
  font-size: 8px;
  font-weight: 800;
}

.engine-icon.low { background: var(--sx-success-soft); color: var(--sx-success); }
.engine-icon.medium { background: var(--sx-warning-soft); color: var(--sx-warning); }
.engine-icon.muted { background: var(--sx-surface-3); color: var(--sx-text-3); }

.engine-row b { display: block; color: var(--sx-text); font-size: 10px; font-weight: 650; }
.engine-row small { display: block; overflow: hidden; margin-top: 1px; color: var(--sx-text-3); font-size: 8px; text-overflow: ellipsis; white-space: nowrap; }
.engine-row .sx-badge { font-size: 8px; }

.asset-mini {
  margin-top: 4px;
  padding: 10px 14px 12px;
  border-top: 1px solid var(--sx-line-soft);
  background: var(--sx-surface-2);
}

.asset-mini-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 6px;
  color: var(--sx-text-3);
  font-size: 9px;
}

.asset-mini-head a { color: var(--sx-accent); text-decoration: none; }
.asset-mini-row { display: grid; grid-template-columns: minmax(0, 1fr) 6px auto; align-items: center; gap: 7px; padding: 4px 0; font-size: 9px; }
.asset-mini-row span { overflow: hidden; color: var(--sx-text-2); text-overflow: ellipsis; white-space: nowrap; }
.asset-mini-row i { width: 5px; height: 5px; border-radius: 50%; background: var(--sx-text-3); }
.asset-mini-row i.ok { background: var(--sx-success); }
.asset-mini-row i.bad { background: var(--sx-danger); }
.asset-mini-row b { color: var(--sx-text-3); font-weight: 500; }

@media (max-width: 1280px) {
  .overview-hero { grid-template-columns: 1fr; }
  .posture-card { min-height: 210px; }
  .overview-main-grid { grid-template-columns: 1fr; }
  .overview-side { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .overview-lower-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .engine-panel { grid-column: span 2; }
}

@media (max-width: 900px) {
  .hero-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .overview-side,
  .overview-lower-grid { grid-template-columns: 1fr; }
  .engine-panel { grid-column: auto; }
  .severity-body { grid-template-columns: 120px minmax(0, 1fr); }
}

@media (max-width: 620px) {
  .hero-metrics { grid-template-columns: 1fr; }
  .posture-score-row { align-items: flex-start; flex-direction: column; }
  .score-ring { width: 102px; height: 102px; flex-basis: 102px; }
  .score-ring > div { width: 78px; height: 78px; }
  .posture-facts { width: 100%; }
  .incident-row { grid-template-columns: 48px minmax(0, 1fr) 42px; }
  .incident-stages { display: none; }
  .event-stream-row { grid-template-columns: 7px 48px minmax(0, 1fr); }
  .event-stream-row .sx-badge { display: none; }
}
</style>
