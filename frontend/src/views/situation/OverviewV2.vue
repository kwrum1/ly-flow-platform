<template>
  <section class="overview-v2">
    <header class="overview-head">
      <div>
        <p>OPERATIONS OVERVIEW</p>
        <h2>运营总览</h2>
      </div>
      <button type="button" :disabled="loading" @click="load">刷新</button>
    </header>

    <div v-if="error" class="state-message">{{ error }}</div>

    <div class="kpi-grid">
      <article class="kpi-card">
        <span>24h 新增事件</span>
        <strong>{{ formatNumber(kpis.recent24h) }}</strong>
        <small>总事件 {{ formatNumber(kpis.total) }}</small>
      </article>
      <article class="kpi-card">
        <span>高危 / 严重</span>
        <strong class="danger">{{ formatNumber(kpis.highRisk) }}</strong>
        <small>需要优先研判</small>
      </article>
      <article class="kpi-card">
        <span>在线 Agent</span>
        <strong class="success">{{ formatNumber(kpis.onlineAgents) }}</strong>
        <small>资产总数 {{ formatNumber(kpis.totalAssets) }}</small>
      </article>
      <article class="kpi-card">
        <span>Incident</span>
        <strong>{{ formatNumber(kpis.incidents) }}</strong>
        <small>关联链生成的案件</small>
      </article>
    </div>

    <div class="panel-grid">
      <section class="panel">
        <div class="panel-head"><h3>ATT&CK 阶段分布</h3><span>最近 {{ sampleSize }} 条事件</span></div>
        <div v-if="stageRows.length" class="bar-list">
          <div v-for="row in stageRows" :key="row.key" class="bar-row">
            <span>{{ stageLabel(row.key) }}</span>
            <div class="bar-track"><i :style="{ width: `${row.percent}%` }" /></div>
            <strong>{{ row.count }}</strong>
          </div>
        </div>
        <div v-else class="empty">暂无阶段数据</div>
      </section>

      <section class="panel">
        <div class="panel-head"><h3>数据来源覆盖</h3><span>最近 {{ sampleSize }} 条事件</span></div>
        <div v-if="sourceRows.length" class="bar-list">
          <div v-for="row in sourceRows" :key="row.key" class="bar-row">
            <span>{{ row.key }}</span>
            <div class="bar-track"><i :style="{ width: `${row.percent}%` }" /></div>
            <strong>{{ row.count }}</strong>
          </div>
        </div>
        <div v-else class="empty">暂无来源数据</div>
      </section>
    </div>

    <section class="panel">
      <div class="panel-head">
        <h3>最近事件</h3>
        <RouterLink to="/events">查看全部</RouterLink>
      </div>
      <div v-if="recentEvents.length" class="event-table-wrap">
        <table class="event-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>来源</th>
              <th>阶段</th>
              <th>严重度</th>
              <th>资产</th>
              <th>规则</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="event in recentEvents" :key="event.event_uid">
              <td class="mono">{{ formatTime(event.event_at) }}</td>
              <td>{{ event.source || '-' }}</td>
              <td>{{ stageLabel(event.stage) }}</td>
              <td><span :class="['severity', event.severity]">{{ event.severity || '-' }}</span></td>
              <td>{{ event.asset_id || '-' }}</td>
              <td>{{ event.rule_id || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty">暂无事件</div>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { attackWorkbenchClient, overviewClient } from '../../api/domain'
import { eventsV2Client } from '../../api/v2'
import { stageLabel } from '../../domain/attack-labels'

const loading = ref(false)
const error = ref('')
const stats = ref({})
const incidentData = ref({})
const eventItems = ref([])

const sampleSize = computed(() => eventItems.value.length)
const kpis = computed(() => ({
  recent24h: stats.value.recent_events_24h ?? stats.value.new_events ?? 0,
  total: stats.value.total_events ?? 0,
  highRisk: Number(stats.value.critical_events || 0) + Number(stats.value.high_events || 0),
  totalAssets: stats.value.total_assets ?? 0,
  onlineAgents: stats.value.online_agents ?? 0,
  incidents: incidentData.value.total ?? incidentData.value.items?.length ?? 0,
}))

const stageRows = computed(() => buildRows(eventItems.value, 'stage'))
const sourceRows = computed(() => buildRows(eventItems.value, 'source'))
const recentEvents = computed(() => eventItems.value.slice(0, 8))

function unwrap(response) {
  return response?.data?.data ?? response?.data ?? {}
}

function buildRows(items, key) {
  const counts = new Map()
  for (const item of items) {
    const value = item?.[key] || 'unknown'
    counts.set(value, (counts.get(value) || 0) + 1)
  }
  const rows = [...counts.entries()]
    .map(([name, count]) => ({ key: name, count }))
    .sort((left, right) => right.count - left.count)
    .slice(0, 8)
  const max = rows[0]?.count || 1
  return rows.map((row) => ({ ...row, percent: Math.max(4, Math.round((row.count / max) * 100)) }))
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString('zh-CN')
}

function formatTime(value) {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleString('zh-CN', { hour12: false })
}

async function load() {
  loading.value = true
  error.value = ''
  const [statsResult, incidentResult, eventsResult] = await Promise.allSettled([
    overviewClient.stats(),
    attackWorkbenchClient.incidents({ limit: 1 }),
    eventsV2Client.list({ limit: 100 }),
  ])
  if (statsResult.status === 'fulfilled') stats.value = unwrap(statsResult.value)
  if (incidentResult.status === 'fulfilled') incidentData.value = unwrap(incidentResult.value)
  if (eventsResult.status === 'fulfilled') {
    const page = unwrap(eventsResult.value)
    eventItems.value = Array.isArray(page.items) ? page.items : []
  }
  if (statsResult.status === 'rejected' && eventsResult.status === 'rejected') {
    error.value = '数据加载失败，请稍后重试'
  }
  loading.value = false
}

onMounted(load)
</script>

<style scoped>
.overview-v2 { display: grid; gap: 16px; color: #1f2a37; }
.overview-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; }
.overview-head p { margin: 0 0 2px; color: #98a2b3; font-size: 10px; letter-spacing: .08em; }
.overview-head h2 { margin: 0; font-size: 20px; font-weight: 600; }
.overview-head button { height: 32px; padding: 0 14px; border: 1px solid #d8e1ec; border-radius: 6px; background: #fff; color: #475467; cursor: pointer; }
.overview-head button:hover { border-color: #1976d2; color: #1268bd; }
.state-message { padding: 10px 12px; border: 1px solid #f3c2c2; border-radius: 6px; background: #fff5f5; color: #c43838; font-size: 13px; }
.kpi-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.kpi-card { padding: 14px 16px; border: 1px solid #d8e1ec; border-radius: 8px; background: #fff; }
.kpi-card span { display: block; color: #667085; font-size: 12px; }
.kpi-card strong { display: block; margin: 6px 0 2px; font-size: 24px; font-weight: 600; font-variant-numeric: tabular-nums; }
.kpi-card small { color: #98a2b3; font-size: 11px; }
.kpi-card .danger { color: #c43838; }
.kpi-card .success { color: #168a55; }
.panel-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.panel { min-width: 0; padding: 14px 16px; border: 1px solid #d8e1ec; border-radius: 8px; background: #fff; }
.panel-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; }
.panel-head h3 { margin: 0; font-size: 14px; font-weight: 600; }
.panel-head span, .panel-head a { color: #98a2b3; font-size: 11px; text-decoration: none; }
.panel-head a:hover { color: #1268bd; }
.bar-list { display: grid; gap: 8px; }
.bar-row { display: grid; grid-template-columns: 90px minmax(0, 1fr) 44px; align-items: center; gap: 10px; font-size: 12px; }
.bar-row > span { overflow: hidden; color: #475467; text-overflow: ellipsis; white-space: nowrap; }
.bar-row > strong { text-align: right; font-variant-numeric: tabular-nums; }
.bar-track { height: 8px; overflow: hidden; border-radius: 4px; background: #f1f5f9; }
.bar-track i { display: block; height: 100%; border-radius: 4px; background: #1976d2; }
.empty { padding: 24px 0; color: #98a2b3; font-size: 12px; text-align: center; }
.event-table-wrap { overflow-x: auto; }
.event-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.event-table th, .event-table td { padding: 8px 10px; border-bottom: 1px solid #eef2f6; text-align: left; white-space: nowrap; }
.event-table th { color: #667085; font-weight: 500; background: #f8fafc; }
.event-table tr:last-child td { border-bottom: 0; }
.mono { font-family: Consolas, monospace; color: #475467; }
.severity { padding: 2px 6px; border-radius: 4px; background: #f1f5f9; color: #475467; font-size: 11px; }
.severity.critical { background: #fdecec; color: #c43838; }
.severity.high { background: #fff3e6; color: #ad6800; }
.severity.medium { background: #fff8db; color: #8a6d00; }
.severity.low { background: #eef7f1; color: #168a55; }
@media (max-width: 960px) { .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .panel-grid { grid-template-columns: 1fr; } }
@media (max-width: 560px) { .kpi-grid { grid-template-columns: 1fr; } }
</style>
