<template>
  <section class="v-page">
    <header class="v-head">
      <div>
        <p class="v-eyebrow">EVENT SEARCH</p>
        <h1>事件检索</h1>
        <p>同源、同目的、同情报的事件按滚动 1 小时聚合。主机运行时、RASP、日志只显示受害服务器，不显示空白的源/目标。</p>
      </div>
      <div class="v-head-actions">
        <div class="v-tabs">
          <button v-for="w in windows" :key="w.key" type="button" class="v-tab" :class="{ active: win === w.key }" @click="setWindow(w.key)">{{ w.label }}</button>
        </div>
        <button class="v-btn" type="button" :disabled="loading" @click="load">{{ loading ? '查询中…' : '查询' }}</button>
      </div>
    </header>

    <div v-if="error" class="v-error">{{ error }}</div>

    <article class="v-panel">
      <div class="v-panel-body">
        <div class="v-toolbar">
          <label class="v-field grow"><span>关键字</span><input v-model.trim="q" class="v-input" placeholder="IP / 域名 / 规则 / 进程 / 用户" @keyup.enter="load"></label>
          <label class="v-field"><span>类别</span>
            <select v-model="category" class="v-select">
              <option value="">全部</option><option value="traffic">流量</option><option value="runtime">主机运行时</option><option value="log_audit">日志审计</option><option value="rasp">应用 RASP</option>
            </select>
          </label>
          <label class="v-field"><span>等级</span>
            <select v-model="severity" class="v-select">
              <option value="">全部</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option>
            </select>
          </label>
        </div>
      </div>
      <div class="v-panel-head">
        <div class="v-panel-title">结果</div>
        <span class="v-panel-meta">{{ displayItems.length }} 条聚合记录 · {{ formatNumber(occurrences) }} 次命中</span>
      </div>
      <div class="v-table-wrap">
        <table class="v-table">
          <thead><tr><th>时间</th><th>等级</th><th>类别</th><th>事件</th><th>情报源 → 受害服务器</th><th>受害服务器</th><th>次数</th><th class="actions" /></tr></thead>
          <tbody>
            <tr v-for="e in displayItems" :key="e.event_uid" class="clickable" @click="selected = e">
              <td class="num">{{ shortTime(e.last_seen || e.event_at || e.timestamp) }}</td>
              <td><span class="v-badge" :class="e.severity">{{ severityLabel(e.severity) }}</span></td>
              <td>{{ categoryLabel(e.category) }}</td>
              <td class="ev-main"><b>{{ eventTitle(e) }}</b><small>{{ e.rule_id || e.source || '-' }}</small></td>
              <td class="v-mono">{{ pairText(e) }}</td>
              <td>{{ destLabel(e) }}</td>
              <td class="num">{{ e.count || 1 }}</td>
              <td class="actions"><button class="v-btn sm" type="button" @click.stop="selected = e">详情</button></td>
            </tr>
          </tbody>
        </table>
        <div v-if="!displayItems.length" class="v-table-empty">
          <strong>{{ loading ? '正在查询' : '暂无情报' }}</strong>
          <span v-if="!loading">尝试扩大时间窗口或清除筛选。</span>
        </div>
      </div>
    </article>

    <div v-if="selected" class="v-scrim" @click.self="selected = null">
      <aside class="v-drawer event-drawer">
        <div class="v-drawer-head">
          <div><p class="v-eyebrow">EVENT</p><div class="v-panel-title">{{ eventTitle(selected) }}</div></div>
          <button class="v-btn ghost" type="button" @click="selected = null">关闭</button>
        </div>
        <div class="v-drawer-body detail">
          <div class="detail-top">
            <span class="v-badge" :class="selected.severity">{{ severityLabel(selected.severity) }}</span>
            <span class="v-badge info">{{ categoryLabel(selected.category) }}</span>
            <span class="v-badge muted">{{ shortId(selected.event_uid) }}</span>
          </div>
          <dl class="v-kv">
            <dt>发生时间</dt><dd>{{ shortTime(selected.event_at || selected.timestamp) }}</dd>
            <dt>首次 / 最近</dt><dd>{{ shortTime(selected.first_seen) }} / {{ shortTime(selected.last_seen) }}</dd>
            <dt>受害服务器</dt><dd>{{ destLabel(selected) }}</dd>
            <dt v-if="hasPair(selected)">来源 → 目的</dt><dd v-if="hasPair(selected)" class="v-mono">{{ pairText(selected) }}</dd>
            <dt>情报 / 规则</dt><dd class="v-mono">{{ selected.rule_name || selected.rule_id || '-' }}</dd>
            <dt>来源</dt><dd>{{ sourceLabel(selected) }}</dd>
            <dt>命中次数</dt><dd>{{ selected.count || 1 }}</dd>
            <dt>摘要</dt><dd>{{ selected.summary || '-' }}</dd>
          </dl>
          <details class="tech" open>
            <summary>技术详情 / 原始载荷</summary>
            <dl class="v-kv">
              <dt>事件 UID</dt><dd class="v-mono">{{ selected.event_uid }}</dd>
              <dt>引擎</dt><dd class="v-mono">{{ selected.source_engine || selected.source || '-' }}</dd>
              <dt>规则 ID</dt><dd class="v-mono">{{ selected.rule_id || '-' }}</dd>
              <dt>聚合键</dt><dd class="v-mono">{{ selected.aggregate_key || '-' }}</dd>
              <dt>消息 ID</dt><dd class="v-mono">{{ selected.message_id || '-' }}</dd>
            </dl>
            <pre class="raw">{{ pretty(selected) }}</pre>
          </details>
        </div>
      </aside>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { assetAgentClient, opsClient } from '../../api/domain'
import { severityLabel } from '../../domain/attack-labels'
import { formatChinaDateTime } from '../../shared/time'

const windows = [
  { key: '1h', label: '1 小时', ms: 3600000 },
  { key: '24h', label: '24 小时', ms: 86400000 },
  { key: '7d', label: '7 天', ms: 604800000 },
  { key: '30d', label: '30 天', ms: 2592000000 },
]

const win = ref('24h')
const q = ref('')
const category = ref('')
const severity = ref('')
const loading = ref(false)
const error = ref('')
const items = ref([])
const agents = ref([])
const selected = ref(null)

const agentNameById = computed(() => {
  const map = new Map()
  for (const agent of agents.value) {
    const name = agent.display_name || agent.hostname || agent.agent_id
    if (agent.agent_id && name) map.set(String(agent.agent_id), name)
  }
  return map
})

const agentNameByIP = computed(() => {
  const map = new Map()
  for (const agent of agents.value) {
    const name = agent.display_name || agent.hostname || agent.agent_id
    if (agent.ip && name) map.set(String(agent.ip), name)
  }
  return map
})

const agentNameByHost = computed(() => {
  const map = new Map()
  for (const agent of agents.value) {
    const name = agent.display_name || agent.hostname || agent.agent_id
    if (agent.hostname && name) map.set(String(agent.hostname), name)
    if (agent.agent_id && name) map.set(String(agent.agent_id), name)
  }
  return map
})

function unwrap(r) { return r?.data?.data ?? r?.data ?? r ?? {} }
function formatNumber(v) { return (Number(v) || 0).toLocaleString('zh-CN') }
function shortTime(v) { return v ? formatChinaDateTime(v) : '-' }
function shortId(v) { const text = String(v || ''); return text.length > 16 ? `${text.slice(0, 8)}…${text.slice(-4)}` : text || '-' }
function categoryLabel(v) { return ({ traffic: '流量', runtime: '主机运行时', log_audit: '日志审计', rasp: '应用 RASP' })[v] || v || '-' }
function pretty(v) { try { return JSON.stringify(v, null, 2) } catch { return String(v) } }

function eventCategory(event) {
  return String(event.component_category || event.category || event.persisted_category || '')
}

function eventTitle(event) {
  const title = event.rule_name || event.event_type || event.rule_id || '检测事件'
  return title === 'component.alert' ? (event.summary || event.rule_id || '检测事件') : title
}

function sourceLabel(event) {
  if (String(event.source || '').includes('mirror') || String(event.agent_id || '') === '') {
    if (String(event.source || '').includes('mirror')) return '旁路镜像观测'
  }
  return event.source_label || event.source_engine || event.source || categoryLabel(eventCategory(event))
}

function agentName(event) {
  return agentNameById.value.get(String(event.agent_id || '')) ||
    agentNameByHost.value.get(String(event.hostname || event.asset_id || '')) ||
    event.agent_display_name || event.display_name || event.hostname || event.asset_id || ''
}

function destLabel(event) {
  const cat = eventCategory(event)
  if (['runtime', 'rasp', 'log_audit'].includes(cat)) return agentName(event) || event.dst_ip || '未知服务器'
  const dst = String(event.dst_ip || '')
  if (dst) return agentNameByIP.value.get(dst) || dst
  return agentName(event) || '未知服务器'
}

function pairText(event) {
  const cat = eventCategory(event)
  if (['runtime', 'rasp', 'log_audit'].includes(cat)) return `${categoryLabel(cat)} → ${destLabel(event)}`
  const src = String(event.src_ip || '')
  const dst = String(event.dst_ip || '')
  if (!src && !dst) return `${sourceLabel(event)} → ${destLabel(event)}`
  return `${agentNameByIP.value.get(src) || src || '未知来源'} → ${agentNameByIP.value.get(dst) || dst || destLabel(event)}`
}

function hasPair(event) {
  const cat = eventCategory(event)
  if (['runtime', 'rasp', 'log_audit'].includes(cat)) return false
  return Boolean(event.src_ip || event.dst_ip)
}

function severityRank(value) {
  return ({ critical: 4, high: 3, medium: 2, low: 1 })[String(value || '').toLowerCase()] || 0
}

const displayItems = computed(() => {
  const buckets = []
  const sorted = [...items.value].sort((a, b) => new Date(a.first_seen || a.event_at || a.timestamp) - new Date(b.first_seen || b.event_at || b.timestamp))
  for (const item of sorted) {
    const cat = eventCategory(item)
    const key = [cat, item.rule_id || item.rule_name || item.event_type, pairText(item), agentName(item)].join('|')
    const at = new Date(item.first_seen || item.event_at || item.timestamp).getTime()
    const bucket = buckets.find((row) => row.key === key && Number.isFinite(at) && at >= row.windowStart && at <= row.windowStart + 3600000)
    if (bucket) {
      bucket.count += Number(item.count) || 1
      bucket.last_seen = item.last_seen || item.event_at || item.timestamp
      if (severityRank(item.severity) > severityRank(bucket.severity)) bucket.severity = item.severity
      continue
    }
    buckets.push({
      ...item,
      key,
      count: Number(item.count) || 1,
      windowStart: Number.isFinite(at) ? at : Date.now(),
      last_seen: item.last_seen || item.event_at || item.timestamp,
    })
  }
  return buckets.sort((a, b) => new Date(b.last_seen || 0) - new Date(a.last_seen || 0))
})

const occurrences = computed(() => displayItems.value.reduce((sum, event) => sum + (Number(event.count) || 1), 0))

async function load() {
  loading.value = true
  error.value = ''
  const w = windows.find((x) => x.key === win.value) || windows[1]
  const to = new Date()
  const from = new Date(to.getTime() - w.ms)
  try {
    const [eventsResult, agentsResult] = await Promise.allSettled([
      opsClient.eventSample({
        from: from.toISOString(), to: to.toISOString(), limit: 500,
        q: q.value || undefined, category: category.value || undefined, severity: severity.value || undefined,
      }),
      assetAgentClient.agents({ limit: 500 }),
    ])
    if (eventsResult.status === 'fulfilled') {
      items.value = unwrap(eventsResult.value).items || []
    } else {
      throw eventsResult.reason
    }
    agents.value = agentsResult.status === 'fulfilled' ? (unwrap(agentsResult.value).items || []) : []
  } catch (e) {
    error.value = e?.message || '事件查询失败'
    items.value = []
  } finally {
    loading.value = false
  }
}

function setWindow(k) { if (win.value !== k) { win.value = k; load() } }

onMounted(load)
</script>

<style scoped>
.clickable { cursor: pointer; }
.ev-main { max-width: 360px; }
.ev-main b { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.detail { display: grid; gap: 18px; }
.detail-top { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.detail h3 { margin-bottom: 10px; color: var(--v-ink); font-size: 12.5px; font-weight: 620; }
.event-drawer { width: min(38vw, 520px); max-width: 520px; }
.event-drawer .v-kv dt, .event-drawer .v-kv dd { padding: 8px 10px; font-size: 11.5px; }
.event-drawer .detail { gap: 14px; }
.tech { border-top: 1px solid var(--v-line); padding-top: 12px; }
.tech summary { cursor: pointer; color: var(--v-ink-2); font-size: 12px; font-weight: 600; }
.raw { margin: 10px 0 0; max-height: 320px; padding: 12px; overflow-y: auto; overflow-x: hidden; border: 1px solid var(--v-line); border-radius: var(--v-radius-sm); background: var(--v-surface-3); color: var(--v-ink-2); font-family: var(--v-mono); font-size: 10.5px; line-height: 1.55; white-space: pre-wrap; word-break: break-word; }
</style>
