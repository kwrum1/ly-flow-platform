<template>
  <section class="v-page">
    <header class="v-head">
      <div>
        <p class="v-eyebrow">DATA TRUST</p>
        <h1>数据与健康</h1>
        <p>检测结论取决于字段是否真实存在。本页只统计实际返回的样本：缺失保留为未知，端口 0 视为未知，空样本不显示 0%。</p>
      </div>
      <div class="v-head-actions">
        <div class="v-tabs">
          <button v-for="w in windows" :key="w.key" type="button" class="v-tab" :class="{ active: win === w.key }" @click="setWindow(w.key)">{{ w.label }}</button>
        </div>
        <button class="v-btn" type="button" :disabled="loading" @click="load">{{ loading ? '采样中…' : '重新采样' }}</button>
      </div>
    </header>

    <div v-if="error" class="v-error">{{ error }}</div>

    <section class="v-grid c4">
      <article class="v-stat"><span class="v-stat-label"><i />样本记录</span><strong class="v-stat-value">{{ ready.events ? field.sample : '—' }}</strong><span class="v-stat-note">{{ ready.events ? `代表 ${formatNumber(field.occurrence)} 次命中` : '正在采样' }}</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />五元组完整率</span><strong class="v-stat-value" :class="tone(field.completeRate)">{{ field.completeRate === null ? '—' : field.completeRate + '%' }}</strong><span class="v-stat-note">需地址与 1–65535 端口同时存在</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />端口未知率</span><strong class="v-stat-value" :class="tone(invert(portRate))">{{ portRate === null ? '—' : portRate + '%' }}</strong><span class="v-stat-note">dst_port 为空或 0</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />可查询跨度</span><strong class="v-stat-value">{{ span.days === null ? '—' : span.days + ' 天' }}</strong><span class="v-stat-note">样本内最早事件至今</span></article>
    </section>

    <section class="v-grid c2">
      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">字段完整率</div><span class="v-panel-meta">样本 {{ field.sample }} 条</span></div>
        <div class="v-table-wrap">
          <table class="v-table">
            <thead><tr><th>字段</th><th>缺失</th><th>缺失率</th><th>状态</th></tr></thead>
            <tbody>
              <tr v-for="row in field.fields" :key="row.key">
                <td><b>{{ row.label }}</b><small>{{ row.key }}</small></td>
                <td class="num">{{ row.missing }}</td>
                <td class="num">{{ row.rate === null ? '—' : row.rate + '%' }}</td>
                <td><span class="v-state" :data-state="row.rate === null ? 'unknown' : row.rate === 0 ? 'healthy' : 'degraded'">{{ row.rate === null ? '无样本' : row.rate === 0 ? '完整' : '有缺失' }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </article>

      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">按来源质量</div><span class="v-panel-meta">按命中次数排序</span></div>
        <div class="v-table-wrap">
          <table class="v-table">
            <thead><tr><th>来源</th><th>样本</th><th>命中</th><th>地址缺失</th><th>端口未知</th></tr></thead>
            <tbody>
              <tr v-for="row in sourceRows" :key="row.key">
                <td><b>{{ sourceLabel(row.key) }}</b><small>{{ row.key }}</small></td>
                <td class="num">{{ row.sample }}</td>
                <td class="num">{{ formatNumber(row.occurrence) }}</td>
                <td class="num">{{ row.missingRate === null ? '—' : row.missingRate + '%' }}</td>
                <td class="num">{{ row.portUnknownRate === null ? '—' : row.portUnknownRate + '%' }}</td>
              </tr>
            </tbody>
          </table>
          <div v-if="!sourceRows.length" class="v-table-empty">{{ ready.events ? '窗口内没有样本' : '正在采样' }}</div>
        </div>
      </article>
    </section>

    <section class="v-grid c2">
      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">引擎健康</div><span class="v-panel-meta">{{ engineRows.length }} 个实例</span></div>
        <div class="v-table-wrap">
          <table class="v-table">
            <thead><tr><th>引擎</th><th>主机</th><th>状态</th><th>版本</th><th>规则包</th><th>最后事件</th></tr></thead>
            <tbody>
              <tr v-for="e in engineRows" :key="`${e.agent_id}-${e.engine}`">
                <td><b>{{ e.engine }}</b></td>
                <td>{{ e.hostname || '-' }}<small>{{ e.agent_id }}</small></td>
                <td><span class="v-state" :data-state="engineState(e).tone">{{ engineState(e).label }}</span></td>
                <td>{{ e.version || '-' }}</td>
                <td>{{ e.rule_pack_version || '-' }}</td>
                <td class="num">{{ e.last_event_at ? shortTime(e.last_event_at) : '—' }}</td>
              </tr>
            </tbody>
          </table>
          <div v-if="!engineRows.length" class="v-table-empty">暂无引擎心跳</div>
        </div>
      </article>

      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">组件健康</div><span class="v-panel-meta">{{ degraded.length }} 项未就绪 / 共 {{ componentRows.length }} 项</span></div>
        <div class="v-table-wrap">
          <table class="v-table">
            <thead><tr><th>组件</th><th>状态</th><th>说明</th></tr></thead>
            <tbody>
              <tr v-if="!ready.components"><td colspan="3" class="v-empty">正在读取</td></tr>
              <tr v-for="c in componentRows" :key="c.name">
                <td><b class="v-mono">{{ c.name }}</b></td>
                <td><span class="v-state" :data-state="c.state">{{ c.label }}</span></td>
                <td class="msg">{{ c.message || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </article>
    </section>

    <article class="v-panel">
      <div class="v-panel-head">
        <div class="v-panel-title">采集可见性</div>
        <span class="v-panel-meta">{{ capture.agents.length ? `${capture.agents.length} 个传感器` : '暂无传感器上报' }}</span>
      </div>
      <div class="v-table-wrap">
        <table class="v-table">
          <thead><tr><th>传感器</th><th>状态</th><th>引擎</th><th>窗口</th><th>丢包</th><th>丢包率</th><th>原因</th><th>持续</th></tr></thead>
          <tbody>
            <tr v-for="agent in capture.agents" :key="agent.agent_id">
              <td><b class="v-mono">{{ agent.agent_id }}</b><small>{{ agent.interface || '未绑定网卡' }}</small></td>
              <td><span class="v-state" :data-state="agent.state">{{ stateLabel(agent.state) }}</span></td>
              <td>{{ agent.active_engine || '—' }}<small v-if="agent.fallback_reason">{{ agent.requested_engine }} → {{ agent.fallback_reason }}</small></td>
              <td class="num">{{ captureWindow(agent.window) }}</td>
              <td class="num">{{ agent.window && agent.window.valid ? formatNumber(agent.window.kernel_drop_delta + agent.window.ring_freeze_delta) : '—' }}</td>
              <td class="num">{{ agent.drop_ratio_percent === null || agent.drop_ratio_percent === undefined ? '—' : agent.drop_ratio_percent.toFixed(2) + '%' }}</td>
              <td class="msg">{{ reasonLabel(agent.reason) }}</td>
              <td class="num">{{ sinceText(agent.since) }}</td>
            </tr>
          </tbody>
        </table>
        <div v-if="!capture.agents.length" class="v-table-empty">{{ capture.reason === 'no_sensor_report' ? '没有传感器上报采集计数器，状态保持未知' : '正在读取' }}</div>
      </div>
      <div class="v-panel-body">
        <ul class="notes">
          <li>健康要求：有效采样窗口、零丢包、零发布错误，且收包分母可测。</li>
          <li>分母不可测时只报告丢包数，不报告丢包率；服务重启后到下一次心跳之间状态为未知。</li>
        </ul>
      </div>
    </article>

    <article class="v-panel">
      <div class="v-panel-head"><div class="v-panel-title">时间与留存</div><span class="v-panel-meta">口径说明见下</span></div>
      <div class="v-panel-body">
        <dl class="v-kv">
          <dt>时间源</dt><dd>{{ clock.label }}<span class="v-dim"> · {{ clock.tone === 'success' ? '已同步' : clock.tone === 'warning' ? '手动时间源不会自动校准' : '未读取到时间源' }}</span></dd>
          <dt>平台偏移</dt><dd class="v-mono">{{ offsetText }}</dd>
          <dt>平台时间</dt><dd>{{ platformTime }}</dd>
          <dt>服务端时间</dt><dd>{{ serverTime }}</dd>
          <dt>样本跨度</dt><dd>{{ span.earliest ? `${shortTime(span.earliest)} ~ ${shortTime(span.latest)}` : '无有效时间字段' }}</dd>
        </dl>
        <ul class="notes">
          <li>样本每次最多 200 条聚合记录，比率是样本比率，不是全量断言。</li>
          <li>缺失值不会补 0；端口 0 一律计为未知。</li>
          <li>留存跨度只反映样本中能查到的最早时间，不等同于存储 TTL 或合规承诺。</li>
        </ul>
      </div>
    </article>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { opsClient } from '../../api/domain'
import { classifyClockSource, computeFieldQuality, computeSourceQuality, queryableSpan } from '../../domain/data-quality'
import { formatChinaDateTime } from '../../shared/time'

const windows = [
  { key: '24h', label: '24 小时', ms: 86400000 },
  { key: '7d', label: '7 天', ms: 604800000 },
  { key: '30d', label: '30 天', ms: 2592000000 },
]

const win = ref('7d')
const loading = ref(false)
const error = ref('')
const events = ref([])
const engines = ref([])
const components = ref(null)
const systemTime = ref(null)
const ready = ref({ events: false, components: false, engines: false })

const field = computed(() => computeFieldQuality(events.value))
const sourceRows = computed(() => computeSourceQuality(events.value))
const span = computed(() => queryableSpan(events.value))
const portRate = computed(() => field.value.fields.find((f) => f.key === 'dst_port')?.rate ?? null)
const clock = computed(() => classifyClockSource(systemTime.value?.source))
const offsetText = computed(() => { const v = Number(systemTime.value?.offset_ms); return Number.isFinite(v) ? `${Math.round(v / 1000)} s` : '未读取' })
const platformTime = computed(() => systemTime.value?.platform_time ? formatChinaDateTime(systemTime.value.platform_time) : '—')
const serverTime = computed(() => systemTime.value?.server_time ? formatChinaDateTime(systemTime.value.server_time) : '—')

const engineRows = computed(() => (engines.value || []).map((e) => ({ ...e })))
const engineState = (engine) => {
  const state = String(engine.state || '')
  if (state === 'running') return { label: '运行中', tone: 'healthy' }
  if (state === 'adapter_active') return { label: '适配器采集', tone: 'healthy' }
  if (state === 'installed') return { label: '已安装未运行', tone: 'degraded' }
  if (state === 'disabled') return { label: '未启用', tone: 'unknown' }
  if (state === 'not_installed') return { label: '未安装', tone: 'unknown' }
  return engine.running ? { label: '运行中', tone: 'healthy' } : { label: '未运行', tone: 'failed' }
}
const capture = computed(() => {
  const raw = components.value?.capture
  return {
    state: raw?.state || 'unknown',
    reason: raw?.reason || '',
    agents: Array.isArray(raw?.agents) ? raw.agents : [],
  }
})
const stateLabel = (s) => ({ healthy: '正常', degraded: '降级', partial: '部分失明', failed: '失败', unknown: '未知', disabled: '未启用' })[s] || s || '未知'
const reasonLabel = (r) => ({
  '': '无',
  no_previous_sample: '等待第二个采样点',
  no_sensor_report: '无传感器上报',
  counters_missing: '计数器缺失',
  'counter reset': '计数器重置',
  'sampling gap': '采样间隔过大',
  'invalid sample window': '采样窗口无效',
  capture_disabled: '采集未启用',
  interface_invalid: '网卡无效',
  spool_unreadable: '落盘队列不可读',
  publish_errors: '发布错误',
  packet_loss: '存在丢包',
  'denominator source changed': '分母来源切换',
  denominator_unknown: '收包分母不可测',
  loss_unknown: '丢包计数不可信',
  sensor_stale: '传感器无新包',
  clock_skewed: '时钟偏移',
  spool_pressured: '落盘队列拥塞',
  engine_fallback: '采集引擎降级回退',
})[r] || r
const captureWindow = (w) => (w && w.valid ? `${Math.round(w.seconds)}s` : '无效')
const sinceText = (v) => {
  if (!v) return '—'
  const ms = Date.now() - new Date(v).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '—'
  const m = Math.floor(ms / 60000)
  if (m < 60) return `${m} 分钟`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h} 小时`
  return `${Math.floor(h / 24)} 天`
}
const componentRows = computed(() => {
  const map = components.value?.components || {}
  return Object.keys(map).sort().map((name) => {
    const item = map[name] || {}
    const state = item.status === 'ok' ? 'healthy' : item.status === 'degraded' ? 'degraded' : item.status === 'error' ? 'failed' : 'unknown'
    return { name, state, label: { healthy: '正常', degraded: '降级', failed: '失败', unknown: '未知' }[state], message: item.message }
  })
})
const degraded = computed(() => componentRows.value.filter((c) => c.state !== 'healthy'))

function unwrap(r) { return r?.data?.data ?? r?.data ?? r ?? {} }
function invert(v) { return v === null || v === undefined ? null : 100 - v }
function tone(v) { if (v === null || v === undefined) return 'unknown'; if (v >= 95) return 'success'; if (v >= 70) return 'warning'; return 'danger' }
function formatNumber(v) { return (Number(v) || 0).toLocaleString('zh-CN') }
function shortTime(v) { return v ? formatChinaDateTime(v) : '-' }
function sourceLabel(v) { return ({ 'ly-security-engine': '安全引擎', suricata: 'Suricata', log_audit: '日志审计', runtime: '主机运行时', rasp: 'RASP', wazuh: 'Wazuh（历史）' })[v] || v || '未知' }

async function load() {
  loading.value = true
  error.value = ''
  const w = windows.find((x) => x.key === win.value) || windows[1]
  const to = new Date()
  const from = new Date(to.getTime() - w.ms)
  const [e, c, t, g] = await Promise.allSettled([
    opsClient.eventSample({ from: from.toISOString(), to: to.toISOString(), limit: 200 }),
    opsClient.components(),
    opsClient.systemTime(),
    opsClient.engineHealth(),
  ])
  if (e.status === 'fulfilled') { events.value = unwrap(e.value).items || []; ready.value.events = true }
  if (c.status === 'fulfilled') { components.value = c.value; ready.value.components = true }
  if (t.status === 'fulfilled') systemTime.value = t.value
  if (g.status === 'fulfilled') { engines.value = unwrap(g.value).items || []; ready.value.engines = true }
  const failed = [e, c, t, g].filter((x) => x.status === 'rejected').length
  if (failed === 4) error.value = '健康接口全部不可达，页面不显示任何"正常"结论。'
  else if (failed) error.value = `${failed} 个接口读取失败，对应区域显示为未知。`
  loading.value = false
}

function setWindow(k) { if (win.value !== k) { win.value = k; load() } }

onMounted(load)
</script>

<style scoped>
.msg { max-width: 420px; overflow: hidden; text-overflow: ellipsis; color: var(--v-ink-3); }
.notes { margin: 14px 0 0; padding-left: 18px; color: var(--v-ink-3); font-size: 11.5px; line-height: 1.9; }
</style>
