<template>
  <section class="sx-page dq-page">
    <header class="sx-page-head">
      <div>
        <p class="sx-kicker">DATA TRUST · FIELD LINEAGE · RETENTION</p>
        <h2 class="sx-title">数据质量</h2>
        <p class="sx-subtitle">
          检测结论的可信度取决于字段是否真实存在。本页只统计实际返回的样本：缺失值保留为 unknown，端口 0 视为未知，
          空样本不显示为 0%。所有比率都标注样本量。
        </p>
      </div>
      <div class="sx-head-actions">
        <div class="dq-window" role="group" aria-label="采样窗口">
          <button
            v-for="item in windows"
            :key="item.key"
            type="button"
            class="dq-window-btn"
            :class="{ active: item.key === activeWindow }"
            @click="setWindow(item.key)"
          >{{ item.label }}</button>
        </div>
        <button class="sx-btn" type="button" :disabled="loading" @click="load">{{ loading ? '采样中…' : '重新采样' }}</button>
      </div>
    </header>

    <div v-if="error" class="sx-error">{{ error }}</div>

    <section class="dq-kpis">
      <article class="sx-metric">
        <span class="sx-metric-label"><i />样本记录</span>
        <strong class="sx-metric-value">{{ eventsReady ? formatNumber(field.sample) : '—' }}</strong>
        <span class="sx-metric-note">{{ eventsReady ? `上限 500 条 · 代表 ${formatNumber(field.occurrence)} 次命中` : '正在采样' }}</span>
      </article>
      <article class="sx-metric">
        <span class="sx-metric-label"><i />五元组完整率</span>
        <strong class="sx-metric-value" :class="toneFor(field.completeRate)">{{ field.completeRate === null ? '—' : field.completeRate + '%' }}</strong>
        <span class="sx-metric-note">需 src/dst 与 1–65535 端口同时存在</span>
      </article>
      <article class="sx-metric">
        <span class="sx-metric-label"><i />端口未知率</span>
        <strong class="sx-metric-value" :class="toneFor(inverse(portUnknownRate))">{{ portUnknownRate === null ? '—' : portUnknownRate + '%' }}</strong>
        <span class="sx-metric-note">dst_port 为空或等于 0</span>
      </article>
      <article class="sx-metric">
        <span class="sx-metric-label"><i />地址缺失率</span>
        <strong class="sx-metric-value" :class="toneFor(inverse(addressMissingRate))">{{ addressMissingRate === null ? '—' : addressMissingRate + '%' }}</strong>
        <span class="sx-metric-note">src_ip 或 dst_ip 为空</span>
      </article>
    </section>

    <section class="dq-grid-2">
      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">字段完整率</div>
          <span class="sx-panel-meta">样本 {{ eventsReady ? formatNumber(field.sample) : '—' }} 条</span>
        </div>
        <div class="sx-table-wrap">
          <table class="sx-table">
            <thead><tr><th>字段</th><th>缺失记录</th><th>缺失率</th><th>状态</th></tr></thead>
            <tbody>
              <tr v-for="row in field.fields" :key="row.key">
                <td><b>{{ row.label }}</b><small>{{ row.key }}</small></td>
                <td class="sx-mono">{{ formatNumber(row.missing) }}</td>
                <td class="sx-mono">{{ row.rate === null ? '—' : row.rate + '%' }}</td>
                <td><span class="sx-state" :data-state="row.rate === null ? 'unknown' : row.rate === 0 ? 'healthy' : row.rate > 20 ? 'degraded' : 'installed'">{{ row.rate === null ? '无样本' : row.rate === 0 ? '完整' : '有缺失' }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </article>

      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">按来源的采集质量</div>
          <span class="sx-panel-meta">按命中次数排序</span>
        </div>
        <div class="sx-table-wrap">
          <table class="sx-table">
            <thead><tr><th>来源</th><th>样本</th><th>命中</th><th>地址缺失</th><th>端口未知</th></tr></thead>
            <tbody>
              <tr v-if="!sourceRows.length"><td colspan="5" class="sx-empty">{{ eventsReady ? '窗口内没有样本' : '正在采样' }}</td></tr>
              <tr v-for="row in sourceRows" :key="row.key">
                <td><b>{{ sourceLabel(row.key) }}</b><small>{{ row.key }}</small></td>
                <td class="sx-mono">{{ formatNumber(row.sample) }}</td>
                <td class="sx-mono">{{ formatNumber(row.occurrence) }}</td>
                <td class="sx-mono">{{ row.missingRate === null ? '—' : row.missingRate + '%' }}</td>
                <td class="sx-mono">{{ row.portUnknownRate === null ? '—' : row.portUnknownRate + '%' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </article>
    </section>

    <section class="dq-grid-2">
      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">每日新增（按 first_seen）</div>
          <span class="sx-panel-meta">窗口 {{ windowLabel }}</span>
        </div>
        <div class="sx-panel-body">
          <div v-if="dailyRows.length" class="dq-daily">
            <div v-for="row in dailyRows" :key="row.day" class="dq-daily-row">
              <span class="sx-mono">{{ row.day }}</span>
              <span class="dq-daily-track"><i :style="{ width: dailyPercent(row.count) + '%' }" /></span>
              <b class="sx-mono">{{ formatNumber(row.count) }}</b>
            </div>
          </div>
          <div v-else class="sx-empty"><div><strong>{{ eventsReady ? '窗口内没有可归属日期的样本' : '正在采样' }}</strong></div></div>
        </div>
      </article>

      <article class="sx-panel">
        <div class="sx-panel-head">
          <div class="sx-panel-title">留存与时间质量</div>
          <RouterLink class="sx-panel-meta" to="/control-center">平台设置 →</RouterLink>
        </div>
        <div class="sx-panel-body dq-facts">
          <div>
            <span>样本可查询跨度</span>
            <b class="sx-mono">{{ span.days === null ? '未知' : span.days + ' 天' }}</b>
            <small>{{ span.earliest ? `${formatTime(span.earliest)} ~ ${formatTime(span.latest)}` : '无有效时间字段' }}</small>
          </div>
          <div>
            <span>时间源</span>
            <b>{{ clock.label }}</b>
            <small>{{ clock.tone === 'warning' ? '手动时间源不会自动校准，跨设备时序不可靠' : clock.tone === 'success' ? '已由系统时间源同步' : '未读取到时间源' }}</small>
          </div>
          <div>
            <span>平台偏移</span>
            <b class="sx-mono">{{ offsetText }}</b>
            <small>offset_ms 来自 /api/v1/system/time</small>
          </div>
          <div>
            <span>服务端时间</span>
            <b class="sx-mono">{{ serverTime }}</b>
            <small>平台时间 {{ platformTime }}</small>
          </div>
        </div>
      </article>
    </section>

    <section class="sx-panel">
      <div class="sx-panel-head">
        <div class="sx-panel-title">组件健康</div>
        <span class="sx-panel-meta">{{ componentsReady ? `${degraded.length} 项未就绪 / 共 ${componentTotal} 项` : '加载中' }}</span>
      </div>
      <div class="sx-table-wrap">
        <table class="sx-table">
          <thead><tr><th>组件</th><th>状态</th><th>说明</th><th>修复建议</th></tr></thead>
          <tbody>
            <tr v-if="!componentsReady"><td colspan="4" class="sx-empty">正在读取 /api/v1/debug/components</td></tr>
            <tr v-for="row in componentRows" :key="row.name">
              <td><b class="sx-mono">{{ row.name }}</b></td>
              <td><span class="sx-state" :data-state="row.state">{{ row.stateLabel }}</span></td>
              <td class="dq-msg">{{ row.message || '-' }}</td>
              <td class="dq-msg">{{ row.remediation || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="sx-panel dq-notes">
      <div class="sx-panel-head"><div class="sx-panel-title">口径说明</div></div>
      <div class="sx-panel-body">
        <ul>
          <li><b>样本</b>：本页每次最多读取 500 条聚合记录，比率是样本比率，不是全量断言。</li>
          <li><b>缺失</b>：空字符串、null、undefined 都记为缺失；不会补 0，也不会推断。</li>
          <li><b>端口 0</b>：历史数据用 0 表示未知端口，本页一律计为未知。</li>
          <li><b>留存</b>：只反映样本里能查到的最早时间，不等同于存储层 TTL 或合规承诺。</li>
          <li><b>时间</b>：手动时间源即使偏移很小也标记为未同步。</li>
        </ul>
      </div>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { opsClient } from '../api/domain'
import {
  classifyClockSource,
  computeDailyVolume,
  computeFieldQuality,
  computeSourceQuality,
  queryableSpan,
} from '../domain/data-quality'
import { formatChinaDateTime } from '../shared/time'

const windows = [
  { key: '24h', label: '24 小时', ms: 24 * 60 * 60 * 1000 },
  { key: '7d', label: '7 天', ms: 7 * 24 * 60 * 60 * 1000 },
  { key: '30d', label: '30 天', ms: 30 * 24 * 60 * 60 * 1000 },
]

const activeWindow = ref('7d')
const loading = ref(false)
const error = ref('')
const events = ref([])
const components = ref(null)
const systemTime = ref(null)
const stats = ref({})

const ready = reactive({ events: false, components: false, time: false })
const eventsReady = computed(() => ready.events)
const componentsReady = computed(() => ready.components)
const windowLabel = computed(() => windows.find((item) => item.key === activeWindow.value)?.label || '7 天')

const field = computed(() => computeFieldQuality(events.value))
const sourceRows = computed(() => computeSourceQuality(events.value))
const dailyRows = computed(() => computeDailyVolume(events.value))
const span = computed(() => queryableSpan(events.value))

const portUnknownRate = computed(() => {
  const row = field.value.fields.find((item) => item.key === 'dst_port')
  return row ? row.rate : null
})

const addressMissingRate = computed(() => {
  if (!field.value.sample) return null
  const records = events.value.filter((item) => !item.src_ip || !item.dst_ip).length
  return Math.round((records / field.value.sample) * 1000) / 10
})

const clock = computed(() => classifyClockSource(systemTime.value?.source))
const offsetText = computed(() => {
  const value = Number(systemTime.value?.offset_ms)
  if (!Number.isFinite(value)) return '未读取'
  return `${Math.round(value / 1000)} s`
})
const platformTime = computed(() => (systemTime.value?.platform_time ? formatChinaDateTime(systemTime.value.platform_time) : '—'))
const serverTime = computed(() => (systemTime.value?.server_time ? formatChinaDateTime(systemTime.value.server_time) : '—'))

const componentRows = computed(() => {
  const map = components.value?.components || {}
  return Object.keys(map)
    .sort()
    .map((name) => {
      const item = map[name] || {}
      const state = item.status === 'ok'
        ? 'healthy'
        : item.status === 'degraded'
          ? 'degraded'
          : item.status === 'error'
            ? 'failed'
            : 'unknown'
      return {
        name,
        state,
        stateLabel: { healthy: '正常', degraded: '降级', failed: '失败', unknown: '未知' }[state],
        message: item.message,
        remediation: item.remediation,
      }
    })
})
const componentTotal = computed(() => componentRows.value.length)
const degraded = computed(() => componentRows.value.filter((row) => row.state !== 'healthy'))

function inverse(value) {
  return value === null || value === undefined ? null : 100 - value
}

function toneFor(value) {
  if (value === null || value === undefined) return 'unknown'
  if (value >= 95) return 'success'
  if (value >= 70) return 'warning'
  return 'danger'
}

function dailyPercent(count) {
  const max = Math.max(1, ...dailyRows.value.map((row) => row.count))
  return Math.max(2, Math.round((count / max) * 100))
}

function formatNumber(value) {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed.toLocaleString('zh-CN') : '0'
}

function formatTime(value) {
  return value ? formatChinaDateTime(value) : '—'
}

function sourceLabel(value) {
  return ({ 'ly-security-engine': '安全引擎', suricata: 'Suricata', wazuh: 'Wazuh', runtime: '主机运行时', rasp: 'RASP', traffic: '流量检测', log_audit: '日志审计', yara: 'YARA', lyprobe: 'LyFlow 探针' })[value] || value || '未知'
}

function setWindow(key) {
  if (activeWindow.value === key) return
  activeWindow.value = key
  load()
}

function unwrap(response) {
  return response?.data?.data ?? response?.data ?? response ?? {}
}

async function load() {
  loading.value = true
  error.value = ''
  const ms = windows.find((item) => item.key === activeWindow.value)?.ms || 7 * 86400000
  const to = new Date()
  const from = new Date(to.getTime() - ms)

  const [eventsResult, componentsResult, timeResult, statsResult] = await Promise.allSettled([
    opsClient.eventSample({ from: from.toISOString(), to: to.toISOString(), limit: 500 }),
    opsClient.components(),
    opsClient.systemTime(),
    opsClient.stats(),
  ])

  if (eventsResult.status === 'fulfilled') {
    const payload = unwrap(eventsResult.value)
    events.value = Array.isArray(payload) ? payload : (payload.items || [])
    ready.events = true
  } else {
    ready.events = false
  }

  if (componentsResult.status === 'fulfilled') {
    components.value = componentsResult.value
    ready.components = true
  } else {
    ready.components = false
  }

  if (timeResult.status === 'fulfilled') {
    systemTime.value = timeResult.value
    ready.time = true
  } else {
    ready.time = false
  }

  if (statsResult.status === 'fulfilled') stats.value = unwrap(statsResult.value)

  const failures = [eventsResult, componentsResult, timeResult, statsResult].filter((item) => item.status === 'rejected').length
  if (failures === 4) error.value = '数据质量接口全部不可达，页面不显示任何"正常"结论。'
  else if (failures) error.value = `${failures} 个接口读取失败；对应区域显示为未知。`

  loading.value = false
}

onMounted(load)
</script>

<style scoped>
.dq-page { gap: 14px; }

.dq-window { display: inline-flex; overflow: hidden; border: var(--lyf-hairline-strong); border-radius: var(--lyf-radius-sm); background: var(--lyf-surface); }
.dq-window-btn { height: 32px; padding: 0 11px; border: 0; border-right: var(--lyf-hairline); background: transparent; color: var(--lyf-ink-3); font: inherit; font-size: 11.5px; cursor: pointer; }
.dq-window-btn:last-child { border-right: 0; }
.dq-window-btn:hover { color: var(--lyf-accent); background: var(--lyf-accent-soft); }
.dq-window-btn.active { background: var(--lyf-ink); color: var(--lyf-surface); font-weight: 600; }
[data-theme='dark'] .dq-window-btn.active { background: var(--lyf-accent); color: #06120f; }

.dq-kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.dq-grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }

.dq-daily { display: grid; gap: 7px; }
.dq-daily-row { display: grid; grid-template-columns: 92px minmax(0, 1fr) 60px; align-items: center; gap: 10px; }
.dq-daily-row span { color: var(--lyf-ink-3); font-size: 10.5px; }
.dq-daily-track { height: 4px; overflow: hidden; border-radius: 2px; background: var(--lyf-surface-3); }
.dq-daily-track i { display: block; height: 100%; background: var(--lyf-accent); opacity: 0.75; }
.dq-daily-row b { color: var(--lyf-ink); font-size: 11px; font-weight: 600; text-align: right; }

.dq-facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.dq-facts div { display: grid; gap: 2px; padding: 11px; border: var(--lyf-hairline); border-radius: var(--lyf-radius-sm); background: var(--lyf-surface-2); }
.dq-facts span { color: var(--lyf-ink-3); font-size: 10.5px; }
.dq-facts b { color: var(--lyf-ink); font-size: 15px; font-weight: 600; }
.dq-facts small { color: var(--lyf-ink-3); font-size: 10px; line-height: 1.45; }

.dq-msg { max-width: 360px; overflow: hidden; color: var(--lyf-ink-3); font-size: 11px; text-overflow: ellipsis; }

.dq-notes ul { margin: 0; padding-left: 18px; color: var(--lyf-ink-2); font-size: 11.5px; line-height: 1.9; }
.dq-notes b { color: var(--lyf-ink); font-weight: 600; }

@media (max-width: 1180px) {
  .dq-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .dq-grid-2 { grid-template-columns: minmax(0, 1fr); }
}

@media (max-width: 640px) {
  .dq-kpis { grid-template-columns: minmax(0, 1fr); }
  .dq-facts { grid-template-columns: minmax(0, 1fr); }
}
</style>
