<template>
  <section class="sx-page engines-page">
    <header class="sx-page-head">
      <div>
        <p class="sx-kicker">DETECTION ENGINE HEALTH</p>
        <h2 class="sx-title">引擎健康</h2>
        <p class="sx-subtitle">按 Agent 查看 Suricata、Wazuh、YARA、RASP 的安装、运行、规则包和最后一次事件；状态直接来自引擎心跳。</p>
      </div>
      <div class="sx-head-actions">
        <span class="sx-live"><i />LIVE</span>
        <button class="sx-btn" type="button" :disabled="loading" @click="load">刷新</button>
      </div>
    </header>

    <section class="engine-stats">
      <article class="sx-metric"><span class="sx-metric-label"><i />已安装实例</span><strong class="sx-metric-value">{{ formatNumber(installedItems.length) }}</strong><span class="sx-metric-note">未安装实例默认折叠</span></article>
      <article class="sx-metric"><span class="sx-metric-label"><i />运行中</span><strong class="sx-metric-value success">{{ formatNumber(runningCount) }}</strong><span class="sx-metric-note">running = true 且 Agent 在线</span></article>
      <article class="sx-metric"><span class="sx-metric-label"><i />离线 / 异常</span><strong class="sx-metric-value danger">{{ formatNumber(abnormalCount) }}</strong><span class="sx-metric-note">仅统计已安装但未运行</span></article>
      <article class="sx-metric"><span class="sx-metric-label"><i />规则总数</span><strong class="sx-metric-value">{{ formatNumber(ruleTotal) }}</strong><span class="sx-metric-note">规则中心统计</span></article>
    </section>

    <div v-if="error" class="sx-error">{{ error }}</div>

    <section class="engine-card-grid">
      <article v-for="engine in engineCards" :key="engine.key" class="sx-panel engine-card">
        <div class="engine-card-head">
          <span class="engine-monogram" :class="engine.tone">{{ engine.short }}</span>
          <div><b>{{ engine.label }}</b><small>{{ engine.count }} 个实例</small></div>
          <span class="sx-badge" :class="engine.tone">{{ engine.status }}</span>
        </div>
        <div class="engine-card-body">
          <div><span>运行实例</span><b>{{ engine.running }}/{{ engine.count }}</b></div>
          <div><span>最近事件</span><b>{{ engine.lastEvent }}</b></div>
          <div><span>规则包</span><b>{{ engine.rulePack || '-' }}</b></div>
        </div>
      </article>
    </section>

    <section class="sx-panel">
      <div class="sx-panel-head">
        <div class="sx-panel-title">引擎实例</div>
        <label class="show-all"><input v-model="showUninstalled" type="checkbox" />显示未安装实例</label>
      </div>
      <div class="sx-table-wrap sx-scroll">
        <table class="sx-table engine-table">
          <thead><tr><th>引擎</th><th>Agent / 主机</th><th>状态</th><th>版本</th><th>规则包</th><th>最后事件</th><th>最后心跳</th><th>错误</th></tr></thead>
          <tbody>
            <tr v-if="loading && !items.length"><td colspan="8" class="sx-empty">正在读取引擎健康…</td></tr>
            <tr v-else-if="!visibleItems.length"><td colspan="8" class="sx-empty"><div><strong>没有已安装引擎心跳</strong>等待 Agent 上报 capability。</div></td></tr>
            <tr v-for="item in visibleItems" :key="`${item.agent_id}-${item.engine}`">
              <td><b>{{ engineLabel(item.engine) }}</b><small>{{ item.output_path || '-' }}</small></td>
              <td><b>{{ item.hostname || '-' }}</b><small>{{ item.agent_id }} · {{ item.ip || '-' }}</small></td>
              <td><span class="sx-badge" :class="statusTone(item)">{{ statusLabel(item) }}</span></td>
              <td>{{ item.version || '-' }}</td>
              <td>{{ item.rule_pack_version || '-' }}</td>
              <td>{{ formatTime(item.last_event_at) }}</td>
              <td>{{ formatTime(item.last_heartbeat) }}</td>
              <td class="error-cell">{{ item.last_error || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { assetAgentClient, ruleClient } from '../api/domain'

const loading = ref(false)
const error = ref('')
const items = ref([])
const ruleTotal = ref(0)
const showUninstalled = ref(false)

const engineDefinitions = [
  { key: 'suricata', label: 'Suricata', short: 'SU' },
  { key: 'wazuh', label: 'Wazuh', short: 'WA' },
  { key: 'yara', label: 'YARA', short: 'YA' },
  { key: 'rasp', label: 'OpenRASP', short: 'RA' },
  { key: 'dpi', label: 'DPI Engine', short: 'DP' },
]

const installedItems = computed(() => items.value.filter((item) => item.installed !== false))
const visibleItems = computed(() => showUninstalled.value ? items.value : installedItems.value)
const runningCount = computed(() => installedItems.value.filter((item) => isRunning(item)).length)
const abnormalCount = computed(() => installedItems.value.filter((item) => !isRunning(item)).length)
const engineCards = computed(() => engineDefinitions.map((definition) => {
  const rows = installedItems.value.filter((item) => item.engine === definition.key)
  const running = rows.filter(isRunning).length
  const last = rows.map((item) => item.last_event_at).filter(Boolean).sort().at(-1)
  return {
    ...definition,
    count: rows.length,
    running,
    status: !rows.length ? '无实例' : running === rows.length ? '正常' : running > 0 ? '部分异常' : '异常',
    tone: !rows.length ? 'muted' : running === rows.length ? 'low' : running > 0 ? 'medium' : 'critical',
    lastEvent: last ? formatTime(last) : '-',
    rulePack: rows[0]?.rule_pack_version || '',
  }
}))

function unwrap(response) { return response?.data?.data ?? response?.data ?? response ?? {} }
function formatNumber(value) { return Number(value || 0).toLocaleString('zh-CN') }
function formatTime(value) { if (!value) return '-'; const date = new Date(value); return Number.isNaN(date.getTime()) || date.getFullYear() < 2000 ? '-' : date.toLocaleString('zh-CN', { hour12: false }) }
function engineLabel(value) { return ({ suricata: 'Suricata', wazuh: 'Wazuh', yara: 'YARA', rasp: 'OpenRASP', dpi: 'DPI Engine' })[value] || value || '-' }
function isRunning(item) { return Boolean(item.running) && String(item.agent_status || '').toLowerCase() !== 'offline' }
function statusLabel(item) {
  if (!item.installed) return '未安装'
  if (String(item.agent_status || '').toLowerCase() === 'offline') return 'Agent 离线'
  return item.running ? '运行中' : '异常'
}
function statusTone(item) {
  if (!item.installed) return 'muted'
  if (String(item.agent_status || '').toLowerCase() === 'offline') return 'medium'
  return item.running ? 'low' : 'critical'
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [health, rules] = await Promise.all([assetAgentClient.engineHealth(), ruleClient.stats()])
    const data = unwrap(health)
    items.value = Array.isArray(data.items) ? data.items : []
    const stats = unwrap(rules)
    ruleTotal.value = Number(stats.totalRules || stats.total_rules || 0)
  } catch (cause) {
    error.value = cause?.message || '引擎健康数据加载失败。'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.engines-page { gap: 14px; }
.engine-stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.engine-card-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; }
.engine-card { padding: 12px; }
.engine-card-head { display: flex; align-items: center; gap: 8px; }
.engine-monogram { display: grid; width: 30px; height: 30px; place-items: center; border-radius: 7px; background: var(--sx-accent-soft); color: var(--sx-accent); font-size: 9px; font-weight: 800; }
.engine-monogram.low { background: var(--sx-success-soft); color: var(--sx-success); }
.engine-monogram.medium { background: var(--sx-warning-soft); color: var(--sx-warning); }
.engine-monogram.critical { background: var(--sx-danger-soft); color: var(--sx-danger); }
.engine-monogram.muted { background: var(--sx-surface-3); color: var(--sx-text-3); }
.engine-card-head > div { min-width: 0; flex: 1; }
.engine-card-head b { display: block; color: var(--sx-text); font-size: 11px; }
.engine-card-head small { display: block; color: var(--sx-text-3); font-size: 9px; }
.engine-card-body { display: grid; gap: 5px; margin-top: 10px; padding-top: 9px; border-top: 1px solid var(--sx-line-soft); }
.engine-card-body div { display: flex; align-items: center; justify-content: space-between; gap: 6px; font-size: 9px; }
.engine-card-body span { color: var(--sx-text-3); }
.engine-card-body b { overflow: hidden; color: var(--sx-text-2); font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
.show-all { display: inline-flex; align-items: center; gap: 6px; color: var(--sx-text-3); font-size: 10px; cursor: pointer; }
.engine-table { min-width: 1080px; }
.error-cell { max-width: 180px; overflow: hidden; color: var(--sx-danger); font-size: 9px; text-overflow: ellipsis; }
@media (max-width: 1200px) {
  .engine-card-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 850px) {
  .engine-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .engine-card-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 560px) {
  .engine-stats, .engine-card-grid { grid-template-columns: 1fr; }
}
</style>
