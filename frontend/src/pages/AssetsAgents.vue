<template>
  <section class="asset-page">
    <form class="query-panel surface-card" @submit.prevent="loadAll">
      <label><span>关键字</span><input v-model.trim="query" placeholder="主机名 / IP / Agent"></label>
      <label><span>视图</span><input value="服务器资源监控" disabled></label>
      <button type="submit" class="primary" :disabled="loading">{{ loading ? '更新中' : '查询' }}</button>
      <button type="button" @click="loadAll" :disabled="loading">刷新</button>
    </form>

    <div v-if="error" class="notice error">{{ error }}</div>

    <article class="events-panel surface-card">
      <div class="panel-title">
        <strong>服务器资源视图</strong>
        <span>{{ assets.length }} 台 / CPU · 内存 · 磁盘</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>主机</th><th>地址</th><th>系统</th><th>能力</th><th>CPU 配置</th><th>CPU 占用</th><th>内存</th><th>磁盘</th><th>最近上报</th></tr>
          </thead>
          <tbody>
            <tr v-if="loading && !hasLoaded"><td colspan="9" class="empty-cell">正在读取服务器资源数据</td></tr>
            <tr v-else-if="assets.length === 0"><td colspan="9" class="empty-cell">当前没有服务器资源上报。</td></tr>
            <tr v-for="asset in assets" :key="asset.id || asset.agent_id || asset.hostname">
              <td><b>{{ assetDisplayName(asset) }}</b><small>{{ assetHostMeta(asset) }}</small></td>
              <td>{{ pickText(asset.ip, '未上报地址') }}</td>
              <td><b>{{ osText(asset) }}</b><small>{{ pickText(asset.arch, '-') }}</small></td>
              <td><div class="capability-chips"><span v-for="item in capabilityLabels(asset)" :key="item" class="engine-chip">{{ item }}</span></div></td>
              <td><span class="engine-chip">{{ cpuConfig(asset) }}</span></td>
              <td><ResourceMeter :value="percent(asset.cpu_usage_percent)" :text="percentText(asset.cpu_usage_percent)" /></td>
              <td><ResourceMeter :value="percent(asset.memory_usage_percent)" :text="memoryText(asset)" /></td>
              <td><ResourceMeter :value="percent(asset.disk_usage_percent)" :text="diskText(asset)" /></td>
              <td><b>{{ formatChinaDateTime(asset.metrics_updated_at || asset.last_heartbeat || asset.last_seen) }}</b><small>{{ freshnessText(asset.metrics_freshness) }}</small></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="pager">
        <button type="button" @click="prevPage" :disabled="loading || page === 1">上一页</button>
        <span>第 {{ page }} 页</span>
        <button type="button" @click="nextPage" :disabled="loading || assets.length < pageSize">下一页</button>
      </div>
    </article>
  </section>
</template>

<script setup>
import { computed, defineComponent, h, onMounted, ref } from 'vue'
import { assetAgentClient } from '../api/domain'
import { normalizeItems, pickText } from '../shared/api-normalize'
import { formatChinaDateTime } from '../shared/time'

function numberValue(value) {
  const next = Number(value)
  return Number.isFinite(next) ? next : 0
}

function percent(value) {
  return Math.max(0, Math.min(100, numberValue(value)))
}

function pressureClass(value) {
  if (value >= 85) return 'critical'
  if (value >= 70) return 'warn'
  return 'ok'
}

const ResourceMeter = defineComponent({
  props: { value: { type: Number, default: 0 }, text: { type: String, default: '-' } },
  setup(props) {
    return () => h('div', { class: 'meter-cell' }, [
      h('span', { class: 'meter-text' }, props.text),
      h('i', { class: 'meter-track' }, h('em', { class: pressureClass(props.value), style: { width: props.value + '%' } })),
    ])
  },
})

const loading = ref(false)
const hasLoaded = ref(false)
const error = ref('')
const query = ref('')
const page = ref(1)
const pageSize = ref(20)
const assetsPayload = ref({ items: [], total: 0 })
const agentDisplayNames = ref(new Map())

const assets = computed(() => assetsPayload.value.items)

function percentText(value) {
  return Number.isFinite(Number(value)) ? percent(value).toFixed(1) + '%' : '-'
}

function formatMB(value) {
  const mb = numberValue(value)
  if (!mb) return '-'
  if (mb >= 1024) return (mb / 1024).toFixed(mb >= 10240 ? 0 : 1) + ' GB'
  return Math.round(mb) + ' MB'
}

function formatGB(value) {
  const gb = numberValue(value)
  if (!gb) return '-'
  return gb >= 1024 ? (gb / 1024).toFixed(1) + ' TB' : Math.round(gb) + ' GB'
}

function cpuConfig(asset) {
  return pickText(asset.cpu || asset.cpu_cores || asset.cpu?.cores, '-')
}

function osText(asset) {
  return [asset.os, asset.os_version].filter(Boolean).join(' ') || '-'
}

function agentIdentity(asset) {
  return asset.agent_id || asset.id || ''
}

function assetDisplayName(asset) {
  const agentName = agentDisplayNames.value.get(agentIdentity(asset))
  return pickText(agentName || asset.display_name || asset.hostname, '未上报主机名')
}

function assetHostMeta(asset) {
  const hostname = pickText(asset.hostname, '')
  const agentID = pickText(agentIdentity(asset), '未绑定 Agent')
  const name = assetDisplayName(asset)
  return hostname && hostname !== name ? `${hostname} · ${agentID}` : agentID
}

function memoryText(asset) {
  const total = formatMB(asset.memory_mb)
  const used = formatMB(asset.memory_used_mb)
  const pct = percentText(asset.memory_usage_percent)
  if (total === '-') return '-'
  return used === '-' ? total : used + ' / ' + total + ' · ' + pct
}

function diskText(asset) {
  const total = formatGB(asset.disk_gb)
  const used = formatGB(asset.disk_used_gb)
  const pct = percentText(asset.disk_usage_percent)
  if (total === '-') return '-'
  return used === '-' ? total : used + ' / ' + total + ' · ' + pct
}

function freshnessText(value) {
  return { fresh: '', stale: '延迟', expired: '过期', unknown: '未知' }[value] || value || '-'
}

function capabilityLabels(asset) {
  const capabilities = asset?.capabilities || asset?.metadata?.capabilities || {}
  const labels = []
  if (capabilities.traffic_collector?.enabled) labels.push('流量')
  if (capabilities.runtime_sensor?.enabled) labels.push('运行')
  if (capabilities.rasp_probe_manager?.enabled) labels.push('RASP')
  if (capabilities.yara_scanner?.enabled) {
    const status = String(capabilities.yara_scanner.status || '').toLowerCase()
    labels.push(['degraded', 'unavailable', 'disabled'].includes(status) ? 'YARA异常' : 'YARA')
  }
  if (capabilities.log_collector?.enabled) labels.push('日志')
  return labels.length ? labels : ['资产采集']
}

async function loadAll() {
  loading.value = true
  error.value = ''
  try {
    const [payload, agentsPayload] = await Promise.all([
      assetAgentClient.assets({ limit: pageSize.value, offset: (page.value - 1) * pageSize.value, search: query.value || undefined }),
      assetAgentClient.agents({ limit: 500 }),
    ])
    const agents = normalizeItems(agentsPayload).items
    agentDisplayNames.value = new Map(agents.map((agent) => [agent.agent_id || agent.id, agent.display_name || agent.hostname]).filter(([id, name]) => id && name))
    assetsPayload.value = normalizeItems(payload)
    hasLoaded.value = true
  } catch (requestError) {
    error.value = requestError?.message || '无法读取服务器资源数据'
  } finally {
    loading.value = false
  }
}

function prevPage() {
  if (page.value > 1) { page.value -= 1; loadAll() }
}

function nextPage() {
  if (assets.value.length >= pageSize.value) { page.value += 1; loadAll() }
}

onMounted(loadAll)
</script>

<style scoped>
.asset-page{position:relative;height:100%;min-height:0;display:grid;grid-template-rows:auto minmax(0,1fr);gap:12px;padding:14px;color:var(--text-primary);box-sizing:border-box}.query-panel,.events-panel{border-color:var(--border-color)}.query-panel{display:grid;grid-template-columns:1.4fr minmax(180px,.8fr) auto auto;gap:9px;align-items:end;padding:12px;min-height:0}.query-panel label{display:grid;gap:5px;min-width:0;color:var(--text-secondary);font-size:12px}input{height:32px;min-width:0;border:1px solid var(--border-color);border-radius:var(--card-radius-sm);background:var(--bg-secondary);color:var(--text-primary);padding:0 11px;font-size:12px;outline:0}input:disabled{opacity:.75}input::placeholder{color:var(--text-muted)}input:focus{border-color:var(--border-glow);box-shadow:0 0 0 3px var(--primary-glow)}button{height:32px;padding:0 12px;border:1px solid var(--border-color);border-radius:var(--card-radius-sm);background:var(--bg-elevated);color:var(--text-secondary);cursor:pointer;font-size:12px;transition:border-color var(--transition-fast),color var(--transition-fast),background var(--transition-fast)}button:hover:not(:disabled){border-color:var(--border-glow);color:var(--text-primary);background:var(--bg-hover)}button:disabled{opacity:.45;cursor:not-allowed}.primary{border:0;background:linear-gradient(135deg,var(--primary-color),var(--risk-low));color:var(--text-inverse);font-weight:900;box-shadow:0 10px 28px rgba(56,189,248,.18)}.events-panel{min-height:0;display:grid;grid-template-rows:44px minmax(0,1fr) 40px}.panel-title{position:relative;height:44px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;border-bottom:1px solid var(--border-light);background:rgba(4,12,24,.38)}.panel-title strong{color:var(--text-primary);font-size:14px}.panel-title span{color:var(--text-muted);font-size:12px}.table-wrap{position:relative;min-height:0;overflow:auto}table{width:100%;min-width:1180px;border-collapse:separate;border-spacing:0;table-layout:fixed}th,td{padding:8px 12px;border-bottom:1px solid var(--border-light);text-align:left;vertical-align:middle}th{position:sticky;top:0;z-index:1;height:36px;color:var(--text-muted);background:var(--bg-card);font-size:11px;font-weight:900;letter-spacing:.08em;text-transform:uppercase}td{height:44px;color:var(--text-primary);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}td b{display:block;color:var(--text-primary);font-size:12px;overflow:hidden;text-overflow:ellipsis}td small{display:block;margin-top:2px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis}.empty-cell{height:96px;text-align:center;color:var(--text-secondary)}.engine-chip{display:inline-flex;max-width:100%;padding:3px 8px;border:1px solid rgba(125,211,252,.24);border-radius:999px;color:var(--primary-light);background:rgba(125,211,252,.09);overflow:hidden;text-overflow:ellipsis}.meter-cell{display:grid;gap:5px;min-width:0}.meter-text{color:var(--text-primary);font-size:12px;overflow:hidden;text-overflow:ellipsis}.meter-track{display:block;height:6px;border-radius:999px;background:rgba(148,163,184,.14);overflow:hidden}.meter-track em{display:block;height:100%;border-radius:inherit}.meter-track .ok{background:linear-gradient(90deg,var(--risk-low),var(--primary-light))}.meter-track .warn{background:linear-gradient(90deg,var(--risk-medium),#fbbf24)}.meter-track .critical{background:linear-gradient(90deg,var(--risk-critical),#fb7185)}.pager{position:relative;display:flex;align-items:center;justify-content:flex-end;gap:10px;padding:4px 14px;border-top:1px solid var(--border-light);background:rgba(4,12,24,.34)}.pager span{min-width:72px;text-align:center;color:var(--text-secondary);font-size:12px}.notice.error{padding:10px 12px;border:1px solid var(--risk-critical-border);border-radius:var(--card-radius-sm);color:#fecaca;background:var(--risk-critical-bg)}.capability-chips{display:flex;flex-wrap:wrap;gap:4px}@media(max-width:1100px){.query-panel{grid-template-columns:1fr auto auto}.asset-page{padding:10px}}@media(max-width:760px){.query-panel{grid-template-columns:1fr}}
</style>
