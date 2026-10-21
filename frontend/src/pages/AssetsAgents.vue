<template>
  <section class="sx-page assets-page">
    <header class="sx-page-head">
      <div>
        <p class="sx-kicker">ASSET &amp; AGENT INVENTORY</p>
        <h2 class="sx-title">资产与 Agent</h2>
        <p class="sx-subtitle">以真实资产心跳、资源指标和 Agent 能力为核心；离线、延迟和异常都按后端状态展示，不做推断。</p>
      </div>
      <div class="sx-head-actions">
        <span class="sx-live"><i />LIVE</span>
        <button class="sx-btn" type="button" :disabled="loading" @click="loadAll">刷新</button>
      </div>
    </header>

    <section class="asset-stats">
      <article class="sx-metric">
        <span class="sx-metric-label"><i />资产总数</span>
        <strong class="sx-metric-value">{{ formatNumber(assetStats.total) }}</strong>
        <span class="sx-metric-note">登记的主机资产</span>
      </article>
      <article class="sx-metric">
        <span class="sx-metric-label"><i />在线 / 离线</span>
        <strong class="sx-metric-value"><span class="online">{{ formatNumber(assetStats.online) }}</span><em class="divider">/</em><span class="offline">{{ formatNumber(assetStats.offline) }}</span></strong>
        <span class="sx-metric-note">按最近心跳状态统计</span>
      </article>
      <article class="sx-metric">
        <span class="sx-metric-label"><i />RASP 覆盖</span>
        <strong class="sx-metric-value success">{{ formatNumber(assetStats.with_rasp) }}</strong>
        <span class="sx-metric-note">已安装应用防护能力</span>
      </article>
      <article class="sx-metric">
        <span class="sx-metric-label"><i />风险资产</span>
        <strong class="sx-metric-value danger">{{ formatNumber(assetStats.critical_assets) }}</strong>
        <span class="sx-metric-note">后端标记的关键风险</span>
      </article>
    </section>

    <form class="sx-filter" @submit.prevent="resetAndLoad">
      <label class="wide"><span>关键字</span><input v-model.trim="query" class="sx-input" placeholder="主机名 / IP / Agent ID" /></label>
      <button type="submit" class="sx-btn primary" :disabled="loading">{{ loading ? '查询中…' : '查询' }}</button>
      <button type="button" class="sx-btn ghost" :disabled="loading" @click="resetAndLoad">刷新</button>
      <span class="filter-note">共 {{ formatNumber(assetStats.total) }} 台资产 · 当前页 {{ assets.length }} 台</span>
    </form>

    <div v-if="error" class="sx-error">{{ error }}</div>

    <section class="sx-panel">
      <div class="sx-panel-head">
        <div class="sx-panel-title">服务器资源视图</div>
        <span class="sx-panel-meta">CPU · 内存 · 磁盘 · 能力</span>
      </div>
      <div class="sx-table-wrap sx-scroll">
        <table class="sx-table asset-table">
          <thead>
            <tr>
              <th>主机</th>
              <th>地址</th>
              <th>系统</th>
              <th>能力</th>
              <th>CPU</th>
              <th>内存</th>
              <th>磁盘</th>
              <th>状态</th>
              <th>最近上报</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading && !hasLoaded"><td colspan="9" class="sx-empty">正在读取资产数据…</td></tr>
            <tr v-else-if="assets.length === 0"><td colspan="9" class="sx-empty"><div><strong>{{ query ? '没有匹配的资产' : '当前没有资产上报' }}</strong>{{ query ? '调整关键字或清空搜索条件。' : '确认 Agent 已注册并持续发送心跳。' }}</div></td></tr>
            <tr v-for="asset in assets" :key="asset.id || asset.agent_id || asset.hostname" class="asset-row" @click="selectedAsset = asset">
              <td>
                <b>{{ assetDisplayName(asset) }}</b>
                <small>{{ asset.agent_id || '未绑定 Agent' }} · {{ asset.importance || 'medium' }}</small>
              </td>
              <td class="sx-mono">{{ asset.ip || '未上报' }}</td>
              <td><b>{{ osText(asset) }}</b><small>{{ asset.arch || '-' }}</small></td>
              <td><div class="capability-chips"><span v-for="chip in capabilityChips(asset)" :key="chip.label" class="sx-badge" :class="chip.tone">{{ chip.label }}</span></div></td>
              <td><Meter :value="percent(asset.cpu_usage_percent)" :text="percentText(asset.cpu_usage_percent)" /></td>
              <td><Meter :value="percent(asset.memory_usage_percent)" :text="memoryText(asset)" /></td>
              <td><Meter :value="percent(asset.disk_usage_percent)" :text="diskText(asset)" /></td>
              <td><span class="sx-badge" :class="asset.status === 'online' ? 'low' : 'muted'">{{ asset.status === 'online' ? '在线' : '离线' }}</span></td>
              <td><b>{{ formatTime(asset.metrics_updated_at || asset.last_heartbeat || asset.last_seen) }}</b><small>{{ freshnessText(asset.metrics_freshness) }}</small></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="asset-pager">
        <span>第 {{ page }} 页 / 每页 {{ pageSize }} 台</span>
        <div>
          <button class="sx-btn" type="button" :disabled="loading || page === 1" @click="prevPage">上一页</button>
          <button class="sx-btn" type="button" :disabled="loading || assets.length < pageSize" @click="nextPage">下一页</button>
        </div>
      </div>
    </section>

    <Teleport to="body">
      <div v-if="selectedAsset" class="sx-drawer-scrim" @click.self="selectedAsset = null">
        <aside class="sx-drawer">
        <header class="sx-drawer-head">
          <div>
            <p class="sx-kicker">ASSET DETAIL</p>
            <h3 class="asset-drawer-title">{{ assetDisplayName(selectedAsset) }}</h3>
          </div>
          <button class="sx-icon-btn" type="button" aria-label="关闭资产详情" @click="selectedAsset = null">×</button>
        </header>
        <div class="sx-drawer-body">
          <div class="asset-detail-top">
            <div class="asset-avatar">{{ assetInitial(selectedAsset) }}</div>
            <div>
              <div class="asset-detail-badges">
                <span class="sx-badge" :class="selectedAsset.status === 'online' ? 'low' : 'muted'">{{ selectedAsset.status === 'online' ? '在线' : '离线' }}</span>
                <span class="sx-badge info">{{ selectedAsset.importance || 'medium' }}</span>
                <span class="sx-badge" :class="selectedAsset.risk_level">{{ severityLabel(selectedAsset.risk_level) }}</span>
              </div>
              <p>{{ selectedAsset.agent_id || '未绑定 Agent' }} · {{ selectedAsset.ip || '未上报 IP' }}</p>
            </div>
          </div>

          <section class="asset-detail-section">
            <h4>基础信息</h4>
            <div class="asset-detail-grid">
              <div><span>主机名</span><b>{{ selectedAsset.hostname || '-' }}</b></div>
              <div><span>操作系统</span><b>{{ osText(selectedAsset) }}</b></div>
              <div><span>架构</span><b>{{ selectedAsset.arch || '-' }}</b></div>
              <div><span>CPU 配置</span><b>{{ selectedAsset.cpu || '-' }}</b></div>
              <div><span>内存总量</span><b>{{ formatMB(selectedAsset.memory_mb) }}</b></div>
              <div><span>磁盘总量</span><b>{{ formatGB(selectedAsset.disk_gb) }}</b></div>
              <div><span>首次发现</span><b>{{ formatTime(selectedAsset.first_seen) }}</b></div>
              <div><span>最近心跳</span><b>{{ formatTime(selectedAsset.last_heartbeat || selectedAsset.last_seen) }}</b></div>
            </div>
          </section>

          <section class="asset-detail-section">
            <h4>资源使用</h4>
            <div class="asset-meters">
              <Meter :value="percent(selectedAsset.cpu_usage_percent)" :text="`CPU ${percentText(selectedAsset.cpu_usage_percent)}`" />
              <Meter :value="percent(selectedAsset.memory_usage_percent)" :text="memoryText(selectedAsset)" />
              <Meter :value="percent(selectedAsset.disk_usage_percent)" :text="diskText(selectedAsset)" />
            </div>
          </section>

          <section class="asset-detail-section">
            <h4>Agent 能力</h4>
            <div class="capability-detail-list">
              <div v-for="chip in capabilityChips(selectedAsset)" :key="chip.label"><span class="sx-badge" :class="chip.tone">{{ chip.label }}</span><small>{{ chip.note }}</small></div>
              <div v-if="!capabilityChips(selectedAsset).length" class="sx-muted">该资产尚未上报能力信息。</div>
            </div>
          </section>

          <section class="asset-detail-section">
            <h4>安全计数</h4>
            <div class="asset-detail-grid">
              <div><span>告警</span><b>{{ formatNumber(selectedAsset.alert_count) }}</b></div>
              <div><span>漏洞</span><b>{{ formatNumber(selectedAsset.vuln_count) }}</b></div>
              <div><span>RASP 阻断</span><b>{{ formatNumber(selectedAsset.rasp_blocked) }}</b></div>
              <div><span>指标时间</span><b>{{ formatTime(selectedAsset.metrics_updated_at) }}</b></div>
            </div>
          </section>
        </div>
        </aside>
      </div>
    </Teleport>
  </section>
</template>

<script setup>
import { computed, defineComponent, h, onMounted, ref } from 'vue'
import { assetAgentClient } from '../api/domain'
import { normalizeItems } from '../shared/api-normalize'
import { formatChinaDateTime } from '../shared/time'

const Meter = defineComponent({
  props: { value: { type: Number, default: 0 }, text: { type: String, default: '-' } },
  setup(props) {
    return () => h('div', { class: 'meter' }, [
      h('span', { class: 'meter-text' }, props.text),
      h('i', { class: 'meter-track' }, h('em', { class: props.value >= 85 ? 'critical' : props.value >= 70 ? 'warn' : 'ok', style: { width: `${props.value}%` } })),
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
const assetStats = ref({})
const agentDisplayNames = ref(new Map())
const selectedAsset = ref(null)

const assets = computed(() => assetsPayload.value.items)

function numberValue(value) {
  const next = Number(value)
  return Number.isFinite(next) ? next : 0
}

function percent(value) {
  return Math.max(0, Math.min(100, numberValue(value)))
}

function percentText(value) {
  const next = Number(value)
  return Number.isFinite(next) ? `${next.toFixed(1)}%` : '-'
}

function formatNumber(value) {
  return numberValue(value).toLocaleString('zh-CN')
}

function formatTime(value) {
  return value ? formatChinaDateTime(value) : '-'
}

function formatMB(value) {
  const mb = numberValue(value)
  if (!mb) return '-'
  return mb >= 1024 ? `${(mb / 1024).toFixed(mb >= 10240 ? 0 : 1)} GB` : `${Math.round(mb)} MB`
}

function formatGB(value) {
  const gb = numberValue(value)
  if (!gb) return '-'
  return gb >= 1024 ? `${(gb / 1024).toFixed(1)} TB` : `${Math.round(gb)} GB`
}

function osText(asset) {
  return [asset.os, asset.os_version].filter(Boolean).join(' ') || '-'
}

function assetIdentity(asset) {
  return asset.agent_id || asset.id || ''
}

function assetDisplayName(asset) {
  const agentName = agentDisplayNames.value.get(assetIdentity(asset))
  return agentName || asset.display_name || asset.hostname || '未上报主机名'
}

function assetInitial(asset) {
  return String(assetDisplayName(asset) || 'A').slice(0, 1).toUpperCase()
}

function memoryText(asset) {
  const total = formatMB(asset.memory_mb)
  if (total === '-') return '-'
  return `${formatMB(asset.memory_used_mb)} / ${total} · ${percentText(asset.memory_usage_percent)}`
}

function diskText(asset) {
  const total = formatGB(asset.disk_gb)
  if (total === '-') return '-'
  return `${formatGB(asset.disk_used_gb)} / ${total} · ${percentText(asset.disk_usage_percent)}`
}

function freshnessText(value) {
  return { fresh: '最新', stale: '延迟', expired: '过期', unknown: '未知' }[value] || value || '-'
}

function severityLabel(value) {
  return ({ critical: '严重', high: '高危', medium: '中危', low: '低危' })[value] || value || '低危'
}

function capabilityChips(asset) {
  const capabilities = asset?.capabilities || {}
  const supervisors = capabilities.engine_supervisors || {}
  const chips = []
  if (capabilities.asset_collector?.enabled) chips.push({ label: '资产采集', tone: 'info', note: '接口 / 性能 / 进程' })
  if (supervisors.suricata?.running) chips.push({ label: '流量采集', tone: 'low', note: supervisors.suricata.rule_pack_version || 'Suricata' })
  if (supervisors.wazuh?.running) chips.push({ label: '主机运行', tone: 'low', note: supervisors.wazuh.rule_pack_version || 'Wazuh' })
  if (supervisors.rasp?.running) chips.push({ label: 'RASP', tone: 'medium', note: supervisors.rasp.rule_pack_version || '应用防护' })
  if (supervisors.yara?.running) chips.push({ label: 'YARA', tone: 'low', note: supervisors.yara.rule_pack_version || '文件扫描' })
  if (capabilities.log_collector?.enabled) chips.push({ label: '日志审计', tone: 'info', note: (capabilities.log_collector.collectors || []).join(' / ') || '日志采集' })
  return chips
}

async function loadAll() {
  loading.value = true
  error.value = ''
  try {
    const [payload, agentsPayload, statsPayload] = await Promise.all([
      assetAgentClient.assets({ limit: pageSize.value, offset: (page.value - 1) * pageSize.value, search: query.value || undefined }),
      assetAgentClient.agents({ limit: 500 }),
      assetAgentClient.assetStats(),
    ])
    const agents = normalizeItems(agentsPayload).items
    agentDisplayNames.value = new Map(agents.map((agent) => [agent.agent_id || agent.id, agent.display_name || agent.hostname]).filter(([id, name]) => id && name))
    assetsPayload.value = normalizeItems(payload)
    assetStats.value = statsPayload || {}
    hasLoaded.value = true
  } catch (requestError) {
    error.value = requestError?.message || '无法读取资产数据。'
  } finally {
    loading.value = false
  }
}

function resetAndLoad() {
  page.value = 1
  loadAll()
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
.assets-page { gap: 14px; }
.asset-stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.sx-metric-value .online { color: var(--sx-success); }
.sx-metric-value .offline { color: var(--sx-danger); }
.sx-metric-value .divider { margin: 0 4px; color: var(--sx-text-3); font-size: 15px; font-style: normal; font-weight: 400; }
.filter-note { margin-left: auto; color: var(--sx-text-3); font-size: 10px; }
.asset-table { min-width: 1280px; }
.asset-row { cursor: pointer; }
.capability-chips { display: flex; max-width: 220px; flex-wrap: wrap; gap: 3px; }
.capability-chips .sx-badge { font-size: 8px; }
.asset-pager { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 9px 14px; border-top: 1px solid var(--sx-line-soft); color: var(--sx-text-3); font-size: 10px; }
.asset-pager > div { display: flex; gap: 6px; }
.asset-drawer-title { margin: 3px 0 0; color: var(--sx-text); font-size: 18px; font-weight: 720; }
.asset-detail-top { display: flex; align-items: center; gap: 12px; padding: 12px; border: 1px solid var(--sx-line-soft); border-radius: var(--sx-radius); background: var(--sx-surface-2); }
.asset-avatar { display: grid; width: 46px; height: 46px; place-items: center; border-radius: 11px; background: linear-gradient(145deg, var(--sx-accent-soft), var(--sx-surface-3)); color: var(--sx-accent); font-size: 20px; font-weight: 780; }
.asset-detail-badges { display: flex; flex-wrap: wrap; gap: 4px; }
.asset-detail-top p { margin: 6px 0 0; color: var(--sx-text-3); font-size: 10px; }
.asset-detail-section { margin-top: 16px; }
.asset-detail-section h4 { margin: 0 0 8px; color: var(--sx-text); font-size: 12px; font-weight: 700; }
.asset-detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 7px 12px; }
.asset-detail-grid div { min-width: 0; padding: 7px 9px; border-radius: 5px; background: var(--sx-surface-2); }
.asset-detail-grid span { display: block; color: var(--sx-text-3); font-size: 9px; }
.asset-detail-grid b { display: block; overflow-wrap: anywhere; margin-top: 2px; color: var(--sx-text); font-size: 11px; font-weight: 600; }
.asset-meters { display: grid; gap: 8px; padding: 10px; border: 1px solid var(--sx-line-soft); border-radius: var(--sx-radius-sm); background: var(--sx-surface-2); }
.capability-detail-list { display: grid; gap: 6px; }
.capability-detail-list > div { display: flex; align-items: center; gap: 8px; padding: 7px 9px; border: 1px solid var(--sx-line-soft); border-radius: 5px; }
.capability-detail-list small { color: var(--sx-text-3); font-size: 9px; }

:deep(.meter) { display: grid; min-width: 110px; gap: 4px; }
:deep(.meter-text) { overflow: hidden; color: var(--sx-text-2); font-size: 9px; text-overflow: ellipsis; white-space: nowrap; }
:deep(.meter-track) { display: block; height: 5px; overflow: hidden; border-radius: 4px; background: var(--sx-surface-3); }
:deep(.meter-track em) { display: block; height: 100%; border-radius: inherit; background: var(--sx-success); }
:deep(.meter-track em.warn) { background: var(--sx-warning); }
:deep(.meter-track em.critical) { background: var(--sx-danger); }

@media (max-width: 1100px) {
  .asset-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .filter-note { display: none; }
}
@media (max-width: 700px) {
  .asset-stats { grid-template-columns: 1fr; }
  .asset-detail-grid { grid-template-columns: 1fr; }
}
</style>
