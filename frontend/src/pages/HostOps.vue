<template>
  <section class="host-page">
    <header class="host-header">
      <h2>主机运维</h2>
      <span>Agent 采集主机信息与资源占用</span>
    </header>

    <section class="stats-bar">
      <div class="stat-card"><span>主机数</span><strong>{{ total }}</strong></div>
      <div class="stat-card online"><span>在线主机</span><strong>{{ onlineCount }}</strong></div>
      <div class="stat-card"><span>平均 CPU</span><strong>{{ averageMetric('cpu_usage_percent') }}%</strong></div>
      <div class="stat-card warn"><span>平均内存</span><strong>{{ averageMetric('memory_usage_percent') }}%</strong></div>
    </section>

    <article class="panel host-panel">
      <div class="panel-title"><strong>主机资产</strong><span>{{ `${hosts.length} / ${total} 台` }}</span></div>
      <div class="host-grid">
        <article v-if="loading && !hasLoaded" class="empty-card">正在读取主机运维数据</article>
        <article v-else-if="!hosts.length" class="empty-card">暂无主机数据</article>
        <article v-for="host in hosts" :key="host.id || host.agent_id" class="host-card">
          <div class="host-top">
            <div>
              <b>{{ host.hostname || host.agent_id }}</b>
              <small>{{ host.agent_id || '-' }}</small>
            </div>
            <span :class="['status-pill', host.status]">{{ statusLabel(host.status) }}</span>
          </div>

          <div class="identity-grid">
            <span>IP 地址</span><b>{{ host.ip || '-' }}</b>
            <span>系统</span><b>{{ osText(host) }}</b>
            <span>风险</span><b>{{ riskLabel(host.risk_level) }} · {{ importanceLabel(host.importance) }}</b>
            <span>心跳</span><b>{{ formatTime(host.last_heartbeat) }}</b>
          </div>

          <section class="usage-grid">
            <div class="usage-item">
              <span>CPU</span><b>{{ host.cpu || '-' }}</b>
              <em>{{ percent(host.cpu_usage_percent) }}%</em>
              <i><u :style="barStyle(host.cpu_usage_percent)"></u></i>
            </div>
            <div class="usage-item">
              <span>内存</span><b>{{ sizeMb(host.memory_used_mb) }} / {{ sizeMb(host.memory_mb) }}</b>
              <em>{{ percent(host.memory_usage_percent) }}%</em>
              <i><u :style="barStyle(host.memory_usage_percent)"></u></i>
            </div>
            <div class="usage-item">
              <span>磁盘</span><b>{{ sizeGb(host.disk_used_gb) }} / {{ sizeGb(host.disk_gb) }}</b>
              <em>{{ percent(host.disk_usage_percent) }}%</em>
              <i><u :style="barStyle(host.disk_usage_percent)"></u></i>
            </div>
          </section>

          <section class="detail-strip">
            <span>告警 {{ host.alert_count || 0 }}</span>
            <span>漏洞 {{ host.vuln_count || 0 }}</span>
            <span>RASP 阻断 {{ host.rasp_blocked || 0 }}</span>
            <span>采集 {{ formatTime(host.metrics_updated_at) }}</span>
          </section>

          <section class="capability-block">
            <strong>开启能力</strong>
            <div class="cap-list">
              <span v-for="cap in capabilityBadges(host.capabilities)" :key="cap">{{ cap }}</span>
            </div>
          </section>
        </article>
      </div>
      <div v-if="error" class="notice error">{{ error }}</div>
    </article>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { assetAgentClient } from '../api/domain'
import { normalizeItems } from '../shared/api-normalize'
import { formatChinaDateTime } from '../shared/time'

const hosts = ref([])
const total = ref(0)
const loading = ref(false)
const hasLoaded = ref(false)
const error = ref('')

const onlineCount = computed(() => hosts.value.filter((h) => h.status === 'online').length)

function averageMetric(key) {
  const values = hosts.value.map((h) => Number(h[key])).filter(Number.isFinite)
  if (!values.length) return 0
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
}

function percent(value) {
  const n = Number(value)
  if (!Number.isFinite(n)) return 0
  return Math.max(0, Math.min(100, Math.round(n)))
}

function barStyle(value) { return { width: percent(value) + '%' } }
function sizeMb(value) { return Number.isFinite(Number(value)) ? `${Math.round(Number(value))} MB` : '-' }
function sizeGb(value) { return Number.isFinite(Number(value)) ? `${Math.round(Number(value))} GB` : '-' }
function osText(host) { return [host.os, host.os_version, host.arch].filter(Boolean).join(' / ') || '-' }
function formatTime(value) { return value ? formatChinaDateTime(value) : '-' }
function statusLabel(value) { return { online: '在线', offline: '离线', unknown: '未知' }[value] || value || '未知' }
function riskLabel(value) { return { low: '低风险', medium: '中风险', high: '高风险', critical: '严重风险' }[value] || value || '-' }
function importanceLabel(value) { return { low: '低重要性', medium: '中重要性', high: '高重要性', critical: '核心资产' }[value] || value || '-' }

function capabilityBadges(capabilities = {}) {
  const result = []
  const traffic = capabilities.traffic_collector || {}
  const runtime = capabilities.runtime_sensor || {}
  const asset = capabilities.asset_collector || {}
  const rasp = capabilities.rasp_probe_manager || {}
  if (traffic.enabled) result.push(`流量 ${traffic.active_engine || traffic.requested_engine || '采集'}`)
  if (runtime.enabled) result.push(`Runtime ${runtime.active_backend || runtime.status || '监控'}`)
  if (asset.enabled) result.push(`资产 ${Array.isArray(asset.collects) ? asset.collects.join('/') : '采集'}`)
  if (rasp.enabled) result.push(`RASP ${rasp.mode || rasp.status || '检测'}`)
  return result.length ? result : ['暂无能力上报']
}

async function loadHosts() {
  loading.value = true
  error.value = ''
  try {
    const data = normalizeItems(await assetAgentClient.assets({ limit: 100 }))
    hosts.value = data.items
    total.value = data.total
    hasLoaded.value = true
  } catch (e) {
    error.value = e?.message || '无法读取主机运维数据'
  } finally {
    loading.value = false
  }
}

onMounted(loadHosts)
</script>

<style scoped>
.host-page{min-height:100%;display:grid;align-content:start;gap:14px;padding:18px;color:#172033;background:transparent}.host-header,.stats-bar,.panel{border:1px solid rgba(255,255,255,.58);background:rgba(255,255,255,.3);border-radius:24px;box-shadow:0 24px 80px rgba(49,65,88,.14),inset 0 1px 0 rgba(255,255,255,.55);backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px)}.host-header{padding:18px 22px;display:flex;align-items:end;justify-content:space-between;gap:16px}.host-header h2{margin:0;font-size:24px}.host-header span{color:#64748b;font-size:13px}.stats-bar{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;padding:18px}.stat-card{padding:18px 22px;display:grid;gap:6px;border-radius:18px;background:rgba(255,255,255,.24);border:1px solid rgba(255,255,255,.44)}.stat-card span{color:#64748b;font-size:13px}.stat-card strong{font-size:30px;font-weight:950}.stat-card.online strong{color:#15803d}.stat-card.warn strong{color:#b45309}.panel{overflow:hidden}.host-panel{display:grid;grid-template-rows:44px minmax(0,1fr) auto}.panel-title{height:44px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;border-bottom:1px solid rgba(255,255,255,.38);background:rgba(255,255,255,.2)}.panel-title strong{font-size:14px}.panel-title span{color:#687789;font-size:12px}.host-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(390px,1fr));gap:14px;padding:14px;max-height:calc(100vh - 285px);overflow:auto}.empty-card{grid-column:1/-1;padding:42px;text-align:center;color:#64748b}.host-card{display:grid;gap:12px;padding:16px;border-radius:20px;border:1px solid rgba(255,255,255,.5);background:rgba(255,255,255,.34);box-shadow:inset 0 1px 0 rgba(255,255,255,.42)}.host-top{display:flex;align-items:center;justify-content:space-between;gap:12px}.host-top b{font-size:16px}.host-top small{display:block;margin-top:2px;color:#64748b}.status-pill{border-radius:999px;padding:4px 10px;font-size:12px;font-weight:800;background:rgba(148,163,184,.15);color:#475569}.status-pill.online{background:rgba(34,197,94,.16);color:#15803d}.status-pill.offline{background:rgba(239,68,68,.14);color:#991b1b}.identity-grid{display:grid;grid-template-columns:72px 1fr 72px 1fr;gap:8px 12px;padding:12px;border-radius:16px;background:rgba(255,255,255,.22)}.identity-grid span{color:#64748b;font-size:12px}.identity-grid b{font-size:12px;font-weight:800;word-break:break-all}.usage-grid{display:grid;gap:10px}.usage-item{display:grid;grid-template-columns:44px 1fr 48px;align-items:center;gap:10px}.usage-item span{color:#64748b;font-size:12px}.usage-item b{font-size:12px}.usage-item em{font-style:normal;text-align:right;font-weight:900;color:#172033}.usage-item i{grid-column:2/4;height:8px;border-radius:999px;background:rgba(148,163,184,.18);overflow:hidden}.usage-item u{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,rgba(14,165,233,.78),rgba(52,211,153,.82))}.detail-strip{display:flex;gap:6px;flex-wrap:wrap}.detail-strip span,.cap-list span{border:1px solid rgba(255,255,255,.55);border-radius:999px;padding:4px 9px;font-size:11px;color:#475569;background:rgba(255,255,255,.14)}.capability-block{display:grid;gap:8px}.capability-block strong{font-size:13px}.cap-list{display:flex;gap:6px;flex-wrap:wrap}.notice{padding:10px 16px;border-radius:14px;font-size:12px}.notice.error{background:rgba(239,68,68,.14);color:#991b1b}@media(max-width:860px){.stats-bar{grid-template-columns:repeat(2,1fr)}.host-grid{grid-template-columns:1fr;max-height:none}.identity-grid{grid-template-columns:72px 1fr}.host-header{align-items:start;flex-direction:column}}
</style>
