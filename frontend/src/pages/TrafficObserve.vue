<template>
  <section class="traffic-page">
    <section class="query-panel">
      <label><span>关键字</span><input v-model.trim="filters.query" placeholder="IP、域名、路径、探针"></label>
      <label><span>源 IP</span><input v-model.trim="filters.src_ip"></label>
      <label><span>源端口</span><input v-model.trim="filters.src_port"></label>
      <label><span>目的 IP</span><input v-model.trim="filters.dst_ip"></label>
      <label><span>目的端口</span><input v-model.trim="filters.dst_port"></label>
      <label><span>开始时间</span><input v-model="filters.start_time" type="datetime-local"></label>
      <label><span>结束时间</span><input v-model="filters.end_time" type="datetime-local"></label>
      <button class="primary" @click="search" :disabled="loading">{{ loading ? '更新中' : '查询' }}</button>
    </section>

    <div v-if="error" class="notice error">{{ error }}</div>

    <article class="panel session-panel">
      <div class="panel-title"><strong>会话列表</strong><span>{{ `${totalFlows || flows.length} 条 / 当前页 ${flows.length} 条` }}</span></div>
      <div ref="tableWrap" :class="['table-wrap', { updating: loading && hasLoaded }]">
        <table>
          <thead><tr><th>时间</th><th>探针</th><th>会话方向</th><th>应用内容</th><th>流量</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-if="loading && !hasLoaded"><td colspan="6" class="empty-cell">正在读取流量</td></tr>
            <tr v-else-if="!flows.length"><td colspan="6" class="empty-cell">暂无流量记录</td></tr>
            <tr v-for="item in flows" :key="item.message_id">
              <td>{{ formatTime(item.timestamp) }}</td>
              <td>{{ probeLabel(item) }}<small>{{ probeMeta(item) }}</small></td>
              <td><b>{{ tupleText(item) }}</b><small>{{ actionLabel(item.business_action) }}</small></td>
              <td>{{ contentSummary(item) }}</td>
              <td>{{ trafficText(item) }}</td>
              <td><button @click="selected = item">详情</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="pager">
        <button @click="prevPage" :disabled="loading || page === 1">上一页</button>
        <span>第 {{ page }} 页</span>
        <button @click="nextPage" :disabled="loading || flows.length < pageSize">下一页</button>
      </div>
    </article>

    <div v-if="selected" class="drawer-mask">
      <aside class="drawer">
        <div class="drawer-title"><strong>流量详情</strong><button @click="selected = null">×</button></div>
        <div class="detail-grid">
          <template v-for="row in detailRows(selected)" :key="row.label">
            <span>{{ row.label }}</span><b>{{ row.value }}</b>
          </template>
        </div>
      </aside>
    </div>
  </section>
</template>

<script setup>
import { nextTick, onMounted, onUnmounted, ref } from 'vue'
import { trafficClient } from '../api/domain'
import { normalizeItems } from '../shared/api-normalize'
import { formatChinaDateTime } from '../shared/time'

const pageSize = ref(12)
const page = ref(1)
const loading = ref(false)
const hasLoaded = ref(false)
const error = ref('')
const flows = ref([])
const totalFlows = ref(0)
const selected = ref(null)
const tableWrap = ref(null)
const filters = ref({ query: '', src_ip: '', src_port: '', dst_ip: '', dst_port: '', start_time: '', end_time: '' })
let resizeObserver = null

function params() { return { ...filters.value, limit: pageSize.value, offset: (page.value - 1) * pageSize.value } }
function formatTime(value) { return value ? formatChinaDateTime(value) : '-' }
function tupleText(item) { return `${item.src_ip || '-'}:${item.src_port || 0} → ${item.dst_ip || '-'}:${item.dst_port || 0} / ${item.protocol || '-'}` }
function probeLabel(item) { return item.capture_source === 'lyprobe' || item.engine === 'lyprobe' ? 'lyprobe' : (item.agent_id || item.probe_name || '-') }
function probeMeta(item) { return item.capture_source === 'lyprobe' ? (item.hostname || item.agent_id || '') : (item.hostname || '') }
function actionLabel(value) {
  return { tcp_flow: 'TCP会话流', http_access: 'HTTP访问', dns_query: 'DNS查询', tls_connection: 'TLS连接', admin_access: '管理访问', login: '登录行为', upload: '上传行为' }[value] || value || '-'
}
function directionLabel(value) { return { egress: '出站', ingress: '入站' }[value] || value || '-' }
function contentSummary(item) { return item.http_host || item.dns_query || item.tls_sni || [item.http_method, item.http_path].filter(Boolean).join(' ') || actionLabel(item.business_action) }
function display(value) { return value === undefined || value === null || value === '' ? '-' : String(value) }
function trafficText(item) { return `↑ ${item.bytes_out || 0} B ↓ ${item.bytes_in || 0} B` }

function detailRows(item) {
  return [
    ['探针', probeLabel(item)], ['采集来源', item.capture_source], ['探针ID', item.agent_id], ['主机名', item.hostname], ['源IP', item.src_ip], ['源端口', item.src_port], ['目的IP', item.dst_ip], ['目的端口', item.dst_port],
    ['传输协议', item.protocol], ['应用协议', item.app_protocol], ['业务行为', actionLabel(item.business_action)], ['流量方向', directionLabel(item.direction)],
    ['入站字节数', item.bytes_in], ['出站字节数', item.bytes_out], ['包数量', item.packets], ['持续时间(毫秒)', item.duration_ms],
    ['HTTP主机', item.http_host], ['HTTP方法', item.http_method], ['HTTP路径', item.http_path], ['DNS查询', item.dns_query], ['TLS SNI', item.tls_sni],
    ['风险等级', item.risk_level],
  ].filter(([, value]) => display(value) !== '-').map(([label, value]) => ({ label, value: display(value) }))
}

async function loadAll() {
  loading.value = true
  error.value = ''
  try {
    const flowData = await trafficClient.flows(params())
    const flowNormalized = normalizeItems(flowData)
    flows.value = [...flowNormalized.items].sort((left, right) => {
      const leftTime = new Date(left.timestamp || 0).getTime() || 0
      const rightTime = new Date(right.timestamp || 0).getTime() || 0
      return rightTime - leftTime
    })
    totalFlows.value = flowNormalized.total
    hasLoaded.value = true
  } catch (e) {
    error.value = e?.message || '无法读取流量观测数据'
  } finally {
    loading.value = false
  }
}
function search() { page.value = 1; loadAll() }
function prevPage() { if (page.value > 1) { page.value -= 1; loadAll() } }
function nextPage() { if (flows.value.length >= pageSize.value) { page.value += 1; loadAll() } }
function updatePageSize({ reload = true } = {}) {
  const height = tableWrap.value?.clientHeight || 0
  if (!height) return
  const nextSize = Math.max(8, Math.floor((height - 36) / 40))
  if (nextSize !== pageSize.value) {
    pageSize.value = nextSize
    if (reload) loadAll()
  }
}
onMounted(async () => {
  await nextTick()
  updatePageSize({ reload: false })
  if (tableWrap.value && typeof ResizeObserver !== 'undefined') {
    resizeObserver = new ResizeObserver(updatePageSize)
    resizeObserver.observe(tableWrap.value)
  }
  loadAll()
})
onUnmounted(() => {
  if (resizeObserver) resizeObserver.disconnect()
})
</script>

<style scoped>
.traffic-page{height:100%;min-height:0;display:grid;grid-template-rows:auto minmax(0,1fr);gap:12px;padding:14px;color:#172033;background:transparent;box-sizing:border-box}.query-panel,.panel{border:1px solid rgba(255,255,255,.58);background:rgba(255,255,255,.3);border-radius:24px;box-shadow:0 24px 80px rgba(49,65,88,.14),inset 0 1px 0 rgba(255,255,255,.55);backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px)}.query-panel{display:grid;grid-template-columns:1.5fr repeat(4,1fr) auto;gap:9px;align-items:end;padding:12px}.query-panel label{display:grid;gap:5px;color:#536170;font-size:12px}input{height:32px;border:1px solid rgba(255,255,255,.66);border-radius:12px;background:rgba(255,255,255,.46);color:#16202c;padding:0 11px;font-size:12px;outline:0}input:focus{border-color:rgba(14,165,233,.55);box-shadow:0 0 0 4px rgba(14,165,233,.12)}.primary,button{height:32px;padding:0 12px;border:1px solid rgba(255,255,255,.6);border-radius:12px;background:rgba(255,255,255,.36);color:#17202c;cursor:pointer;font-size:12px;backdrop-filter:blur(16px)}button:disabled{opacity:.45;cursor:not-allowed}.primary{border:0;background:linear-gradient(135deg,rgba(14,165,233,.88),rgba(52,211,153,.86));color:white;font-weight:900;box-shadow:0 10px 28px rgba(14,165,233,.22)}.panel{overflow:hidden}.session-panel{min-height:0;display:grid;grid-template-rows:44px minmax(0,1fr) 40px}.panel-title{height:44px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;border-bottom:1px solid rgba(255,255,255,.38);background:rgba(255,255,255,.2)}.panel-title strong{color:#152033;font-size:14px}.panel-title span{color:#687789;font-size:12px}.table-wrap{position:relative;min-height:0;overflow:hidden;mask-image:linear-gradient(to bottom,transparent 0,#000 26px,#000 calc(100% - 28px),transparent 100%)}.table-wrap table{transition:opacity .22s ease,transform .22s ease}.table-wrap.updating table{opacity:.72;transform:translateY(1px)}table{width:100%;border-collapse:separate;border-spacing:0;font-size:12px}thead{position:sticky;top:0;z-index:2;backdrop-filter:blur(20px)}th{height:34px;text-align:left;padding:0 11px;color:#5d6b7c;background:rgba(255,255,255,.58);border-bottom:1px solid rgba(255,255,255,.5)}td{height:40px;padding:0 11px;border-bottom:1px solid rgba(255,255,255,.32);color:#334155;vertical-align:middle;background:rgba(255,255,255,.12)}td b{display:block;color:#172033;font-weight:760}td small{display:block;margin-top:2px;color:#728094;font-size:11px}.empty-cell{text-align:center;color:#64748b;padding:14px}.notice{padding:10px 12px;border-radius:14px;border:1px solid}.error{color:#b42318;background:rgba(254,242,242,.62);border-color:rgba(252,165,165,.5)}.pager{height:40px;display:flex;align-items:center;justify-content:flex-end;gap:10px;padding:0 14px;border-top:1px solid rgba(255,255,255,.36)}.pager span{color:#64748b;font-size:12px}.drawer-mask{position:fixed;inset:0;z-index:40;display:flex;justify-content:flex-end;background:rgba(229,237,247,.36);backdrop-filter:blur(18px)}.drawer{width:min(500px,calc(100vw - 32px));height:100%;display:grid;grid-template-rows:54px minmax(0,1fr);overflow:hidden;background:rgba(255,255,255,.56);border-left:1px solid rgba(255,255,255,.66);box-shadow:-28px 0 90px rgba(49,65,88,.2);backdrop-filter:blur(30px)}.drawer-title{height:54px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;border-bottom:1px solid rgba(255,255,255,.5);color:#152033}.drawer-title button{font-size:20px;border:0;background:transparent}.detail-grid{height:100%;overflow:auto;display:grid;grid-template-columns:1fr;gap:8px;align-content:start;padding:12px;font-size:12px}.detail-grid span,.detail-grid b{display:block;border:1px solid rgba(255,255,255,.56);background:rgba(255,255,255,.34);box-shadow:inset 0 1px 0 rgba(255,255,255,.45)}.detail-grid span{padding:8px 12px 0;border-bottom:0;border-radius:14px 14px 0 0;color:#64748b;font-size:11px}.detail-grid b{margin-top:-8px;padding:18px 12px 10px;border-top:0;border-radius:0 0 14px 14px;color:#172033;font-weight:700;word-break:break-all}@media(max-width:1100px){.query-panel{grid-template-columns:1fr}.traffic-page{padding:10px}table{min-width:900px}.detail-grid{grid-template-columns:1fr;grid-auto-rows:auto}.table-wrap{overflow:auto}}
.query-panel{grid-template-columns:1.4fr repeat(6,1fr) auto}
</style>
