<template>
  <section class="events-page">
    <section class="query-panel surface-card">
      <label><span>关键字</span><input v-model.trim="filters.query" placeholder="IP、域名、路径、探针"></label>
      <label><span>源 IP</span><input v-model.trim="filters.src_ip"></label>
      <label><span>目的 IP</span><input v-model.trim="filters.dst_ip"></label>
      <label><span>威胁等级</span><select v-model="filters.severity"><option value="">全部</option><option value="low">低</option><option value="medium">中</option><option value="high">高</option><option value="critical">严重</option></select></label>
      <label><span>开始时间</span><input v-model="filters.start_time" type="datetime-local"></label>
      <label><span>结束时间</span><input v-model="filters.end_time" type="datetime-local"></label>
      <button class="primary" @click="search" :disabled="loading">{{ loading ? '更新中' : '查询' }}</button>
    </section>

    <div v-if="error" class="notice error">{{ error }}</div>

    <article class="events-panel surface-card">
      <div class="panel-title"><strong>{{ title }}</strong><span>{{ `${threats.length} 组 / 共 ${total} 组 / 当前页 ${pageSize} 组` }}</span></div>
      <div ref="tableWrap" data-testid="traffic-threat-table" :class="['table-wrap', { updating: loading && hasLoaded }]">
        <table>
          <thead><tr><th>时间</th><th>等级</th><th>检测引擎</th><th>威胁类型</th><th>探针</th><th>威胁IP</th><th>威胁内容</th><th>次数</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-if="loading && !hasLoaded"><td colspan="9" class="empty-cell">{{ pageCopy().loading }}</td></tr>
            <tr v-else-if="!threats.length"><td colspan="9" class="empty-cell">{{ pageCopy().empty }}</td></tr>
            <tr v-for="item in threats" :key="item.aggregate_key || item.message_id || item.id" data-testid="traffic-threat-row">
              <td>{{ formatTime(item.timestamp) }}</td>
              <td><span :class="['severity', severityClass(item.severity)]">{{ severityLabel(item.severity) }}</span></td>
              <td><span class="engine-chip">{{ sourceEngineLabel(item.source_engine || item.source) }}</span><small>{{ categoryLabel(item.category) }}</small></td>
              <td><b>{{ threatTypeLabel(item) }}</b><small>{{ threatMetaText(item) }}</small></td>
              <td>{{ agentName(item) }}</td>
              <td>{{ threatIP(item) }}</td>
              <td>{{ contentSummary(item) }}</td>
              <td><span class="count-chip">{{ occurrenceCount(item) }}</span></td>
              <td><button data-testid="traffic-threat-detail-open" @click="selected = item">详情</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="pager">
        <button data-testid="traffic-threat-previous-page" @click="prevPage" :disabled="loading || page === 1">上一页</button>
        <span data-testid="traffic-threat-page">第 {{ page }} 页 / {{ totalPages }} 页</span>
        <button data-testid="traffic-threat-next-page" @click="nextPage" :disabled="loading || page >= totalPages">下一页</button>
      </div>
    </article>

    <div v-if="selected" class="drawer-mask">
      <aside class="drawer surface-card" data-testid="traffic-threat-detail">
        <div class="drawer-title"><strong>威胁详情</strong><button data-testid="traffic-threat-detail-close" @click="selected = null">×</button></div>
        <div class="detail-grid">
          <template v-for="row in detailRows(selected)" :key="row.label">
            <span>{{ row.label }}</span><b :data-testid="row.testId">{{ row.value }}</b>
          </template>
        </div>
      </aside>
    </div>
  </section>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { assetAgentClient, trafficClient } from '../api/domain'
import { normalizeItems } from '../shared/api-normalize'
import { formatChinaDateTime } from '../shared/time'

const props = defineProps({
  category: { type: String, default: 'traffic' },
  title: { type: String, default: '流量分析威胁' },
})

const pageSize = ref(12)
const page = ref(1)
const loading = ref(false)
const hasLoaded = ref(false)
const error = ref('')
const threats = ref([])
const total = ref(0)
const selected = ref(null)
const tableWrap = ref(null)
const agentNames = ref({})
const filters = ref({ query: '', src_ip: '', dst_ip: '', severity: '', start_time: '', end_time: '' })
let resizeObserver = null
const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))

function params() { return { ...filters.value, limit: pageSize.value, offset: (page.value - 1) * pageSize.value } }
function apiCategory() { return { application: 'rasp', log: 'log_audit', runtime: 'log_audit', system: 'runtime' }[props.category] || props.category }
function formatTime(value) { return value ? formatChinaDateTime(value) : '-' }
function occurrenceCount(item) { return Number(item?.occurrence_count || item?.count || 1) || 1 }
function entity(item, key) { return item?.entities?.[key] || item?.[key] || '' }
function display(value) { return value === undefined || value === null || value === '' ? '-' : String(value) }
function tupleText(item) { return `${entity(item, 'source_ip') || item.src_ip || '-'}:${item.src_port || 0} → ${entity(item, 'target_ip') || item.dst_ip || '-'}:${item.dst_port || 0}` }
function directionLabel(value) { return { egress: '出站', ingress: '入站' }[value] || value || '-' }
function threatIP(item) {
  const src = entity(item, 'source_ip') || item.src_ip || ''
  const dst = entity(item, 'target_ip') || item.dst_ip || ''
  const port = item.src_port ? ':' + item.src_port : ''
  if (src) return src + port
  if (dst) return dst
  return ''
}
function severityLabel(value) { return { low: '低', medium: '中', high: '高', critical: '严重' }[value] || value || '低' }
function severityClass(value) { return ['low', 'medium', 'high', 'critical'].includes(value) ? value : 'low' }
function threatTypeLabel(item) { return item.rule_name || item.rule_id || item.type || eventTypeLabel(item.event_type || item.type) || item.message || '安全告警' }
function threatMetaText(item) { return [eventTypeLabel(item.event_type), item.stream].filter(Boolean).join(' · ') }
function eventTypeLabel(value) {
  return { tcp_flow: 'TCP会话流', http_access: 'HTTP访问', dns_query: 'DNS查询', tls_connection: 'TLS连接', admin_access: '管理访问', login: '登录行为', upload: '上传行为', traffic_flow: '流量会话', 'rasp.sql': 'RASP SQL注入', 'rasp.exec': 'RASP命令执行', 'rasp.file': 'RASP文件访问', 'rasp.deserialization': 'RASP反序列化', 'rasp.ssrf': 'RASP SSRF', 'runtime.auth.privilege': '运行时权限活动', 'runtime.process': '进程行为', 'runtime.file': '文件行为', 'log_audit.auth': '认证日志审计' }[value] || value || '安全告警'
}
function categoryLabel(value) { return { traffic: '流量检测', network: '网络检测', host: '主机检测', artifact: '文件检测', log: '日志检测', rasp: '应用防护', log_audit: '日志审计', runtime: '系统安全' }[value] || value || '-' }
function sourceEngineLabel(value) { return { suricata: 'Suricata', wazuh: 'Wazuh', sigma: 'Sigma', yara: 'YARA', rasp: 'RASP', lyflow: 'LyFlow', agent: 'Agent', runtime: 'Runtime', log_audit: 'LogAudit', dpi_engine: 'DPI' }[value] || value || '-' }
function stageLabel(value) { return { recon: '侦察探测', initial_access: '初始入侵', execution: '执行载荷', persistence: '持久化', privilege_escalation: '权限提升', lateral_movement: '横向移动', c2_exfiltration: '外联/泄露', detection: '检测命中' }[value] || value || '-' }
function contentSummary(item) { return item.summary || item.message || threatTypeLabel(item) || item.http_host || item.dns_query || item.tls_sni || [item.http_method, item.http_path].filter(Boolean).join(' ') || eventTypeLabel(item.event_type || item.type) }
function detailRows(item) {
  return [
    ['原生规则来源', item.native_rule?.source, 'traffic-threat-detail-native-source'],
    ['原生规则 SID', item.native_rule?.id, 'traffic-threat-detail-native-sid'],
    ['原生规则版本', item.native_rule?.revision, 'traffic-threat-detail-native-revision'],
    ['原始引用路径', item.raw_reference?.path, 'traffic-threat-detail-raw-path'],
    ['原始引用哈希', item.raw_reference?.hash, 'traffic-threat-detail-raw-hash'],
    ['告警次数', occurrenceCount(item)], ['起始时间', formatTime(item.first_seen)], ['最后一次时间', formatTime(item.last_seen || item.timestamp)],
    ['威胁等级', severityLabel(item.severity)], ['检测引擎', sourceEngineLabel(item.source_engine || item.source)], ['检测类别', categoryLabel(item.category)], ['攻击阶段', stageLabel(item.stage_hint)],
    ['命中规则', threatTypeLabel(item)], ['规则ID', item.rule_id], ['威胁类型', threatTypeLabel(item)], ['探针名', agentName(item)], ['主机名', entity(item, 'hostname') || item.hostname],
    ['威胁IP', threatIP(item) || '-'], ['源端口', item.src_port], ['目的IP', entity(item, 'target_ip') || item.dst_ip], ['目的端口', item.dst_port], ['传输协议', item.protocol], ['应用协议', item.app_protocol],
    ['业务行为', eventTypeLabel(item.business_action)], ['流量方向', directionLabel(item.direction)],
    ['HTTP主机', item.http_host], ['HTTP方法', item.http_method], ['HTTP路径', item.http_path],
    ['DNS查询', item.dns_query], ['TLS SNI', item.tls_sni], ['威胁内容', item.summary],
  ].filter(([, value]) => display(value) !== '-').map(([label, value, testId]) => ({ label, value: display(value), testId }))
}

async function loadAll() {
  loading.value = true
  error.value = ''
  try {
    const data = normalizeItems(await trafficClient.threatCategory(apiCategory(), params()))
    threats.value = data.items.map(normalizeAlert)
    total.value = data.total
    hasLoaded.value = true
  } catch (e) {
    error.value = e?.message || '无法读取威胁告警'
  } finally {
    loading.value = false
  }
}
function normalizeAlert(item) {
  const id = entity(item, 'agent_id') || ''
  const metadata = item.metadata || {}
  return {
    ...item,
    timestamp: item.last_seen || item.occurred_at || item.created_at || item.timestamp,
    event_type: item.event_type || item.type || item.rule_id,
    agent_id: id,
    hostname: entity(item, 'hostname') || item.hostname || '',
    src_ip: entity(item, 'source_ip') || item.src_ip || '',
    dst_ip: entity(item, 'target_ip') || item.dst_ip || '',
    protocol: item.protocol || metadata.protocol,
    app_protocol: item.app_protocol || metadata.app_protocol,
    direction: item.direction || metadata.direction,
    source_engine: item.source_engine || item.native_rule?.engine || metadata.source_engine || item.source,
    rule_name: item.rule_name || metadata.rule_name,
    summary: contentSummary(item),
    occurrence_count: occurrenceCount(item),
  }
}

function pageCopy() {
  if (apiCategory() === 'rasp') return { empty: '暂无应用防护日志', loading: '正在读取应用防护日志' }
  if (apiCategory() === 'log_audit') return { empty: '暂无主机审计日志', loading: '正在读取主机审计日志' }
  return { empty: '无流量威胁日志', loading: '正在读取流量威胁日志' }
}
function agentName(item) {
  const id = entity(item, 'agent_id') || item.agent_id || ''
  if (isMirrorTraffic(item, id)) return '流量镜像分析'
  return agentNames.value[id] || item.agent_display_name || item.display_name || item.probe_name || id || '-'
}

function isMirrorTraffic(item, id = '') {
  return item.capture_source === 'mirror' || item.probe_name === '流量镜像分析' || item.agent_display_name === '流量镜像分析' || item.display_name === '流量镜像分析' || !id || id === 'local' || id === 'localhost'
}

async function loadAgents() {
  // DB-registered agents have highest priority (rename via ControlCenter syncs here)
  const map = {}
  try {
    const data = normalizeItems(await assetAgentClient.agents({ limit: 200 }))
    for (const a of data.items) {
      map[a.agent_id] = a.display_name || a.hostname || a.agent_id
    }
  } catch { /* ignore, fall through to names file */ }
  try {
    const namesData = await assetAgentClient.agentNames()
    const names = namesData?.names || {}
    for (const [id, name] of Object.entries(names)) {
      if (!map[id]) map[id] = name
    }
  } catch { /* ignore */ }
  agentNames.value = map
}

function search() { page.value = 1; loadAll() }
function prevPage() { if (page.value > 1) { page.value -= 1; loadAll() } }
function nextPage() { if (page.value < totalPages.value) { page.value += 1; loadAll() } }
function updatePageSize({ reload = true } = {}) {
  const height = tableWrap.value?.clientHeight || 0
  if (!height) return
  const nextSize = Math.max(8, Math.floor((height - 36) / 38))
  if (nextSize !== pageSize.value) { pageSize.value = nextSize; if (reload) loadAll() }
}
onMounted(async () => {
  await nextTick()
  updatePageSize({ reload: false })
  if (tableWrap.value && typeof ResizeObserver !== 'undefined') {
    resizeObserver = new ResizeObserver(updatePageSize)
    resizeObserver.observe(tableWrap.value)
  }
  loadAgents()
  loadAll()
})
onUnmounted(() => { if (resizeObserver) resizeObserver.disconnect() })
</script>

<style scoped>
.events-page{position:relative;height:100%;min-height:0;display:grid;grid-template-rows:auto minmax(0,1fr);gap:12px;padding:14px;color:var(--text-primary);box-sizing:border-box}.query-panel,.events-panel{border-color:var(--border-color)}.query-panel{display:grid;grid-template-columns:1.4fr repeat(5,minmax(110px,1fr)) auto;gap:9px;align-items:end;padding:12px;min-height:0}.query-panel label{display:grid;gap:5px;min-width:0;color:var(--text-secondary);font-size:12px}input,select{height:32px;min-width:0;border:1px solid var(--border-color);border-radius:var(--card-radius-sm);background:var(--bg-secondary);color:var(--text-primary);padding:0 11px;font-size:12px;outline:0}input::placeholder{color:var(--text-muted)}input:focus,select:focus{border-color:var(--border-glow);box-shadow:0 0 0 3px var(--primary-glow)}button{height:32px;padding:0 12px;border:1px solid var(--border-color);border-radius:var(--card-radius-sm);background:var(--bg-elevated);color:var(--text-secondary);cursor:pointer;font-size:12px;transition:border-color var(--transition-fast),color var(--transition-fast),background var(--transition-fast)}button:hover:not(:disabled){border-color:var(--border-glow);color:var(--text-primary);background:var(--bg-hover)}button:disabled{opacity:.45;cursor:not-allowed}.primary{border:0;background:linear-gradient(135deg,var(--primary-color),var(--risk-low));color:var(--text-inverse);font-weight:900;box-shadow:0 10px 28px rgba(56,189,248,.18)}.events-panel{min-height:0;display:grid;grid-template-rows:44px minmax(0,1fr) 40px}.panel-title{position:relative;height:44px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;border-bottom:1px solid var(--border-light);background:rgba(4,12,24,.38)}.panel-title strong{color:var(--text-primary);font-size:14px}.panel-title span{color:var(--text-muted);font-size:12px}.table-wrap{position:relative;min-height:0;overflow:auto}.table-wrap.updating{opacity:.72}table{width:100%;min-width:1180px;border-collapse:separate;border-spacing:0;table-layout:fixed}th,td{padding:8px 12px;border-bottom:1px solid var(--border-light);text-align:center;vertical-align:middle}th{position:sticky;top:0;z-index:1;height:36px;color:var(--text-muted);background:var(--bg-card);font-size:11px;font-weight:900;letter-spacing:.08em;text-transform:uppercase}td{height:38px;color:var(--text-primary);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}td b{display:block;color:var(--text-primary);font-size:12px;overflow:hidden;text-overflow:ellipsis}td small{display:block;margin-top:2px;color:var(--text-muted);overflow:hidden;text-overflow:ellipsis}.empty-cell{height:96px;text-align:center;color:var(--text-secondary)}.count-chip{display:inline-flex;align-items:center;justify-content:center;min-width:42px;padding:3px 8px;border:1px solid rgba(52,211,153,.24);border-radius:999px;color:var(--risk-low);background:rgba(52,211,153,.09);font-weight:900}.engine-chip{display:inline-flex;max-width:100%;padding:3px 8px;border:1px solid rgba(125,211,252,.24);border-radius:999px;color:var(--primary-light);background:rgba(125,211,252,.09);overflow:hidden;text-overflow:ellipsis}.severity{display:inline-flex;justify-content:center;min-width:44px;padding:3px 8px;border-radius:999px;font-size:11px;font-weight:900}.severity.low{color:var(--risk-low);background:var(--risk-low-bg);border:1px solid var(--risk-low-border)}.severity.medium{color:var(--risk-medium);background:var(--risk-medium-bg);border:1px solid var(--risk-medium-border)}.severity.high,.severity.critical{color:var(--risk-critical);background:var(--risk-critical-bg);border:1px solid var(--risk-critical-border)}.pager{position:relative;display:flex;align-items:center;justify-content:flex-end;gap:10px;padding:4px 14px;border-top:1px solid var(--border-light);background:rgba(4,12,24,.34)}.pager span{min-width:72px;text-align:center;color:var(--text-secondary);font-size:12px}.notice.error{padding:10px 12px;border:1px solid var(--risk-critical-border);border-radius:var(--card-radius-sm);color:#fecaca;background:var(--risk-critical-bg)}.drawer-mask{position:fixed;inset:0;z-index:40;display:flex;justify-content:flex-end;padding:74px 24px 24px;background:rgba(2,8,23,.58)}.drawer{width:min(640px,92vw);height:100%;display:grid;grid-template-rows:auto minmax(0,1fr);overflow:hidden}.drawer-title{position:relative;display:flex;align-items:center;justify-content:space-between;gap:14px;padding:16px 18px;border-bottom:1px solid var(--border-light)}.drawer-title strong{font-size:16px}.drawer-title button{font-size:18px}.detail-grid{display:grid;grid-template-columns:112px minmax(0,1fr);gap:10px 14px;padding:18px;overflow:auto}.detail-grid span{display:flex;align-items:center;justify-content:center;color:var(--text-muted);font-size:12px}.detail-grid b{display:flex;align-items:center;justify-content:center;text-align:center;min-width:0;color:var(--text-primary);font-size:12px;word-break:break-word}@media(max-width:1100px){.query-panel{grid-template-columns:repeat(2,minmax(0,1fr)) auto}.events-page{padding:10px}}@media(max-width:760px){.query-panel{grid-template-columns:1fr}.drawer-mask{padding:54px 10px 10px}}
.events-page{color:#243149}.query-panel,.events-panel,.drawer{border-color:#dce4ef!important;background:#fff!important;border-radius:6px!important;box-shadow:0 3px 12px rgba(44,66,96,.08)!important}.query-panel label{color:#526078}.query-panel input,.query-panel select{border-color:#d6dfeb;background:#fff;color:#273449;border-radius:4px}.query-panel button,.events-panel button,.drawer button{border-color:#d6dfeb;background:#fff;color:#40506a;border-radius:4px}.query-panel .primary{border-color:#1769d2;background:#1769d2;color:#fff;box-shadow:none}.panel-title,.pager{background:#f7f9fc;border-color:#e1e7ef}.panel-title strong,td,td b,.drawer-title strong,.detail-grid b{color:#263247}.panel-title span,td small,.pager span,.detail-grid span{color:#768399}th{background:#eef3f8;color:#53627a;letter-spacing:0}th,td{border-color:#e6ebf2}.engine-chip{border-color:#b9d6f4;background:#e8f3ff;color:#1769d2;border-radius:4px;font-weight:750}.count-chip{border-color:#b8dfca;background:#edf9f2;color:#19794b;border-radius:4px}.severity{border-radius:4px}.notice.error{color:#a72820;background:#fff2f1}.drawer-mask{background:rgba(32,45,63,.28)}
</style>
