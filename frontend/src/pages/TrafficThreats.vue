<template>
  <section class="sx-page">
    <header class="sx-page-head">
      <div>
        <p class="sx-kicker">DETECTION SURFACE</p>
        <h2 class="sx-title">{{ title }}</h2>
        <p class="sx-subtitle">
          {{ category === 'rasp'
            ? '应用运行时攻击、检测与阻断证据；数据来自 RASP 组件告警，阻断状态以端侧证据为准。'
            : category === 'runtime'
              ? '主机运行时与日志审计告警；数据来自 eBPF / auditd / procfs 进程采集、认证日志与 Wazuh 组件告警。'
              : '流量检测与攻击会话；数据来自 Suricata / LyFlow 与流量组件告警，按规则与实体聚合。' }}
        </p>
      </div>
      <div class="sx-head-actions">
        <span class="sx-live"><i />LIVE</span>
        <button class="sx-btn" type="button" :disabled="loading" @click="search">{{ loading ? '更新中' : '刷新' }}</button>
      </div>
    </header>

    <section class="tt-stats">
      <article class="sx-metric">
        <span class="sx-metric-label"><i />结果总数</span>
        <strong class="sx-metric-value">{{ total }}</strong>
        <span class="sx-metric-note">当前筛选条件下的聚合记录</span>
      </article>
      <article class="sx-metric">
        <span class="sx-metric-label"><i />高 / 严重</span>
        <strong class="sx-metric-value" :class="highSeverityCount ? 'danger' : ''">{{ highSeverityCount }}</strong>
        <span class="sx-metric-note">当前页样本中的高危记录</span>
      </article>
      <article class="sx-metric">
        <span class="sx-metric-label"><i />来源引擎</span>
        <strong class="sx-metric-value">{{ sourceCount }}</strong>
        <span class="sx-metric-note">当前页出现的数据来源</span>
      </article>
      <article class="sx-metric">
        <span class="sx-metric-label"><i />当前页</span>
        <strong class="sx-metric-value">{{ page }}<em class="tt-page-total">/{{ totalPages }}</em></strong>
        <span class="sx-metric-note">每页 {{ pageSize }} 组，按最后一次发生时间排序</span>
      </article>
    </section>

    <section class="sx-filter tt-filter">
      <label class="wide"><span>关键字</span><input v-model.trim="filters.query" placeholder="IP、域名、路径、探针" @keyup.enter="search"></label>
      <label><span>源 IP</span><input v-model.trim="filters.src_ip" placeholder="10.0.0.1" @keyup.enter="search"></label>
      <label><span>目的 IP</span><input v-model.trim="filters.dst_ip" placeholder="10.0.0.2" @keyup.enter="search"></label>
      <label><span>威胁等级</span>
        <select v-model="filters.severity">
          <option value="">全部</option>
          <option value="low">低</option>
          <option value="medium">中</option>
          <option value="high">高</option>
          <option value="critical">严重</option>
        </select>
      </label>
      <label><span>开始时间</span><input v-model="filters.start_time" type="datetime-local"></label>
      <label><span>结束时间</span><input v-model="filters.end_time" type="datetime-local"></label>
      <button class="sx-btn primary" type="button" :disabled="loading" @click="search">查询</button>
    </section>

    <div v-if="error" class="sx-error">{{ error }}</div>

    <article class="sx-panel">
      <div class="sx-panel-head">
        <div class="sx-panel-title">{{ title }}记录</div>
        <span class="sx-panel-meta">{{ `${threats.length} 组 / 共 ${total} 组 / 第 ${page} 页` }}</span>
      </div>
      <div ref="tableWrap" data-testid="traffic-threat-table" :class="['sx-table-wrap', 'tt-table', { updating: loading && hasLoaded }]">
        <table class="sx-table">
          <thead>
            <tr>
              <th>时间</th><th>等级</th><th>引擎 / 类别</th><th>威胁</th><th>探针</th><th>威胁 IP</th><th>内容</th><th>次数</th><th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading && !hasLoaded"><td colspan="9" class="sx-empty">{{ pageCopy().loading }}</td></tr>
            <tr v-else-if="!threats.length"><td colspan="9" class="sx-empty">{{ pageCopy().empty }}</td></tr>
            <tr v-for="item in threats" :key="item.aggregate_key || item.message_id || item.id" data-testid="traffic-threat-row">
              <td class="tt-time">{{ formatTime(item.timestamp) }}</td>
              <td><span class="sx-badge" :class="severityClass(item.severity)">{{ severityLabel(item.severity) }}</span></td>
              <td><b>{{ sourceEngineLabel(item.source_engine || item.source) }}</b><small>{{ categoryLabel(item.category) }}</small></td>
              <td class="tt-threat"><b>{{ threatTypeLabel(item) }}</b><small>{{ threatMetaText(item) }}</small></td>
              <td>{{ agentName(item) }}</td>
              <td class="sx-mono">{{ threatIP(item) || '-' }}</td>
              <td class="tt-content" :title="contentSummary(item)">{{ contentSummary(item) }}</td>
              <td><span class="sx-badge info">{{ occurrenceCount(item) }}</span></td>
              <td class="tt-action"><button class="sx-btn ghost" type="button" data-testid="traffic-threat-detail-open" @click="selected = item">详情</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="tt-pager">
        <button class="sx-btn" type="button" data-testid="traffic-threat-previous-page" :disabled="loading || page === 1" @click="prevPage">上一页</button>
        <span data-testid="traffic-threat-page" class="sx-mono">第 {{ page }} 页 / {{ totalPages }} 页</span>
        <button class="sx-btn" type="button" data-testid="traffic-threat-next-page" :disabled="loading || page >= totalPages" @click="nextPage">下一页</button>
      </div>
    </article>

    <div v-if="selected" class="sx-drawer-scrim" @click.self="selected = null">
      <aside class="sx-drawer" data-testid="traffic-threat-detail">
        <div class="sx-drawer-head">
          <div>
            <p class="sx-kicker">EVIDENCE</p>
            <div class="sx-panel-title">威胁详情</div>
          </div>
          <button class="sx-btn ghost" type="button" data-testid="traffic-threat-detail-close" @click="selected = null">关闭</button>
        </div>
        <div class="sx-drawer-body tt-detail">
          <dl class="tt-detail-grid">
            <template v-for="row in detailRows(selected)" :key="row.label">
              <dt>{{ row.label }}</dt>
              <dd :data-testid="row.testId">{{ row.value }}</dd>
            </template>
          </dl>
          <div class="tt-detail-actions">
            <button type="button" class="sx-btn primary" :disabled="suppressing || !suppressionRuleValue(selected)" @click="suppressSelected">
              {{ suppressing ? '保存中…' : '标记误报并抑制 30 天' }}
            </button>
            <span v-if="suppressionMessage" class="sx-muted">{{ suppressionMessage }}</span>
          </div>
        </div>
      </aside>
    </div>
  </section>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { assetAgentClient, responseClient, trafficClient } from '../api/domain'
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
const suppressing = ref(false)
const suppressionMessage = ref('')
const tableWrap = ref(null)
const agentNames = ref({})
const capabilityAgents = ref({ traffic: 0, runtime: 0, rasp: 0 })
const filters = ref({ query: '', src_ip: '', dst_ip: '', severity: '', start_time: '', end_time: '' })
let resizeObserver = null
const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))

function pad(value) { return String(value).padStart(2, '0') }
function toLocalInput(date) { return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}` }
function toRFC3339(value) { if (!value) return ''; const date = new Date(value); return Number.isNaN(date.getTime()) ? '' : date.toISOString() }
function applyDefaultWindow() {
  const to = new Date()
  const from = new Date(to.getTime() - 10 * 60 * 1000)
  filters.value.start_time = toLocalInput(from)
  filters.value.end_time = toLocalInput(to)
}
const highSeverityCount = computed(() => threats.value.filter((item) => ['high', 'critical'].includes(item.severity)).length)
const sourceCount = computed(() => new Set(threats.value.map((item) => item.source_engine || item.source).filter(Boolean)).size)

function params() {
  const { start_time, end_time, ...rest } = filters.value
  return { ...rest, start_time: toRFC3339(start_time), end_time: toRFC3339(end_time), limit: pageSize.value, offset: (page.value - 1) * pageSize.value }
}
function apiCategory() { return { application: 'rasp', log: 'log_audit', system: 'runtime' }[props.category] || props.category }
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
function threatMetaText(item) { return [eventTypeLabel(item.event_type), item.stream, item.language].filter(Boolean).join(' · ') }
function eventTypeLabel(value) {
  return { tcp_flow: 'TCP会话流', http_access: 'HTTP访问', dns_query: 'DNS查询', tls_connection: 'TLS连接', admin_access: '管理访问', login: '登录行为', upload: '上传行为', traffic_flow: '流量会话', 'rasp.sql': 'RASP SQL注入', 'rasp.command': 'RASP命令执行', 'rasp.exec': 'RASP命令执行', 'rasp.file': 'RASP文件访问', 'rasp.deserialization': 'RASP反序列化', 'rasp.http': 'RASP SSRF', 'rasp.ssrf': 'RASP SSRF', 'runtime.auth.privilege': '运行时权限活动', 'runtime.process': '进程行为', 'runtime.file': '文件行为', 'log_audit.auth': '认证日志审计' }[value] || value || '安全告警'
}
function categoryLabel(value) { return { traffic: '流量检测', network: '网络检测', host: '主机检测', artifact: '文件检测', log: '日志检测', rasp: '应用防护', log_audit: '日志审计', runtime: '系统安全' }[value] || value || '-' }
function sourceEngineLabel(value) { return { suricata: 'Suricata', wazuh: 'Wazuh', sigma: 'Sigma', yara: 'YARA', rasp: 'RASP', lyflow: 'LyFlow', 'ly-security-engine': '安全引擎', agent: 'Agent', runtime: 'Runtime', log_audit: 'LogAudit', dpi_engine: '历史流量', lyprobe: 'LyFlow 探针', ebpf: 'eBPF', auditd: 'auditd', procfs: 'procfs', 'auth-log-signal': '日志审计' }[value] || value || '-' }
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

function suppressionRuleValue(item) {
  return item?.rule_id || item?.native_rule?.id || item?.rule_name || item?.native_rule?.name || ''
}

async function suppressSelected() {
  const rule = suppressionRuleValue(selected.value)
  if (!rule) {
    suppressionMessage.value = '当前告警没有可用的规则 ID/名称。'
    return
  }
  suppressing.value = true
  suppressionMessage.value = ''
  try {
    await responseClient.suppress({
      suppress_scope: 'rule',
      suppress_value: rule,
      suppress_days: 30,
      reason: '用户在威胁详情中确认误报',
    })
    suppressionMessage.value = `已抑制规则 ${rule} 30 天，后续 XDR 关联不再使用该规则。`
    selected.value = null
    await loadAll()
  } catch (cause) {
    suppressionMessage.value = cause?.message || '规则抑制保存失败。'
  } finally {
    suppressing.value = false
  }
}

let loadSequence = 0

async function loadAll() {
  const sequence = ++loadSequence
  loading.value = true
  error.value = ''
  try {
    const category = apiCategory()
    let data = normalizeItems(await trafficClient.threatCategory(category, params()))
    // Traffic threats are materialized in PostgreSQL. Only use the Redis
    // component stream as a first-load fallback while the backfill catches
    // up; merging it on every query makes items appear and disappear.
    if (!data.items.length && Number(data.total || 0) === 0) {
      data = normalizeItems(await trafficClient.componentAlerts(category, params()))
    }
    if (sequence !== loadSequence) return
    const visibleItems = data.items.filter((item) => !isProtectionHeartbeat(item))
    threats.value = visibleItems.map(normalizeAlert)
    total.value = Math.max(0, Number(data.total) - (data.items.length - visibleItems.length))
    hasLoaded.value = true
  } catch (e) {
    if (sequence === loadSequence) error.value = e?.message || '无法读取威胁告警'
  } finally {
    if (sequence === loadSequence) loading.value = false
  }
}
function isProtectionHeartbeat(item) {
  const type = String(item?.event_type || item?.type || '')
  const summary = String(item?.summary || item?.message || item?.excerpt || '')
  return type.startsWith('rasp.protection.') || /rasp protection heartbeat/i.test(summary)
}
function normalizeAlert(item) {
  const id = entity(item, 'agent_id') || ''
  const metadata = item.metadata || {}
  return {
    ...item,
    timestamp: item.last_seen || item.occurred_at || item.observed_at || item.received_at || item.created_at || item.timestamp,
    event_type: item.event_type || item.type || item.rule_id,
    agent_id: id,
    hostname: entity(item, 'hostname') || item.hostname || '',
    src_ip: entity(item, 'source_ip') || item.src_ip || '',
    dst_ip: entity(item, 'target_ip') || item.dst_ip || '',
    protocol: item.protocol || metadata.protocol,
    app_protocol: item.app_protocol || metadata.app_protocol,
    direction: item.direction || metadata.direction,
    source_engine: item.source_engine || item.native_rule?.engine || metadata.source_engine || (item.category === 'runtime' ? (item.backend || 'runtime') : null) || (item.category === 'rasp' ? 'rasp' : item.source),
    rule_name: item.rule_name || metadata.rule_name,
    summary: contentSummary(item),
    occurrence_count: occurrenceCount(item),
  }
}

function pageCopy() {
  if (apiCategory() === 'rasp') {
    return capabilityAgents.value.rasp
      ? { empty: '暂无应用防护日志', loading: '正在读取应用防护日志' }
      : { empty: '当前接入 Agent 未启用 RASP', loading: '正在读取应用防护日志' }
  }
  if (apiCategory() === 'runtime') {
    return capabilityAgents.value.runtime
      ? { empty: '暂无运行威胁日志', loading: '正在读取运行威胁日志' }
      : { empty: '当前接入 Agent 未启用运行传感器', loading: '正在读取运行威胁日志' }
  }
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
  let runtimeCapable = 0
  let raspCapable = 0
  try {
    const data = normalizeItems(await assetAgentClient.agents({ limit: 200 }))
    for (const a of data.items) {
      map[a.agent_id] = a.display_name || a.hostname || a.agent_id
      const capabilities = a.capabilities || a.metadata?.capabilities || {}
      if (capabilities.runtime_sensor?.enabled) runtimeCapable++
      if (capabilities.rasp_probe_manager?.enabled) raspCapable++
    }
  } catch { /* ignore, fall through to names file */ }
  capabilityAgents.value = { ...capabilityAgents.value, runtime: runtimeCapable, rasp: raspCapable }
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
  applyDefaultWindow()
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
.tt-stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.tt-page-total { margin-left: 3px; color: var(--lyf-ink-3); font-size: 15px; font-weight: 500; }

.tt-filter { display: grid; grid-template-columns: minmax(180px, 1.5fr) repeat(3, minmax(110px, 1fr)) repeat(2, minmax(150px, 1fr)) auto; align-items: end; }
.tt-filter .wide { min-width: 180px; }
.tt-filter input, .tt-filter select { width: 100%; }
.tt-filter button { height: 34px; }

.tt-table { max-height: calc(100vh - 430px); }
.tt-table.updating { opacity: 0.72; }
.tt-time { color: var(--lyf-ink-3); font-family: var(--lyf-font-data); font-size: 11px; white-space: nowrap; }
.tt-threat { max-width: 320px; }
.tt-threat b { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tt-content { max-width: 260px; overflow: hidden; text-overflow: ellipsis; }
.tt-action { text-align: right; }
.tt-action .sx-btn { height: 26px; padding: 0 9px; font-size: 11px; }

.tt-pager { display: flex; align-items: center; justify-content: flex-end; gap: 10px; padding: 10px 14px; border-top: 1px solid var(--lyf-line); background: var(--lyf-surface-2); }
.tt-pager .sx-btn { height: 28px; padding: 0 10px; font-size: 11.5px; }
.tt-pager span { color: var(--lyf-ink-3); font-size: 11px; }

.tt-detail { display: grid; gap: 18px; }
.tt-detail-grid { display: grid; grid-template-columns: 150px minmax(0, 1fr); gap: 1px; margin: 0; border: 1px solid var(--lyf-line); border-radius: var(--lyf-radius-sm); overflow: hidden; }
.tt-detail-grid dt { padding: 9px 12px; background: var(--lyf-surface-2); color: var(--lyf-ink-3); font-size: 11px; }
.tt-detail-grid dd { margin: 0; padding: 9px 12px; overflow-wrap: anywhere; color: var(--lyf-ink); font-family: var(--lyf-font-data); font-size: 11.5px; }
.tt-detail-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; }

@media (max-width: 1400px) {
  .tt-filter { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .tt-filter .wide { grid-column: 1 / -1; }
}
@media (max-width: 1100px) {
  .tt-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .tt-table { max-height: none; }
}
@media (max-width: 720px) {
  .tt-stats { grid-template-columns: minmax(0, 1fr); }
  .tt-filter { grid-template-columns: minmax(0, 1fr); }
  .tt-detail-grid { grid-template-columns: minmax(0, 1fr); }
}
</style>
