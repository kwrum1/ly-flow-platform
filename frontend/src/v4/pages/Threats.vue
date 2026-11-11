<template>
  <section class="v-page">
    <header class="v-head">
      <div>
        <p class="v-eyebrow">DETECTION SURFACE</p>
        <h1>检测面</h1>
        <p>流量、主机运行时、应用 RASP 与 YARA 四类检测结果。阻断状态以端侧证据为准；monitor 模式不等同于已阻断。</p>
      </div>
      <div class="v-head-actions">
        <div class="v-tabs">
          <button class="v-tab" :class="{ active: tab === 'traffic' }" type="button" @click="switchTab('traffic')">流量</button>
          <button class="v-tab" :class="{ active: tab === 'runtime' }" type="button" @click="switchTab('runtime')">主机运行时</button>
          <button class="v-tab" :class="{ active: tab === 'rasp' }" type="button" @click="switchTab('rasp')">应用 RASP</button>
          <button class="v-tab" :class="{ active: tab === 'yara' }" type="button" @click="switchTab('yara')">YARA 命中</button>
        </div>
        <button class="v-btn" type="button" :disabled="loading" @click="load">{{ loading ? '查询中…' : '刷新' }}</button>
      </div>
    </header>

    <div v-if="error" class="v-error">{{ error }}</div>

    <section class="v-grid c4">
      <article class="v-stat"><span class="v-stat-label"><i />结果</span><strong class="v-stat-value">{{ items.length }}</strong><span class="v-stat-note">当前筛选下的聚合记录</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />高 / 严重</span><strong class="v-stat-value danger">{{ highCount }}</strong><span class="v-stat-note">当前样本</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />命中次数</span><strong class="v-stat-value">{{ formatNumber(occurrences) }}</strong><span class="v-stat-note">聚合后的真实命中</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />来源</span><strong class="v-stat-value">{{ sourceCount }}</strong><span class="v-stat-note">{{ tabHint }}</span></article>
    </section>

    <article class="v-panel">
      <div class="v-panel-body">
        <div class="v-toolbar">
          <label class="v-field grow"><span>关键字</span><input v-model.trim="q" class="v-input" placeholder="IP / 域名 / 路径 / 探针" @keyup.enter="load"></label>
          <label class="v-field"><span>等级</span>
            <select v-model="severity" class="v-select">
              <option value="">全部</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option>
            </select>
          </label>
        </div>
      </div>
      <div class="v-table-wrap">
        <table class="v-table">
          <thead><tr><th>时间</th><th>等级</th><th>引擎</th><th>威胁</th><th>源 → 目标</th><th v-if="tab !== 'traffic'">资产主机</th><th>次数</th><th class="actions" /></tr></thead>
          <tbody>
            <tr v-for="t in items" :key="t.aggregate_key || t.id || t.message_id" class="clickable" @click="selected = t">
              <td class="num">{{ shortTime(t.last_seen || t.timestamp || t.first_seen) }}</td>
              <td><span class="v-badge" :class="t.severity">{{ severityLabel(t.severity) }}</span></td>
              <td>{{ t.source_engine || t.source || '-' }}</td>
              <td class="th-main"><b>{{ t.rule_name || t.rule_id || t.event_type || '安全告警' }}</b><small>{{ t.narrative || t.rule_id || '' }}</small></td>
              <td class="v-mono">{{ pairText(t) }}</td>
              <td v-if="tab !== 'traffic'">{{ agentName(t) }}</td>
              <td class="num">{{ t.count || t.occurrence_count || 1 }}</td>
              <td class="actions"><button class="v-btn sm" type="button" @click.stop="selected = t">详情</button></td>
            </tr>
          </tbody>
        </table>
        <div v-if="!items.length" class="v-table-empty"><strong>{{ loading ? '正在读取' : '暂无检测结果' }}</strong></div>
      </div>
    </article>

    <div v-if="selected" class="v-scrim" @click.self="selected = null">
      <aside class="v-drawer threat-drawer">
        <div class="v-drawer-head">
          <div><p class="v-eyebrow">THREAT</p><div class="v-panel-title">{{ selected.rule_name || selected.rule_id || selected.event_type }}</div></div>
          <button class="v-btn ghost" type="button" @click="selected = null">关闭</button>
        </div>
        <div class="v-drawer-body detail">
          <div class="detail-top">
            <span class="v-badge" :class="selected.severity">{{ severityLabel(selected.severity) }}</span>
            <span class="v-badge info">{{ tabLabel }}</span>
            <span class="v-badge muted">{{ selected.aggregate_key || selected.id }}</span>
          </div>

          <!-- 人类可读结论优先：分析员据此判断，而不是读签名名 -->
          <section v-if="selected.narrative" class="narrative">
            <h3>发生了什么</h3>
            <p class="narrative-text">{{ selected.narrative }}</p>
            <p v-if="selected.narrative_detail" class="narrative-detail">{{ selected.narrative_detail }}</p>
          </section>

          <dl class="v-kv">
            <dt>时间</dt><dd>{{ shortTime(selected.first_seen) }} ~ {{ shortTime(selected.last_seen || selected.timestamp) }}</dd>
            <dt>攻击来源</dt>
            <dd class="v-mono">
              {{ selected.source_display || selected.entities?.source_ip || selected.src_ip || '-' }}
              <span v-if="selected.client_forwarded_for && selected.client_forwarded_for !== selected.src_ip" class="hint">
                （X-Forwarded-For 自述客户端 {{ selected.client_forwarded_for }}，仅供参考，未经核实）
              </span>
            </dd>
            <dt>受害服务器</dt>
            <dd class="v-mono">
              {{ selected.victim_ip || selected.entities?.target_ip || selected.dst_ip || selected.victim_display || '-' }}
              <span v-if="selected.requested_domain" class="hint">
                （请求域名 {{ selected.requested_domain }}；域名只说明客户端想访问谁，不等于被打的服务器）
              </span>
            </dd>
            <dt>端口</dt><dd class="v-mono">{{ selected.src_port || '未知' }} → {{ selected.dst_port || '未知' }}</dd>
            <dt>引擎</dt><dd>{{ selected.source_engine || selected.source || '-' }}</dd>
            <dt>规则</dt><dd class="v-mono">{{ selected.rule_name || selected.rule_id || selected.component_rule_id || '-' }}</dd>
            <dt v-if="tab !== 'traffic'">资产主机</dt><dd v-if="tab !== 'traffic'">{{ agentName(selected) }}</dd>
            <dt>次数</dt><dd>{{ selected.count || selected.occurrence_count || 1 }}</dd>
            <dt>分诊状态</dt><dd>{{ triageLabel(selected.triage_status) }}</dd>
          </dl>

          <section v-if="requestLines(selected).length">
            <h3>请求内容</h3>
            <dl class="v-kv">
              <template v-for="line in requestLines(selected)" :key="line.label">
                <dt>{{ line.label }}</dt><dd class="v-mono">{{ line.value }}</dd>
              </template>
            </dl>
          </section>

          <section>
            <h3>原始载荷</h3>
            <p class="hint">仅用于核对，日常判断请以上面的说明为准。</p>
            <pre class="raw">{{ pretty(selected) }}</pre>
          </section>
        </div>
      </aside>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { assetAgentClient, opsClient, trafficClient } from '../../api/domain'
import { severityLabel } from '../../domain/attack-labels'
import { formatChinaDateTime } from '../../shared/time'

const tab = ref('traffic')
const q = ref('')
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
    if (agent.hostname && name) map.set(String(agent.hostname), name)
    if (agent.ip && name) map.set(String(agent.ip), name)
  }
  return map
})

function agentName(event) {
  return agentNameById.value.get(String(event.agent_id || '')) ||
    agentNameById.value.get(String(event.asset_id || '')) ||
    agentNameById.value.get(String(event.hostname || '')) ||
    agentNameById.value.get(String(event.entities?.hostname || '')) ||
    event.agent_display_name || event.display_name || event.hostname || event.asset_id || '未知服务器'
}

const tabLabel = computed(() => ({ traffic: '流量检测', runtime: '主机运行时', rasp: '应用 RASP', yara: 'YARA 命中' })[tab.value])
const tabHint = computed(() => ({ traffic: 'Suricata / lyprobe', runtime: 'eBPF / auditd', rasp: 'Agent RASP', yara: 'YARA 文件扫描' })[tab.value])
const emptyText = computed(() => '暂无检测结果')

const highCount = computed(() => items.value.filter((t) => ['high', 'critical'].includes(t.severity)).length)
const occurrences = computed(() => items.value.reduce((s, t) => s + (Number(t.count || t.occurrence_count) || 1), 0))
const sourceCount = computed(() => new Set(items.value.map((t) => t.source_engine || t.source).filter(Boolean)).size)

function unwrap(r) { return r?.data?.data ?? r?.data ?? r ?? {} }
function formatNumber(v) { return (Number(v) || 0).toLocaleString('zh-CN') }
function shortTime(v) { return v ? formatChinaDateTime(v) : '-' }
function pretty(v) { try { return JSON.stringify(v, null, 2) } catch { return String(v) } }

// 列表里的「来源 → 目标」用可识别的地址，而不是站点名。受害服务器就是报文
// 目的地址；请求域名只作参考，不替代地址。
function pairText(row) {
  if (!row) return '-'
  const src = row.source_display || row.entities?.source_ip || row.src_ip || '-'
  const dst = row.victim_ip || row.entities?.target_ip || row.dst_ip || '-'
  if (src === '-' && dst === '-') return '-'
  return `${src} → ${dst}`
}

// 分诊状态的中文表述，避免把 true_positive 这类枚举直接暴露给分析员。
function triageLabel(status) {
  return ({
    new: '未处置',
    triaged: '已查看',
    true_positive: '确认为真实攻击',
    false_positive: '确认为误报',
    closed: '已关闭',
  })[status] || '未处置'
}

// 把请求细节拆成可直接阅读的行，只在有值时出现。同一个域名只出现一次。
function requestLines(row) {
  const lines = []
  if (!row) return lines
  const seen = new Set()
  const add = (label, value) => {
    if (!value || seen.has(value)) return
    seen.add(value)
    lines.push({ label, value })
  }
  add('请求域名', row.requested_domain || row.http_host || row.tls_sni || row.dns_query)
  const method = row.http_method
  const uri = row.http_uri || row.http_path
  if (method || uri) add('请求', `${method || ''} ${uri || ''}`.trim())
  add('TLS SNI', row.tls_sni)
  add('DNS 查询', row.dns_query)
  add('TLS 指纹 JA3', row.tls_ja3)
  add('TLS 指纹 JA4', row.tls_ja4)
  add('应用协议', row.app_proto ? String(row.app_proto).toUpperCase() : '')
  add('X-Forwarded-For（自述，仅供参考）', row.client_forwarded_for)
  return lines
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [threatResult, agentResult] = await Promise.allSettled([
      tab.value === 'yara'
        ? opsClient.eventSample({ limit: 200, category: 'artifact', q: q.value || undefined, severity: severity.value || undefined })
        : trafficClient.threatCategory(tab.value, {
          limit: 200,
          query: q.value || undefined,
          severity: severity.value || undefined,
        }),
      assetAgentClient.agents({ limit: 500 }),
    ])
    if (threatResult.status === 'fulfilled') {
      items.value = unwrap(threatResult.value).items || []
    } else {
      throw threatResult.reason
    }
    agents.value = agentResult.status === 'fulfilled' ? (unwrap(agentResult.value).items || []) : []
  } catch (e) {
    error.value = e?.message || '威胁读取失败'
    items.value = []
  } finally {
    loading.value = false
  }
}

function switchTab(k) { if (tab.value !== k) { tab.value = k; selected.value = null; load() } }

onMounted(load)
</script>

<style scoped>
.clickable { cursor: pointer; }
.th-main { max-width: 380px; }
.th-main b { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.detail { display: grid; gap: 20px; }
.detail-top { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.detail h3 { margin-bottom: 10px; color: var(--v-ink); font-size: 12.5px; font-weight: 620; }
.threat-drawer { width: min(38vw, 520px); max-width: 520px; }
.threat-drawer .v-kv dt, .threat-drawer .v-kv dd { padding: 8px 10px; font-size: 11.5px; }
.threat-drawer .detail { gap: 14px; }
.raw { margin: 0; max-height: 320px; padding: 12px; overflow-y: auto; overflow-x: hidden; border: 1px solid var(--v-line); border-radius: var(--v-radius-sm); background: var(--v-surface-3); color: var(--v-ink-2); font-family: var(--v-mono); font-size: 10.5px; line-height: 1.55; white-space: pre-wrap; word-break: break-word; }
.narrative { padding: 12px 14px; border: 1px solid var(--v-line); border-left: 3px solid var(--v-accent, #3b6fd4); border-radius: var(--v-radius-sm); background: var(--v-surface-2); }
.narrative-text { margin: 0; color: var(--v-ink); font-size: 12.5px; line-height: 1.7; }
.narrative-detail { margin: 8px 0 0; color: var(--v-ink-2); font-size: 11.5px; line-height: 1.7; }
.hint { color: var(--v-ink-3); font-size: 10.5px; font-weight: 400; }
</style>
