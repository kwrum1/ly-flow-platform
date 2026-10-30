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
          <thead><tr><th>时间</th><th>等级</th><th>引擎</th><th>威胁</th><th>源 → 目标</th><th v-if="tab !== 'traffic'">受害服务器</th><th>次数</th><th class="actions" /></tr></thead>
          <tbody>
            <tr v-for="t in items" :key="t.aggregate_key || t.id || t.message_id" class="clickable" @click="selected = t">
              <td class="num">{{ shortTime(t.last_seen || t.timestamp || t.first_seen) }}</td>
              <td><span class="v-badge" :class="t.severity">{{ severityLabel(t.severity) }}</span></td>
              <td>{{ t.source_engine || t.source || '-' }}</td>
              <td class="th-main"><b>{{ t.rule_name || t.rule_id || t.event_type || '安全告警' }}</b><small>{{ t.rule_id || '' }}</small></td>
              <td class="v-mono">{{ (t.entities?.source_ip || t.src_ip || '-') }} → {{ (t.entities?.target_ip || t.dst_ip || '-') }}</td>
              <td v-if="tab !== 'traffic'">{{ agentName(t) }}</td>
              <td class="num">{{ t.count || t.occurrence_count || 1 }}</td>
              <td class="actions"><button class="v-btn sm" type="button" @click.stop="selected = t">详情</button></td>
            </tr>
          </tbody>
        </table>
        <div v-if="!items.length" class="v-table-empty"><strong>{{ loading ? '正在读取' : '暂无情报' }}</strong></div>
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
          <dl class="v-kv">
            <dt>时间</dt><dd>{{ shortTime(selected.first_seen) }} ~ {{ shortTime(selected.last_seen || selected.timestamp) }}</dd>
            <dt v-if="selected.entities?.source_ip || selected.src_ip || selected.entities?.target_ip || selected.dst_ip">源 → 目标</dt>
            <dd v-if="selected.entities?.source_ip || selected.src_ip || selected.entities?.target_ip || selected.dst_ip" class="v-mono">{{ selected.entities?.source_ip || selected.src_ip || '-' }} → {{ selected.entities?.target_ip || selected.dst_ip || '-' }}</dd>
            <dt>端口</dt><dd class="v-mono">{{ selected.src_port || '未知' }} → {{ selected.dst_port || '未知' }}</dd>
            <dt>引擎</dt><dd>{{ selected.source_engine || selected.source || '-' }}</dd>
            <dt>规则</dt><dd class="v-mono">{{ selected.rule_id || selected.component_rule_id || '-' }}</dd>
            <dt v-if="tab !== 'traffic'">受害服务器</dt><dd v-if="tab !== 'traffic'">{{ agentName(selected) }}</dd>
            <dt>次数</dt><dd>{{ selected.count || selected.occurrence_count || 1 }}</dd>
            <dt>摘要</dt><dd>{{ selected.summary || selected.message || '-' }}</dd>
          </dl>
          <section><h3>原始载荷</h3><pre class="raw">{{ pretty(selected) }}</pre></section>
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
const emptyText = computed(() => '暂无情报')

const highCount = computed(() => items.value.filter((t) => ['high', 'critical'].includes(t.severity)).length)
const occurrences = computed(() => items.value.reduce((s, t) => s + (Number(t.count || t.occurrence_count) || 1), 0))
const sourceCount = computed(() => new Set(items.value.map((t) => t.source_engine || t.source).filter(Boolean)).size)

function unwrap(r) { return r?.data?.data ?? r?.data ?? r ?? {} }
function formatNumber(v) { return (Number(v) || 0).toLocaleString('zh-CN') }
function shortTime(v) { return v ? formatChinaDateTime(v) : '-' }
function pretty(v) { try { return JSON.stringify(v, null, 2) } catch { return String(v) } }

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
</style>
