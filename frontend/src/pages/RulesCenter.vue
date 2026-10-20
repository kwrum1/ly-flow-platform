<template>
  <section class="ops-page">
    <header class="page-head">
      <div>
        <p>ENGINE RULE OPS</p>
        <h2>规则中心</h2>
      </div>
    </header>

    <div v-if="error" class="state-card error-state">{{ error }}</div>
    <article class="surface-card source-card">
      <div class="panel-heading">
        <strong>规则源同步</strong>
        <span>{{ sourceRows.length }} 个规则模块 / {{ totalNativeCount }} 条原生规则</span>
      </div>
      <div class="source-grid">
        <div v-for="item in sourceRows" :key="item.key" :class="['source-row', `engine-${item.key}`]">
          <div class="source-main">
            <span :class="['status-dot', item.running ? 'ok' : item.installed ? 'warn' : 'bad']"></span>
            <div>
              <b>{{ item.title }}</b>
              <small>{{ item.subtitle }}</small>
            </div>
          </div>
          <div class="source-fields">
            <div class="path-field"><span>本地路径</span><strong :title="item.localPath">{{ item.localPath }}</strong></div>
            <div v-if="item.feeds?.length" class="feed-field"><span>更新源</span><strong>{{ item.feeds.length }} 个</strong></div>
            <div><span>当前版本</span><strong :title="item.currentVersion">{{ item.currentVersion }}</strong></div>
            <div><span>最新版本</span><strong :title="item.latestVersion">{{ item.latestVersion }}</strong></div>
            <div><span>{{ item.ruleCountLabel }}</span><strong>{{ item.ruleCount }} 条</strong></div>
            <div v-if="item.ruleFileCount !== null"><span>规则文件</span><strong>{{ item.ruleFileCount }} 个</strong></div>
          </div>
          <div v-if="item.feeds?.length" class="feed-list">
            <span v-for="feed in item.feeds" :key="feed.source_id" :title="feed.name">{{ feed.name }}</span>
          </div>
          <div class="source-actions">
            <em :class="item.running ? 'run' : item.installed ? 'warn' : 'bad'">{{ item.statusText }}</em>
            <button v-if="item.updatable" type="button" @click.prevent.stop="updateSourceRow(item)" :disabled="updatingSource === item.key">
              {{ updatingSource === item.key ? '更新中' : '更新' }}
            </button>
          </div>
          <p v-if="sourceMessages[item.key]" class="row-message">{{ sourceMessages[item.key] }}</p>
        </div>
      </div>
    </article>

    <article class="surface-card rules-panel">
      <div class="panel-title filters">
        <div class="panel-copy">
          <strong>规则清单</strong>
          <span>{{ `${nativeRules.length} 条 / 共 ${total} 条 / 当前页 ${pageSize} 条` }}</span>
        </div>
        <div class="filter-controls">
          <label><span>引擎</span>
            <select v-model="engine" @change="resetAndLoad">
              <option value="">全部</option>
              <option value="suricata">流量威胁</option>
              <option value="wazuh">运行威胁</option>
              <option value="yara">文件扫描</option>
              <option value="rasp">应用防护</option>
            </select>
          </label>
          <input v-model.trim="query" placeholder="搜索规则 ID / 名称 / 路径" @keyup.enter="resetAndLoad">
          <button type="button" @click="resetAndLoad" :disabled="loading">查询</button>
        </div>
      </div>

      <div class="table-wrap">
        <table>
          <thead>
            <tr><th class="rule-col">规则</th><th class="engine-col">引擎</th><th class="path-col">路径</th><th class="status-col">状态</th><th class="severity-col">等级</th><th class="action-col">操作</th></tr>
          </thead>
          <tbody>
            <tr v-if="loading && !nativeRules.length"><td colspan="6" class="empty-cell">正在读取原生规则</td></tr>
            <tr v-else-if="!nativeRules.length"><td colspan="6" class="empty-cell">当前没有读取到原生引擎规则。</td></tr>
            <tr v-for="rule in nativeRules" :key="nativeRuleKey(rule)">
              <td class="rule-cell"><b>{{ pickText(rule.name || rule.id, '未命名规则') }}</b><small>ID {{ rule.id || '-' }} · {{ rule.native_type === 'traffic_feed_rule' ? '流量特征规则' : '原生规则' }}</small></td>
              <td class="engine-cell"><span class="engine-chip">{{ engineLabel(rule.engine) }}</span></td>
              <td class="path-cell"><b>{{ shortPath(rule.path) }}</b><small>line {{ rule.line || '-' }}</small></td>
              <td class="status-cell">
                <label class="enable-pill" :class="{ active: draftFor(rule).enabled }">
                  <input type="checkbox" :checked="draftFor(rule).enabled" @change="setDraft(rule, { enabled: $event.target.checked })">
                  <span>{{ draftFor(rule).enabled ? '启用' : '停用' }}</span>
                </label>
              </td>
              <td class="severity-cell">
                <div class="severity-pills" role="radiogroup" aria-label="规则等级">
                  <button v-for="option in severityOptions" :key="option.value" type="button" :class="['severity-pill', option.value, { active: draftFor(rule).severity === option.value }]" @click="setDraft(rule, { severity: option.value })">{{ option.label }}</button>
                </div>
              </td>
              <td class="action-cell"><button class="confirm-btn" :disabled="savingRules[nativeRuleKey(rule)] || !isDirty(rule)" @click="confirmRule(rule)">{{ savingRules[nativeRuleKey(rule)] ? '生效中' : isDirty(rule) ? '确定' : '已生效' }}</button><small v-if="ruleMessages[nativeRuleKey(rule)]" class="row-message">{{ ruleMessages[nativeRuleKey(rule)] }}</small></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="pager">
        <button type="button" @click="prevPage" :disabled="loading || page === 1">上一页</button>
        <span>第 {{ page }} 页 / {{ totalPages }} 页</span>
        <button type="button" @click="nextPage" :disabled="loading || page >= totalPages">下一页</button>
      </div>
    </article>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ruleClient } from '../api/domain'
import { normalizeItems, pickText } from '../shared/api-normalize'

const loading = ref(false)
const updatingSource = ref('')
const error = ref('')
const nativeRules = ref([])
const runtimeStatus = ref({ engines: {} })
const counts = ref({})
const countSemantics = ref({})
const sourceItems = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(24)
const engine = ref('')
const query = ref('')
const ruleDrafts = reactive({})
const savingRules = reactive({})
const ruleMessages = reactive({})
const sourceMessages = reactive({})

const severityOptions = [
  { value: 'info', label: '信息', score: 20 },
  { value: 'low', label: '低', score: 35 },
  { value: 'medium', label: '中', score: 55 },
  { value: 'high', label: '高', score: 75 },
  { value: 'critical', label: '严重', score: 95 },
]

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))
const totalNativeCount = computed(() => Object.values(counts.value || {}).reduce((sum, value) => sum + Number(value || 0), 0))
const sourceRows = computed(() => {
  const engines = runtimeStatus.value?.engines || {}
  const trafficSources = sourceItems.value.filter((source) => isTrafficSource(source))
  const suricataSemantics = countSemantics.value?.suricata || {}
  return ['suricata', 'wazuh', 'yara', 'rasp', 'geoip'].map((name) => {
    const runtime = engines[name] || {}
    const source = findSourceForEngine(name)
    const geoSource = name === 'geoip'
    const hasGeoSource = geoSource && !!source
    const trafficSource = name === 'suricata'
    const raspSource = name === 'rasp'
    const currentVersion = geoSource
      ? (hasGeoSource ? firstText(source?.current_version, 'city-db') : '未配置')
      : firstText(source?.current_version, runtime.rule_pack_version, runtime.version, raspSource ? '内置规则' : '')
    const feeds = trafficSource ? trafficSources : []
    const ruleCount = trafficSource ? Number(suricataSemantics.signature_count ?? 0) : geoSource ? (hasGeoSource ? 1 : 0) : Number(counts.value?.[name] || runtime.rule_count || 0)
    const effectiveInstalled = geoSource ? hasGeoSource : !!runtime.installed || ruleCount > 0 || !!source?.current_version
    const effectiveRunning = geoSource ? hasGeoSource : !!runtime.running || (trafficSource && effectiveInstalled)
    return {
      key: name,
      engine: name,
      sourceId: source?.source_id,
      sourceIds: trafficSource ? feeds.map((item) => item.source_id).filter(Boolean) : [source?.source_id].filter(Boolean),
      title: engineLabel(name),
      subtitle: trafficSource ? '' : geoSource ? (hasGeoSource ? '公网 IP 城市级归属库' : '未配置 GeoIP 数据源') : displayRulePath(firstText(runtime.rule_path, source?.vendor, source?.name, raspSource ? '内置应用防护规则' : '本地原生规则源')),
      localPath: trafficSource ? 'traffic-rules/signature-feeds' : geoSource ? (hasGeoSource ? displayRulePath(firstText(source?.path, 'geoip/city-attribution')) : '未配置') : displayRulePath(firstText(runtime.rule_path, source?.path, raspSource ? 'rules/rasp' : '')),
      currentVersion,
      latestVersion: geoSource ? (hasGeoSource ? firstText(source?.latest_version, source?.current_version, currentVersion) : '未配置') : firstText(source?.latest_version, source?.current_version, currentVersion),
      ruleCountLabel: trafficSource ? '规则签名' : '规则数量',
      ruleCount,
      ruleFileCount: trafficSource ? Number(suricataSemantics.rule_file_count ?? 0) : null,
      feeds,
      updatable: raspSource ? false : geoSource ? hasGeoSource : (trafficSource ? feeds.length > 0 : !!source),
      running: effectiveRunning,
      installed: effectiveInstalled,
      statusText: sourceStatusText(name, source, effectiveInstalled, effectiveRunning),
    }
  })
})

function isTrafficSource(source) {
  const text = `${source?.category || ''} ${source?.source_id || ''} ${source?.name || ''} ${source?.vendor || ''}`.toLowerCase()
  return text.includes('dpi') || text.includes('traffic') || text.includes('suricata') || text.includes('snort') || text.includes('stamus') || text.includes('trafficid')
}

function firstText(...values) {
  for (const value of values) {
    const text = String(value ?? '').trim()
    if (text) return text
  }
  return '-'
}

function engineLabel(value) {
  return ({ suricata: '流量威胁规则', wazuh: '运行威胁规则', yara: '文件扫描规则', rasp: '应用防护规则', geoip: 'IP地理归属更新' })[value] || value
}

function sourceStatusText(name, source, installed, running) {
  if (!installed) return '未检测到规则'
  if (sourceMessages[name]) return '已更新'
  if (running) return source?.update_available === true ? '运行中 · 可更新' : '运行中'
  return '规则已加载'
}

function displayRulePath(path) {
  return String(path || '-')
    .replace(/suricata/ig, 'traffic-rules')
    .replace(/wazuh/ig, 'runtime-rules')
    .replace(/yara/ig, 'file-rules')
    .replace(/openrasp/ig, 'app-protection')
    .replace(/rasp/ig, 'app-protection')
}

function shortPath(path) {
  return displayRulePath(path).replace(/^.*?(rules|source)\//, '$1/')
}

function findSourceForEngine(name) {
  const aliases = {
    suricata: ['suricata-et-open', 'et open', 'emerging threats', 'suricata', 'dpi', 'traffic'],
    wazuh: ['wazuh', 'auditd', 'hids', 'runtime'],
    yara: ['yara', 'file'],
    rasp: ['openrasp', 'rasp', 'application'],
    geoip: ['geoip', 'ip geo', '地理归属', 'attribution'],
  }[name] || [name]
  const sourceData = sourceItems.value.map((item) => ({
    item,
    data: `${item.source_id || ''} ${item.name || ''} ${item.vendor || ''} ${item.category || ''}`.toLowerCase(),
  }))
  return sourceData.find((entry) => entry.data.includes(name))?.item
    || sourceData.find((entry) => aliases.slice(0, 3).some((alias) => entry.data.includes(alias)))?.item
    || sourceData.find((entry) => aliases.some((alias) => entry.data.includes(alias)))?.item
}

async function loadAll() {
  loading.value = true
  error.value = ''
  try {
    const [native, status, sourceData] = await Promise.all([
      ruleClient.engineRules({ limit: pageSize.value, offset: (page.value - 1) * pageSize.value, engine: engine.value || undefined, query: query.value || undefined }),
      ruleClient.engineRuntimeStatus(),
      ruleClient.sources(),
    ])
    const normalized = normalizeItems(native)
    nativeRules.value = normalized.items
    total.value = normalized.total
    counts.value = native?.counts || native?.data?.counts || {}
    countSemantics.value = native?.count_semantics || native?.data?.count_semantics || {}
    runtimeStatus.value = status || { engines: {} }
    sourceItems.value = normalizeItems(sourceData).items
    seedDrafts()
  } catch (err) {
    error.value = err?.message || '无法读取四引擎规则'
  } finally {
    loading.value = false
  }
}

function seedDrafts() {
  nativeRules.value.forEach((rule) => {
    const key = nativeRuleKey(rule)
    if (!ruleDrafts[key]) {
      ruleDrafts[key] = {
        enabled: rule.enabled !== false,
        severity: normalizeSeverity(rule.severity),
      }
    }
  })
}

function nativeRuleKey(rule) {
  return [rule.engine, rule.path, rule.line, rule.id].filter((value) => value !== undefined && value !== null && value !== '').join(':')
}

function normalizeSeverity(value) {
  const text = String(value || '').toLowerCase()
  if (severityOptions.some((item) => item.value === text)) return text
  return 'medium'
}

function draftFor(rule) {
  const key = nativeRuleKey(rule)
  if (!ruleDrafts[key]) {
    ruleDrafts[key] = { enabled: rule.enabled !== false, severity: normalizeSeverity(rule.severity) }
  }
  return ruleDrafts[key]
}

function setDraft(rule, payload) {
  Object.assign(draftFor(rule), payload)
  delete ruleMessages[nativeRuleKey(rule)]
}

function isDirty(rule) {
  const draft = draftFor(rule)
  return draft.enabled !== (rule.enabled !== false) || draft.severity !== normalizeSeverity(rule.severity)
}

function severityScore(value) {
  return severityOptions.find((item) => item.value === value)?.score ?? 55
}

async function confirmRule(rule) {
  const key = nativeRuleKey(rule)
  const draft = draftFor(rule)
  savingRules[key] = true
  delete ruleMessages[key]
  try {
    const result = await ruleClient.updateRuleItem(key, { enabled: draft.enabled, score: severityScore(draft.severity) })
    rule.enabled = draft.enabled
    rule.severity = result?.severity || draft.severity
    ruleMessages[key] = result?.hot_reloaded ? '已生效，规则引擎已热加载' : '已保存，等待引擎同步'
  } catch (err) {
    ruleMessages[key] = err?.message || '规则调整失败'
  } finally {
    savingRules[key] = false
  }
}

async function updateSourceRow(item) {
  updatingSource.value = item.key
  delete sourceMessages[item.key]
  error.value = ''
  try {
    const sourceIds = item.sourceIds?.length ? item.sourceIds : item.sourceId ? [item.sourceId] : []
    const results = []
    const failed = []
    if (sourceIds.length) {
      const settled = await Promise.allSettled(sourceIds.map((sourceId) => ruleClient.updateSource(sourceId)))
      settled.forEach((result, index) => {
        if (result.status === 'fulfilled') results.push(result.value)
        else failed.push(`${sourceLabel(sourceIds[index])}：${result.reason?.message || '更新失败'}`)
      })
    } else if (item.key !== 'geoip') {
      results.push(await ruleClient.updateEngineRules())
    } else {
      results.push(await ruleClient.updateEngineRules())
    }
    const ok = results.every((result) => result?.hot_reloaded || result?.updated)
    if (results.length && failed.length) {
      sourceMessages[item.key] = `已更新 ${results.length} 个规则源并热加载；${failed.join('；')}`
    } else if (results.length) {
      sourceMessages[item.key] = ok ? `已更新 ${results.length} 个规则源并热加载` : '已刷新规则源'
    } else if (failed.length) {
      sourceMessages[item.key] = failed.join('；')
    } else {
      sourceMessages[item.key] = '没有可更新的规则源'
    }
    await loadAll()
  } catch (err) {
    sourceMessages[item.key] = err?.message || '规则源更新失败'
  } finally {
    updatingSource.value = ''
  }
}

function sourceLabel(sourceId) {
  return sourceItems.value.find((source) => source.source_id === sourceId)?.name || sourceId
}

function resetAndLoad() {
  page.value = 1
  loadAll()
}

function prevPage() {
  if (page.value > 1) {
    page.value -= 1
    loadAll()
  }
}

function nextPage() {
  if (page.value < totalPages.value) {
    page.value += 1
    loadAll()
  }
}

onMounted(loadAll)
</script>

<style scoped>
.ops-page{height:100%;min-height:0;display:grid;grid-template-rows:auto auto minmax(0,1fr);gap:10px;padding:12px;color:var(--text-primary);box-sizing:border-box}.page-head{display:flex;justify-content:space-between;gap:16px;padding:18px 22px;border-radius:20px;border:1px solid var(--border-light);background:linear-gradient(135deg,rgba(17,31,52,.94),rgba(8,18,32,.78))}.page-head p{margin:0 0 6px;color:var(--primary-light);font-size:11px;font-weight:900;letter-spacing:.16em}.page-head h2{margin:0;font-size:clamp(26px,2.6vw,38px);letter-spacing:-.045em}.page-head span{display:block;max-width:820px;margin-top:6px;color:var(--text-muted)}.head-actions{display:flex;gap:8px;align-self:start}.page-head button,.filters button,.pager button,.source-actions button,.confirm-btn{border:0;border-radius:10px;padding:8px 11px;background:#38bdf8;color:#04111f;font-weight:900}.source-actions button.secondary{background:#1e293b;color:#cbd5e1;border:1px solid rgba(148,163,184,.24)}.feed-list{grid-column:1/-1;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px;padding:0 8px 8px 8px;overflow:hidden}.feed-list span{height:22px;min-width:0;display:flex;align-items:center;padding:0 8px;border:1px solid rgba(56,189,248,.2);border-radius:999px;background:rgba(14,165,233,.08);color:#bae6fd;font-size:10px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}button:disabled,.source-actions button:disabled{opacity:.5;cursor:not-allowed;background:#1e293b;color:#64748b}.surface-card{border:1px solid rgba(148,163,184,.18);background:#0f172a;border-radius:20px;box-shadow:0 18px 52px rgba(0,0,0,.22);overflow:hidden}.state-card{padding:9px 12px;border-radius:13px;background:#0f2f3f;border:1px solid rgba(56,189,248,.28);color:#bae6fd}.error-state{background:#3b1118;border-color:rgba(248,113,113,.34);color:#fecaca}.panel-heading,.panel-title{height:38px;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:0 14px;border-bottom:1px solid var(--border-light);background:rgba(4,12,24,.38)}.panel-heading strong,.panel-title strong{color:var(--text-primary);font-size:13px}.panel-heading span,.panel-title span{color:var(--text-muted);font-size:11px}.source-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;padding:8px}.source-row{display:grid;grid-template-rows:auto 1fr auto;gap:6px;min-width:0;padding:8px;border-radius:14px;background:#111c2f;border:1px solid rgba(148,163,184,.14)}.source-main{display:flex;align-items:flex-start;gap:8px;min-width:0}.source-main b{display:block;font-size:13px;color:#e2e8f0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.source-main small{display:block;margin-top:2px;color:#94a3b8;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.status-dot{width:9px;height:9px;margin-top:4px;border-radius:50%;background:#ef4444;box-shadow:0 0 12px rgba(239,68,68,.5);flex:0 0 auto}.status-dot.ok{background:#22c55e;box-shadow:0 0 14px rgba(34,197,94,.55)}.status-dot.warn{background:#f59e0b}.source-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px 8px}.source-fields>div{display:grid;grid-template-columns:48px minmax(0,1fr);gap:5px;align-items:center;min-width:0}.source-fields span{font-size:10px;color:#64748b;white-space:nowrap}.source-fields strong{min-width:0;color:#cbd5e1;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.address-field input{width:100%;min-width:0;height:26px;border-radius:8px;border:1px solid rgba(148,163,184,.18);background:#0b1220;color:#bfdbfe;padding:0 8px;box-sizing:border-box;font-size:11px}.path-field strong{color:#7dd3fc}.source-actions{display:flex;align-items:center;gap:6px;min-width:0}.source-actions em{margin-right:auto;font-style:normal;font-size:11px;color:#94a3b8;white-space:nowrap}.source-actions em.run{color:#86efac}.source-actions em.warn{color:#fcd34d}.source-actions em.bad{color:#fca5a5}.source-actions button{height:28px;padding:0 9px;border-radius:9px;font-size:11px;white-space:nowrap}.row-message{grid-column:1/-1;margin:0;color:#7dd3fc;font-size:11px}.rules-panel{min-height:0;display:grid;grid-template-rows:auto minmax(0,1fr) auto}.filters{min-height:44px;height:auto;align-items:center;padding:8px 14px;gap:12px}.panel-copy{display:grid;gap:2px;min-width:180px}.filter-controls{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex:1;min-width:0}.filters label{display:flex;align-items:center;gap:6px;color:#94a3b8;font-size:12px;white-space:nowrap}.filters select,.filters input{height:30px;border-radius:9px;border:1px solid rgba(148,163,184,.18);background:#0b1220;color:#dbeafe;padding:0 9px}.filters input{width:min(260px,28vw);min-width:180px}.table-wrap{overflow:auto}table{width:100%;min-width:1080px;border-collapse:collapse}th,td{padding:10px 12px;border-bottom:1px solid rgba(148,163,184,.12);text-align:left;vertical-align:top}th{color:#94a3b8;font-size:12px;background:#0b1220;position:sticky;top:0;z-index:1}td b{display:block;color:#e2e8f0;font-size:13px}td small{display:block;margin-top:3px;color:#64748b;font-size:11px}.empty-cell{text-align:center;color:#94a3b8;padding:30px}.engine-chip{display:inline-flex;padding:4px 8px;border-radius:999px;background:#10243a;color:#7dd3fc;font-size:12px}.enable-pill{display:inline-flex;align-items:center;gap:6px;padding:5px 8px;border-radius:999px;background:#1e293b;color:#94a3b8}.enable-pill.active{background:rgba(34,197,94,.14);color:#86efac}.enable-pill input{accent-color:#22c55e}.severity-pills{display:flex;flex-wrap:wrap;gap:5px}.severity-pill{height:25px;border-radius:999px;border:1px solid rgba(148,163,184,.18);background:#111827;color:#94a3b8;font-size:11px}.severity-pill.active.info{background:#0e7490;color:#ecfeff}.severity-pill.active.low{background:#166534;color:#dcfce7}.severity-pill.active.medium{background:#854d0e;color:#fef3c7}.severity-pill.active.high{background:#9a3412;color:#ffedd5}.severity-pill.active.critical{background:#991b1b;color:#fee2e2}.confirm-btn{height:28px}.pager{height:42px;display:flex;align-items:center;justify-content:flex-end;gap:8px;padding:0 14px;color:#94a3b8;border-top:1px solid rgba(148,163,184,.14);background:rgba(4,12,24,.22)}.pager span{height:28px;display:inline-flex;align-items:center;padding:0 10px;border-radius:999px;background:#0b1220;border:1px solid rgba(148,163,184,.18);font-size:12px;font-weight:800}.pager button{height:28px;padding:0 10px;border-radius:9px;font-size:11px}@media(max-width:1280px){.source-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:760px){.source-grid,.metric-grid{grid-template-columns:1fr}.page-head{flex-direction:column}.panel-title{height:auto;flex-wrap:wrap;padding:10px}.filter-controls{width:100%;justify-content:flex-start;flex-wrap:wrap}.filters input{width:100%;min-width:0}}

.table-wrap table{table-layout:fixed}.rule-col{width:19%}.engine-col{width:11%}.path-col{width:20%}.status-col{width:9%}.severity-col{width:29%}.action-col{width:12%}.rule-cell,.path-cell{min-width:0}.rule-cell b,.path-cell b{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.status-cell,.engine-cell,.action-cell{vertical-align:middle}.severity-cell{vertical-align:middle;padding-top:8px;padding-bottom:8px}.severity-pills{display:grid!important;grid-template-columns:repeat(5,minmax(38px,1fr));gap:6px;align-items:center;min-width:230px}.severity-pill{height:28px!important;min-width:0;padding:0 8px!important;border-radius:8px!important;border:1px solid rgba(148,163,184,.2)!important;background:#0b1220!important;color:#94a3b8!important;font-size:12px!important;font-weight:800!important;line-height:28px!important;text-align:center;box-sizing:border-box}.severity-pill.active.info{background:#0e7490!important;color:#ecfeff!important;border-color:#22d3ee!important}.severity-pill.active.low{background:#166534!important;color:#dcfce7!important;border-color:#22c55e!important}.severity-pill.active.medium{background:#854d0e!important;color:#fef3c7!important;border-color:#f59e0b!important}.severity-pill.active.high{background:#9a3412!important;color:#ffedd5!important;border-color:#fb923c!important}.severity-pill.active.critical{background:#991b1b!important;color:#fee2e2!important;border-color:#f87171!important}.action-cell{display:flex;flex-direction:column;align-items:flex-start;gap:5px}.action-cell .confirm-btn{height:30px;min-width:76px;padding:0 12px;border-radius:9px}.action-cell .row-message{margin:0;line-height:1.2}.enable-pill{white-space:nowrap}.engine-chip{white-space:nowrap}@media(max-width:1280px){table{min-width:1180px}.severity-col{width:320px}.severity-pills{min-width:280px}}
.ops-page{color:#243149}.page-head{padding:10px 16px;border-color:#dce4ef;border-radius:6px;background:#fff;box-shadow:0 3px 12px rgba(44,66,96,.07)}.page-head p{color:#2782e8;letter-spacing:0}.page-head h2{color:#243149;font-size:22px;letter-spacing:0}.surface-card{border-color:#dce4ef;background:#fff;border-radius:6px;box-shadow:0 3px 12px rgba(44,66,96,.07)}.panel-heading,.panel-title{border-color:#e3e9f1;background:#f6f8fb}.panel-heading strong,.panel-title strong{color:#263247}.panel-heading span,.panel-title span{color:#758195}.source-row{border-color:#dfe6ef;border-radius:5px;background:#fff}.source-main b{color:#263247}.source-main small{color:#7b8798}.source-fields span{color:#758195}.source-fields strong{color:#334155}.address-field input,.filters select,.filters input{border-color:#d5deea;background:#fff;color:#263247}.feed-list span{border-color:#c4dcf5;border-radius:4px;background:#edf6ff;color:#1769d2}.source-actions em{color:#6f7c91}.source-actions em.run{color:#16824f}.source-actions em.warn{color:#a55d08}.source-actions em.bad{color:#b42318}.source-actions button,.filters button,.pager button,.confirm-btn{border-radius:4px;background:#1769d2;color:#fff}.state-card{border-color:#a9cdf3;background:#edf6ff;color:#1769d2}.table-wrap table th{background:#eef3f8;color:#53627a}.table-wrap table td{color:#304058}.table-wrap table th,.table-wrap table td{border-color:#e6ebf2;text-align:center;vertical-align:middle}.table-wrap td b{color:#263247}.table-wrap td small{color:#758195}.engine-chip{border-radius:4px;background:#e8f3ff;color:#1769d2}.enable-pill{border-radius:4px;background:#f0f3f7;color:#66758a}.enable-pill.active{background:#e9f7ef;color:#178653}.severity-pill{border-radius:4px!important;border-color:#d7e0eb!important;background:#fff!important;color:#526078!important}.pager{border-color:#e3e9f1;background:#f7f9fc;color:#68758a}.pager span{border-color:#d7e0eb;border-radius:4px;background:#fff}.action-cell{align-items:center}
/* Five engine modules: keep the source overview on one compact row on wide screens. */
.source-grid{grid-template-columns:repeat(5,minmax(0,1fr));gap:6px;padding:8px}
.source-row{padding:7px 8px;gap:5px;border-top:2px solid #dce4ef}
.source-row.engine-suricata{border-top-color:#2f80ed}
.source-row.engine-wazuh{border-top-color:#7c5cff}
.source-row.engine-yara{border-top-color:#e0a11b}
.source-row.engine-rasp{border-top-color:#16a36a}
.source-row.engine-geoip{border-top-color:#0f9bb5}
.source-main{gap:6px}
.source-main b{font-size:12px}
.source-main small{font-size:9px}
.source-fields{gap:3px 6px}
.source-fields>div{grid-template-columns:42px minmax(0,1fr);gap:4px}
.source-fields span{font-size:9px}
.source-fields strong{font-size:10px}
.source-fields .path-field strong{font-size:9.5px}
.feed-list{grid-template-columns:repeat(2,minmax(0,1fr));gap:4px;padding:0 4px 5px}
.feed-list span{height:19px;padding:0 6px;font-size:9px}
.source-actions em{font-size:9.5px}
.source-actions button{height:24px;padding:0 7px;font-size:10px}
@media(max-width:1500px){.source-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:1000px){.source-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:760px){.source-grid{grid-template-columns:1fr}}
</style>
