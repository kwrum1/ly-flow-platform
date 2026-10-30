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
        <div class="source-heading-copy">
          <strong>规则源同步</strong>
          <small>按后端实装引擎分组，只展示有上游的可更新规则源</small>
        </div>
        <div class="source-head-meta">
          <span v-if="runtimeStatusWarning" class="source-warning">引擎运行时状态暂不可用，规则与来源仍按本地清单展示</span>
          <span v-if="sourceLoading">正在读取实装引擎…</span>
          <span v-else>{{ engineRows.length }} 个实装引擎 · {{ upstreamLoading ? '读取上游…' : `${upstreamRows.length} 个上游规则源 / ${upstreamUpdateCount} 个可更新` }} · {{ loading ? '读取中' : `${formatCount(totalNativeCount)} 条规则清单` }}</span>
        </div>
      </div>

      <div v-if="sourceLoading" class="source-empty">
        <div><strong>正在读取实装引擎</strong>等待后端引擎健康与规则平台来源返回。</div>
      </div>
      <div v-else-if="!engineRows.length" class="source-empty">
        <div><strong>没有读取到实装引擎</strong>等待引擎心跳或运行时状态上报。</div>
      </div>
      <div v-else class="engine-source-grid">
        <div
          v-for="engine in engineRows"
          :key="engine.key"
          :class="['engine-source-card', `engine-${engine.key}`]"
        >
          <div class="engine-source-head">
            <span class="engine-monogram" :class="engine.tone">{{ engine.short }}</span>
            <div>
              <b>{{ engine.label }}</b>
              <small>{{ engine.instanceLabel }}</small>
            </div>
            <span class="sx-badge" :class="engine.tone">{{ engine.statusText }}</span>
          </div>
          <div class="engine-source-facts">
            <div><span>生效规则</span><b>{{ formatCount(engine.ruleCount) }}</b></div>
            <div><span>上游</span><b>{{ upstreamLoading ? '读取中' : engine.sourceCount }}</b></div>
            <div><span>可更新</span><b>{{ upstreamLoading ? '读取中' : engine.updatableCount }}</b></div>
            <div><span>规则包</span><b :title="engine.rulePack">{{ engine.rulePack }}</b></div>
          </div>
          <p class="engine-source-note">{{ engine.note }}</p>
        </div>
      </div>

      <div class="upstream-section">
        <div class="upstream-heading">
          <div>
            <strong>可更新上游</strong>
            <span>内置、编译产物和无法自动更新的规则不会出现在这里</span>
          </div>
          <span>按引擎与上游版本同步</span>
        </div>

        <div v-if="upstreamLoading" class="source-empty">
          <div><strong>正在读取可更新上游</strong>规则平台来源和版本返回后展示。</div>
        </div>
        <div v-else-if="!upstreamRows.length" class="source-empty">
          <div><strong>没有可更新的上游规则源</strong>当前实装引擎没有配置可自动同步的上游。</div>
        </div>
        <div v-else class="upstream-table-wrap">
          <table class="upstream-table">
            <thead>
              <tr><th>引擎</th><th>上游规则源</th><th>更新地址</th><th>版本</th><th>最近同步</th><th>更新</th></tr>
            </thead>
            <tbody>
              <tr v-for="source in upstreamRows" :key="source.key">
                <td><span class="engine-chip">{{ source.engineLabel }}</span></td>
                <td>
                  <b>{{ source.name }}</b>
                  <small>{{ source.license || source.vendor || source.sourceId }}</small>
                </td>
                <td class="upstream-address">
                  <a v-if="source.url" :href="source.url" target="_blank" rel="noopener noreferrer" :title="source.url">{{ shortUrl(source.url) }}</a>
                  <span v-else>未配置上游地址</span>
                </td>
                <td>
                  <b>{{ source.currentVersion }}</b>
                  <small v-if="source.latestVersion && source.latestVersion !== '未上报' && source.latestVersion !== source.currentVersion">上游 {{ source.latestVersion }}</small>
                  <small v-else-if="source.currentVersion === '未上报'">暂无上游版本</small>
                  <small v-else>上游版本已同步</small>
                </td>
                <td>
                  <b>{{ source.lastSyncText }}</b>
                  <small>{{ source.syncStatusText }}</small>
                </td>
                <td class="upstream-actions">
                  <span :class="['update-state', source.updateStateTone]">{{ source.updateStateText }}</span>
                  <button v-if="source.canUpdate" class="confirm-btn" type="button" :disabled="updatingSource === source.key" @click="updateUpstream(source)">
                    {{ updatingSource === source.key ? '同步中…' : source.updateAvailable ? '更新' : '同步' }}
                  </button>
                  <small v-if="sourceMessages[source.key]" class="row-message">{{ sourceMessages[source.key] }}</small>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="geo-data-note">
          <b>IP 地理归属库</b>
          <span>用于全球态势地图的 IP → 城市定位，属于基础地理数据，不是引擎规则源；不纳入上面的规则同步列表。</span>
          <span v-if="geoSourceInfo" class="geo-source-ref">后端登记：{{ geoSourceInfo.name }} · <a :href="geoSourceInfo.url" target="_blank" rel="noopener noreferrer">{{ shortUrl(geoSourceInfo.url) }}</a></span>
          <span v-else class="geo-source-ref">后端未登记地理库更新源。</span>
        </div>
      </div>
    </article>

    <article class="surface-card whitelist-card">
      <div class="panel-heading">
        <div class="source-heading-copy">
          <strong>告警白名单</strong>
          <small>按规则、来源 IP 或资产临时抑制告警；到期自动恢复，避免永久盲区</small>
        </div>
        <span>{{ whitelistLoading ? '读取中…' : `${whitelistItems.length} 条生效中` }}</span>
      </div>
      <div class="whitelist-body">
        <form class="whitelist-form" @submit.prevent="addWhitelist">
          <label><span>范围</span>
            <select v-model="whitelistForm.scope">
              <option value="rule">规则</option>
              <option value="source">来源 IP</option>
              <option value="victim">资产 / 实体</option>
            </select>
          </label>
          <label class="whitelist-value"><span>匹配值</span>
            <input v-model.trim="whitelistForm.value" placeholder="规则 ID / 名称、来源 IP、Agent 或主机名" />
          </label>
          <label><span>有效期</span>
            <select v-model.number="whitelistForm.days">
              <option :value="7">7 天</option>
              <option :value="30">30 天</option>
              <option :value="90">90 天</option>
            </select>
          </label>
          <label class="whitelist-reason"><span>原因</span>
            <input v-model.trim="whitelistForm.reason" placeholder="例如：业务授权扫描 / 已知误报" />
          </label>
          <button class="confirm-btn" type="submit" :disabled="whitelistSaving || !whitelistForm.value || !whitelistForm.reason">
            {{ whitelistSaving ? '保存中…' : '加入白名单' }}
          </button>
        </form>
        <p v-if="whitelistMessage" class="row-message">{{ whitelistMessage }}</p>
        <div v-if="whitelistItems.length" class="whitelist-list">
          <div v-for="entry in whitelistItems" :key="entry.id" class="whitelist-item">
            <span class="sx-badge info">{{ whitelistScopeLabel(entry.scope) }}</span>
            <b>{{ entry.value }}</b>
            <small>{{ entry.reason || '未填写原因' }} · {{ formatWhitelistTime(entry.expires_at) }} 到期</small>
            <button type="button" :disabled="whitelistRemoving === entry.id" @click="removeWhitelist(entry)">
              {{ whitelistRemoving === entry.id ? '移除中…' : '移除' }}
            </button>
          </div>
        </div>
        <div v-else-if="!whitelistLoading" class="whitelist-empty">当前没有告警白名单。</div>
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
              <option value="lyprobe">LyFlow 探针</option>
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
import { assetAgentClient, responseClient, ruleClient } from '../api/domain'
import { normalizeItems, pickText } from '../shared/api-normalize'

const loading = ref(false)
const sourceLoading = ref(true)
const upstreamLoading = ref(true)
const updatingSource = ref('')
const error = ref('')
const nativeRules = ref([])
const runtimeStatus = ref({ engines: {} })
const engineHealthItems = ref([])
const platformSourceItems = ref([])
const platformVersionItems = ref([])
const legacySourceItems = ref([])
const activeBundle = ref({})
const counts = ref({})
const runtimeStatusWarning = ref(false)
const total = ref(0)
const page = ref(1)
const pageSize = ref(24)
const engine = ref('')
const query = ref('')
const ruleDrafts = reactive({})
const savingRules = reactive({})
const ruleMessages = reactive({})
const sourceMessages = reactive({})
const whitelistPolicy = ref({ suppressions: [] })
const whitelistLoading = ref(false)
const whitelistSaving = ref(false)
const whitelistRemoving = ref('')
const whitelistMessage = ref('')
const whitelistForm = reactive({ scope: 'rule', value: '', days: 30, reason: '' })

const severityOptions = [
  { value: 'info', label: '信息', score: 20 },
  { value: 'low', label: '低', score: 35 },
  { value: 'medium', label: '中', score: 55 },
  { value: 'high', label: '高', score: 75 },
  { value: 'critical', label: '严重', score: 95 },
]

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))
const whitelistItems = computed(() => Array.isArray(whitelistPolicy.value?.suppressions) ? whitelistPolicy.value.suppressions : [])
const totalNativeCount = computed(() => total.value)
const engineDefinitions = {
  'security-engine': { label: 'LyFlow 安全引擎', short: 'LY', order: 0 },
  suricata: { label: 'Suricata', short: 'SU', order: 1 },
  wazuh: { label: 'Wazuh', short: 'WA', order: 2 },
  yara: { label: 'YARA', short: 'YA', order: 3 },
  rasp: { label: 'OpenRASP', short: 'RA', order: 4 },
  lyprobe: { label: 'LyFlow 探针规则', short: 'LP', order: 5 },
}
const sourceAliases = {
  'suricata-et-open': 'et-open-connector',
  'falco-supported-subset': 'falco-connector',
}
const internalSourceIds = new Set(['lyflow-default', 'lyflow-compiled-local', 'custom-rasp-rules', 'openrasp-derived', 'restricted-commercial'])

const installedEngineKeys = computed(() => {
  const keys = new Set()
  for (const item of engineHealthItems.value) {
    if (item?.installed !== false && item?.engine) keys.add(item.engine)
  }
  if (runtimeStatus.value?.engines?.['security-engine']) keys.add('security-engine')
  if (runtimeStatus.value?.engines?.lyprobe) keys.add('lyprobe')
  for (const [key, count] of Object.entries(counts.value || {})) {
    if (Number(count || 0) > 0) keys.add(key)
  }
  return keys
})

const allUpstreamSources = computed(() => {
  const versions = new Map()
  for (const version of platformVersionItems.value) {
    const id = String(version?.source_id || '')
    if (!id) continue
    const previous = versions.get(id)
    if (!previous || String(version.synced_at || '') > String(previous.synced_at || '')) versions.set(id, version)
  }
  const platformByID = new Map()
  for (const source of platformSourceItems.value) {
    const id = String(source?.source_id || source?.id || '')
    if (id) platformByID.set(id, source)
  }
  const legacyByID = new Map()
  for (const source of legacySourceItems.value) {
    const id = String(source?.source_id || source?.id || '')
    if (id) legacyByID.set(id, source)
  }
  const rows = new Map()

  for (const platform of platformSourceItems.value) {
    const id = String(platform?.source_id || platform?.id || '')
    if (!id || internalSourceIds.has(id) || id === 'ip-geo-attribution') continue
    if (platform.updatable !== true || platform.connector !== true || platform.restricted || !platform.url) continue
    const canonicalID = sourceAliases[id] || id
    const legacy = legacyByID.get(id)
      || (id === 'et-open-connector' ? legacyByID.get('suricata-et-open') : null)
      || (id === 'falco-connector' ? legacyByID.get('falco-supported-subset') : null)
      || null
    rows.set(canonicalID, makeUpstreamSource({ platform, legacy, version: versions.get(id), canonicalID }))
  }

  for (const legacy of legacySourceItems.value) {
    const id = String(legacy?.source_id || legacy?.id || '')
    if (!id || internalSourceIds.has(id) || !legacy?.source_url) continue
    const canonicalID = sourceAliases[id] || id
    if (rows.has(canonicalID)) continue
    rows.set(canonicalID, makeUpstreamSource({ legacy, version: versions.get(id), canonicalID }))
  }

  return [...rows.values()].sort((a, b) => a.order - b.order || a.name.localeCompare(b.name, 'zh-CN'))
})

const upstreamRows = computed(() => allUpstreamSources.value.filter((source) => installedEngineKeys.value.has(source.engine)))
const upstreamUpdateCount = computed(() => upstreamRows.value.filter((source) => source.updateAvailable).length)
const geoSourceInfo = computed(() => platformSourceItems.value.find((source) => (source?.source_id || source?.id) === 'ip-geo-attribution') || null)

const engineRows = computed(() => {
  const rows = []
  const runtime = runtimeStatus.value?.engines || {}
  const security = runtime['security-engine']
  if (security) {
    const ruleCounts = security.rule_counts || {}
    const ruleCount = Object.values(ruleCounts).reduce((sum, value) => sum + Number(value || 0), 0)
    const healthy = security.control_health?.status === 'healthy' || security.status === 'running'
    rows.push(makeEngineRow({
      key: 'security-engine',
      running: healthy,
      ruleCount,
      rulePack: security.bundle_version || activeBundle.value?.bundle_id || activeBundle.value?.version || '-',
      instances: 1,
      note: `统一编译 Bundle · 共享 ${upstreamLoading.value ? '读取中' : formatCount(allUpstreamSources.value.length)} 个上游 · 流量 ${formatCount(ruleCounts.traffic)} / 运行 ${formatCount(ruleCounts.runtime)} / RASP ${formatCount(ruleCounts.rasp)}`,
      sourceCount: allUpstreamSources.value.length,
      updatableCount: allUpstreamSources.value.filter((source) => source.updateAvailable).length,
    }))
  }

  for (const key of installedEngineKeys.value) {
    if (key === 'security-engine') continue
    const healthAll = engineHealthItems.value.filter((item) => item?.engine === key)
    const healthRows = healthAll.filter((item) => item?.installed !== false)
    const runtimeInfo = runtime[key] || {}
    const runningRows = healthRows.filter((item) => isEngineRunning(item))
    const runtimeRunning = Boolean(runtimeInfo.running) || (key === 'suricata' && Number(runtimeInfo.signature_count || 0) > 0)
    const running = healthRows.length ? runningRows.length === healthRows.length : runtimeRunning
    const unavailable = healthAll.length > 0 && healthRows.length === 0 && !runtimeRunning
    const ruleCount = Number(counts.value?.[key] ?? runtimeInfo.rule_count ?? runtimeInfo.signature_count ?? 0)
    const rulePack = unavailable ? '未安装' : firstText(healthRows[0]?.rule_pack_version, runtimeInfo.rule_pack_version, runtimeInfo.bundle_version, '未上报')
    const sourceCount = allUpstreamSources.value.filter((source) => source.engine === key).length
    const updatableCount = allUpstreamSources.value.filter((source) => source.engine === key && source.updateAvailable).length
    const isProbe = key === 'lyprobe'
    rows.push(makeEngineRow({
      key,
      running,
      unavailable,
      ruleCount,
      rulePack,
      instances: isProbe && running ? 1 : healthRows.length,
      note: isProbe
        ? 'ET Open 子集 · rulecompiler 生成 · NetFlow v9 证据链'
        : healthRows.length
          ? `${healthRows[0]?.hostname || healthRows[0]?.agent_id || '本机'} · ${firstText(healthRows[0]?.version, '版本未上报')}`
          : unavailable
            ? 'Agent 未报告可运行的原生引擎，规则仍保留在规则清单中'
            : '规则包已加载，等待引擎心跳',
      sourceCount: isProbe ? 1 : sourceCount,
      updatableCount: isProbe ? 0 : updatableCount,
    }))
  }
  return rows.sort((a, b) => a.order - b.order)
})

function makeEngineRow({ key, running, unavailable = false, ruleCount, rulePack, instances, note, sourceCount, updatableCount }) {
  const definition = engineDefinitions[key] || { label: key, short: String(key).slice(0, 2).toUpperCase(), order: 99 }
  return {
    key,
    label: definition.label,
    short: definition.short,
    order: definition.order,
    tone: unavailable ? 'muted' : running ? 'low' : (instances || ruleCount > 0) ? 'medium' : 'muted',
    statusText: unavailable ? '未安装' : running ? '运行中' : (instances || ruleCount > 0) ? '规则已加载' : '无心跳',
    instanceLabel: unavailable ? '引擎未安装' : instances ? `${instances} 个实例` : (ruleCount > 0 ? '规则已加载' : '无实例'),
    ruleCount,
    rulePack,
    sourceCount,
    updatableCount,
    note,
  }
}

function makeUpstreamSource({ platform, legacy, version, canonicalID }) {
  const sourceID = String(platform?.source_id || legacy?.source_id || canonicalID)
  const raw = platform || legacy || {}
  const engine = engineForSource(raw)
  const currentVersion = firstText(version?.version, legacy?.current_version, '未上报')
  const latestVersion = firstText(version?.version, legacy?.latest_version, '未上报')
  const currentKnown = currentVersion !== '未上报' && currentVersion !== '未同步' && currentVersion !== '未记录' && currentVersion !== '已安装'
  const latestKnown = latestVersion !== '未上报'
  const updateAvailable = (currentKnown && latestKnown && currentVersion !== latestVersion) || (!version && legacy?.update_available === true)
  return {
    key: canonicalID,
    sourceId: sourceID,
    kind: platform ? 'platform' : 'legacy',
    engine,
    engineLabel: engineDefinitions[engine]?.label || engine,
    order: engineDefinitions[engine]?.order ?? 99,
    name: platform?.name || legacy?.name || sourceID,
    license: platform?.license || legacy?.license || '',
    vendor: legacy?.vendor || platform?.origin || '',
    url: platform?.url || legacy?.source_url || '',
    currentVersion,
    latestVersion,
    lastSync: version?.synced_at || '',
    lastSyncText: version?.synced_at ? formatSourceTime(version.synced_at) : '未同步',
    syncStatusText: version ? '规则平台已同步' : '未同步',
    updateAvailable,
    updateStateText: updateAvailable ? '有新版本' : (currentKnown && latestKnown ? '已是最新' : '未上报'),
    updateStateTone: updateAvailable ? 'available' : (currentKnown && latestKnown ? 'synced' : 'unknown'),
    canUpdate: updateAvailable || !currentKnown || !latestKnown,
  }
}

function engineForSource(source) {
  const category = String(source?.category || '').toLowerCase()
  const text = `${source?.source_id || ''} ${source?.name || ''} ${source?.vendor || ''}`.toLowerCase()
  if (text.includes('yara')) return 'yara'
  if (text.includes('lyprobe') || text.includes('ly_probe')) return 'lyprobe'
  if (text.includes('openrasp') || text.includes('rasp') || text.includes('coreruleset') || text.includes('owasp')) return 'rasp'
  if (category === 'traffic') return 'suricata'
  if (category === 'rasp') return 'rasp'
  if (category === 'runtime' || category === 'log_audit' || category === 'hids') return 'wazuh'
  if (text.includes('wazuh') || text.includes('auditd') || text.includes('falco') || text.includes('sigma') || text.includes('elastic')) return 'wazuh'
  return 'suricata'
}

function isEngineRunning(item) {
  return Boolean(item?.running) && String(item?.agent_status || '').toLowerCase() !== 'offline'
}

function formatCount(value) {
  return Number(value || 0).toLocaleString('zh-CN')
}

function formatSourceTime(value) {
  if (!value) return '未记录'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false })
}

function whitelistScopeLabel(scope) {
  return ({ rule: '规则', source: '来源 IP', victim: '资产 / 实体', agent: '资产 / 实体' })[scope] || scope || '-'
}

function formatWhitelistTime(value) {
  return value ? formatSourceTime(value) : '未设置'
}

async function loadWhitelist() {
  whitelistLoading.value = true
  whitelistMessage.value = ''
  try {
    whitelistPolicy.value = unwrap(await responseClient.policy())
  } catch (err) {
    whitelistMessage.value = err?.message || '白名单读取失败。'
  } finally {
    whitelistLoading.value = false
  }
}

async function addWhitelist() {
  if (!whitelistForm.value.trim() || !whitelistForm.reason.trim()) return
  whitelistSaving.value = true
  whitelistMessage.value = ''
  try {
    await responseClient.suppress({
      suppress_scope: whitelistForm.scope,
      suppress_value: whitelistForm.value.trim(),
      suppress_days: whitelistForm.days,
      reason: whitelistForm.reason.trim(),
    })
    whitelistForm.value = ''
    whitelistForm.reason = ''
    whitelistMessage.value = '已加入白名单，到期后自动恢复检测。'
    await loadWhitelist()
  } catch (err) {
    whitelistMessage.value = err?.message || '白名单保存失败。'
  } finally {
    whitelistSaving.value = false
  }
}

async function removeWhitelist(entry) {
  whitelistRemoving.value = entry.id
  whitelistMessage.value = ''
  try {
    const policy = unwrap(await responseClient.policy())
    const suppressions = (policy.suppressions || []).filter((item) => item.id !== entry.id)
    await responseClient.updatePolicy({ ...policy, suppressions })
    whitelistMessage.value = '白名单已移除，该范围立即恢复检测。'
    await loadWhitelist()
  } catch (err) {
    whitelistMessage.value = err?.message || '白名单移除失败。'
  } finally {
    whitelistRemoving.value = ''
  }
}

function shortUrl(value) {
  const text = String(value || '')
  if (!text) return '未配置'
  return text.replace(/^https?:\/\//, '').replace(/\/$/, '')
}


function firstText(...values) {
  for (const value of values) {
    const text = String(value ?? '').trim()
    if (text) return text
  }
  return '-'
}

function unwrap(response) {
  return response?.data?.data ?? response?.data ?? response ?? {}
}

function engineLabel(value) {
  return engineDefinitions[value]?.label || ({ suricata: 'Suricata', wazuh: 'Wazuh', yara: 'YARA', rasp: 'OpenRASP' })[value] || value
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

async function loadAll() {
  loading.value = true
  error.value = ''
  try {
    const native = await ruleClient.engineRules({ limit: pageSize.value, offset: (page.value - 1) * pageSize.value, engine: engine.value || undefined, query: query.value || undefined })
    const normalized = normalizeItems(native)
    nativeRules.value = normalized.items
    total.value = normalized.total
    counts.value = native?.counts || native?.data?.counts || {}
    seedDrafts()
  } catch (err) {
    nativeRules.value = []
    total.value = 0
    counts.value = {}
    error.value = err?.message || '无法读取原生引擎规则'
  } finally {
    loading.value = false
  }
}

async function loadSourceData() {
  sourceLoading.value = true
  upstreamLoading.value = true
  runtimeStatusWarning.value = false
  try {
    const [statusResult, healthResult] = await Promise.allSettled([
      withTimeout(ruleClient.engineRuntimeStatus(), 8000),
      withTimeout(assetAgentClient.engineHealth(), 8000),
    ])
    if (statusResult.status === 'fulfilled') {
      runtimeStatus.value = unwrap(statusResult.value) || { engines: {} }
    } else {
      runtimeStatus.value = { engines: {} }
      runtimeStatusWarning.value = true
    }
    if (healthResult.status === 'fulfilled') engineHealthItems.value = normalizeItems(healthResult.value).items
    // Engine cards only need runtime status and health. Do not keep them in a
    // loading state while the slower rule-source catalog is fetched.
    sourceLoading.value = false

    const [legacyResult, platformResult, versionResult, bundleResult] = await Promise.allSettled([
      withTimeout(ruleClient.sources(), 12000),
      withTimeout(ruleClient.platformSources(), 12000),
      withTimeout(ruleClient.platformVersions(), 12000),
      withTimeout(ruleClient.platformActiveBundle(), 12000),
    ])
    if (legacyResult.status === 'fulfilled') legacySourceItems.value = normalizeItems(legacyResult.value).items
    if (platformResult.status === 'fulfilled') platformSourceItems.value = normalizeItems(platformResult.value).items
    if (versionResult.status === 'fulfilled') platformVersionItems.value = normalizeItems(versionResult.value).items
    activeBundle.value = bundleResult.status === 'fulfilled' ? unwrap(bundleResult.value) : {}
  } finally {
    sourceLoading.value = false
    upstreamLoading.value = false
  }
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('source request timeout')), ms)),
  ])
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

async function updateUpstream(source) {
  updatingSource.value = source.key
  delete sourceMessages[source.key]
  error.value = ''
  try {
    if (source.kind === 'platform') {
      const result = await ruleClient.platformSync({
        source_id: source.sourceId,
        version: `sync-${new Date().toISOString().replace(/[-:.]/g, '')}`,
      })
      const info = unwrap(result)
      const converted = info.converted_count ?? info.rule_count ?? 0
      const inserted = info.inserted_count ?? 0
      await ruleClient.platformActivateBundle()
      sourceMessages[source.key] = `已从上游同步 ${formatCount(converted)} 条规则${inserted > 0 ? ` · 新增 ${formatCount(inserted)} 条` : ''}，已重新编译生效`
    } else {
      const result = unwrap(await ruleClient.updateSource(source.sourceId))
      sourceMessages[source.key] = result?.hot_reloaded ? '已更新并热加载' : '已同步，等待引擎加载'
    }
    await Promise.all([loadAll(), loadSourceData()])
  } catch (err) {
    sourceMessages[source.key] = err?.message || '上游规则更新失败'
  } finally {
    updatingSource.value = ''
  }
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

onMounted(() => {
  loadAll()
  loadSourceData()
  loadWhitelist()
})
</script>

<style scoped>
.ops-page { display: grid; gap: 14px; min-width: 0; }
.page-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; padding-bottom: 14px; border-bottom: 1px solid var(--lyf-line); background-image: linear-gradient(90deg, var(--lyf-accent-line), transparent 46%); background-repeat: no-repeat; background-position: left bottom; background-size: 100% 1px; }
.page-head p { margin: 0 0 5px; color: var(--lyf-accent); font-family: var(--lyf-font-data); font-size: 10px; font-weight: 600; letter-spacing: 0.18em; }
.page-head h2 { margin: 0; color: var(--lyf-ink); font-size: clamp(21px, 2vw, 27px); font-weight: 650; letter-spacing: -0.02em; }

.surface-card { border: 1px solid var(--lyf-line); border-radius: var(--lyf-radius); background: linear-gradient(180deg, rgb(34 211 238 / 4%), transparent 34%), var(--lyf-surface); overflow: hidden; }

.panel-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 12px 16px; border-bottom: 1px solid var(--lyf-line); background: var(--lyf-surface-2); }
.panel-title, .source-heading-copy strong { margin: 0; color: var(--lyf-ink); font-size: 13px; font-weight: 650; }
.panel-copy, .source-heading-copy small { display: block; margin-top: 2px; color: var(--lyf-ink-3); font-size: 11px; }
.source-head-meta { display: flex; flex-wrap: wrap; gap: 10px; color: var(--lyf-ink-3); font-family: var(--lyf-font-data); font-size: 10.5px; text-align: right; }
.source-warning { color: var(--lyf-medium); }

.engine-source-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; padding: 14px 16px; }
.engine-source-card { position: relative; border: 1px solid var(--lyf-line); border-radius: var(--lyf-radius-sm); background: var(--lyf-surface-2); padding: 12px; overflow: hidden; }
.engine-source-card::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 2px; background: var(--lyf-accent); opacity: 0.6; }
.engine-source-head { display: flex; align-items: center; gap: 9px; }
.engine-source-head > div { min-width: 0; flex: 1; }
.engine-source-head b { display: block; color: var(--lyf-ink); font-size: 12.5px; font-weight: 600; }
.engine-source-head small { display: block; color: var(--lyf-ink-3); font-size: 10px; }
.engine-monogram { display: grid; width: 28px; height: 28px; flex: 0 0 28px; place-items: center; border: 1px solid var(--lyf-accent-line); border-radius: var(--lyf-radius-sm); color: var(--lyf-accent); font-family: var(--lyf-font-data); font-size: 10px; font-weight: 700; }
.engine-source-facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 12px; margin-top: 12px; }
.engine-source-facts span { display: block; color: var(--lyf-ink-3); font-size: 10px; }
.engine-source-facts b { display: block; overflow: hidden; color: var(--lyf-ink); font-family: var(--lyf-font-data); font-size: 13px; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
.engine-source-note { margin: 10px 0 0; padding-top: 9px; border-top: 1px solid var(--lyf-line); color: var(--lyf-ink-3); font-size: 10px; }

.upstream-section { border-top: 1px solid var(--lyf-line); }
.upstream-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 11px 16px; background: var(--lyf-surface-2); }
.upstream-heading strong { color: var(--lyf-ink); font-size: 12.5px; font-weight: 600; }
.upstream-heading span { display: block; color: var(--lyf-ink-3); font-size: 10.5px; }
.upstream-table-wrap { overflow: auto; }
.upstream-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.upstream-table th { height: 36px; padding: 0 12px; border-bottom: 1px solid var(--lyf-line-2); background: var(--lyf-surface-2); color: var(--lyf-ink-3); font-family: var(--lyf-font-data); font-size: 9.5px; font-weight: 600; letter-spacing: 0.08em; text-align: left; text-transform: uppercase; white-space: nowrap; }
.upstream-table td { padding: 9px 12px; border-bottom: 1px solid var(--lyf-line); color: var(--lyf-ink-2); vertical-align: middle; }
.upstream-table tr:last-child td { border-bottom: 0; }
.upstream-table tr:hover { background: rgb(34 211 238 / 4%); }
.upstream-table b { display: block; color: var(--lyf-ink); font-size: 12px; font-weight: 600; }
.upstream-table small { display: block; margin-top: 2px; color: var(--lyf-ink-3); font-size: 10px; }
.upstream-address a { color: var(--lyf-accent); font-family: var(--lyf-font-data); font-size: 10.5px; text-decoration: none; }
.upstream-address a:hover { text-decoration: underline; }
.upstream-actions { white-space: nowrap; }
.engine-chip { display: inline-flex; padding: 1px 7px; border: 1px solid var(--lyf-low-line); border-radius: 2px; background: var(--lyf-low-soft); color: var(--lyf-low); font-family: var(--lyf-font-data); font-size: 10px; font-weight: 600; }
.update-state { display: inline-flex; margin-right: 8px; color: var(--lyf-ink-3); font-size: 10.5px; }
.confirm-btn { height: 26px; padding: 0 10px; border: 1px solid var(--lyf-accent-line); border-radius: 2px; background: var(--lyf-accent-soft); color: var(--lyf-accent); font: inherit; font-size: 11px; cursor: pointer; }
.confirm-btn:hover:not(:disabled) { border-color: var(--lyf-accent); box-shadow: var(--lyf-glow); }
.confirm-btn:disabled { opacity: 0.45; cursor: not-allowed; }
.row-message { display: block; margin-top: 4px; color: var(--lyf-medium); font-size: 10px; }

.source-empty, .whitelist-empty { display: grid; min-height: 110px; place-items: center; padding: 18px; color: var(--lyf-ink-3); font-size: 11.5px; text-align: center; }
.source-empty strong { display: block; margin-bottom: 4px; color: var(--lyf-ink-2); }

.geo-data-note { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; padding: 11px 16px; border-top: 1px solid var(--lyf-line); color: var(--lyf-ink-3); font-size: 10.5px; }
.geo-data-note b { color: var(--lyf-ink-2); }
.geo-source-ref a { color: var(--lyf-accent); text-decoration: none; }

.filters { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--lyf-line); }
.filter-controls { display: flex; flex-wrap: wrap; gap: 10px; }
.filters label { display: grid; gap: 4px; color: var(--lyf-ink-3); font-size: 10.5px; }
.filters input, .filters select { height: 32px; padding: 0 10px; border: 1px solid var(--lyf-line-2); border-radius: var(--lyf-radius-sm); background: var(--lyf-surface); color: var(--lyf-ink); font: inherit; font-size: 12px; outline: 0; }
.filters input:focus, .filters select:focus { border-color: var(--lyf-accent); box-shadow: var(--lyf-glow); }

.table-wrap { overflow: auto; }
.table-wrap table { width: 100%; border-collapse: collapse; font-size: 12px; }
.table-wrap th { height: 36px; padding: 0 12px; border-bottom: 1px solid var(--lyf-line-2); background: var(--lyf-surface-2); color: var(--lyf-ink-3); font-family: var(--lyf-font-data); font-size: 9.5px; font-weight: 600; letter-spacing: 0.08em; text-align: left; text-transform: uppercase; white-space: nowrap; }
.table-wrap td { padding: 9px 12px; border-bottom: 1px solid var(--lyf-line); color: var(--lyf-ink-2); vertical-align: middle; }
.table-wrap tr:hover { background: rgb(34 211 238 / 4%); }
.table-wrap b { color: var(--lyf-ink); font-weight: 600; }
.table-wrap small { display: block; margin-top: 2px; color: var(--lyf-ink-3); font-size: 10px; }
.empty-cell { padding: 26px 12px; color: var(--lyf-ink-3); text-align: center; }

.severity-pills { display: flex; gap: 4px; }
.severity-pill, .enable-pill { display: inline-flex; padding: 1px 7px; border: 1px solid var(--lyf-line-2); border-radius: 2px; background: var(--lyf-surface-2); color: var(--lyf-ink-2); font-family: var(--lyf-font-data); font-size: 10px; cursor: pointer; }
.severity-pill.active, .enable-pill.active { border-color: var(--lyf-accent-line); background: var(--lyf-accent-soft); color: var(--lyf-accent); }
.action-cell button { height: 26px; padding: 0 9px; border: 1px solid var(--lyf-line-2); border-radius: 2px; background: var(--lyf-surface); color: var(--lyf-ink-2); font: inherit; font-size: 11px; cursor: pointer; }
.action-cell button:hover { border-color: var(--lyf-accent); color: var(--lyf-accent); }

.pager { display: flex; align-items: center; justify-content: flex-end; gap: 10px; padding: 10px 14px; border-top: 1px solid var(--lyf-line); background: var(--lyf-surface-2); color: var(--lyf-ink-3); font-size: 11px; }
.pager button { height: 26px; padding: 0 10px; border: 1px solid var(--lyf-line-2); border-radius: 2px; background: var(--lyf-surface); color: var(--lyf-ink-2); font: inherit; font-size: 11px; cursor: pointer; }
.pager button:disabled { opacity: 0.45; cursor: not-allowed; }

.whitelist-card .panel-heading { align-items: flex-start; }
.whitelist-body { display: grid; gap: 12px; padding: 14px 16px; }
.whitelist-form { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 10px; }
.whitelist-form label { display: grid; gap: 4px; color: var(--lyf-ink-3); font-size: 10.5px; }
.whitelist-form input, .whitelist-form select { height: 32px; padding: 0 10px; border: 1px solid var(--lyf-line-2); border-radius: var(--lyf-radius-sm); background: var(--lyf-surface); color: var(--lyf-ink); font: inherit; font-size: 12px; outline: 0; }
.whitelist-form button { height: 32px; padding: 0 12px; border: 1px solid var(--lyf-accent); border-radius: 2px; background: var(--lyf-accent); color: #031018; font: inherit; font-size: 12px; font-weight: 650; cursor: pointer; }
.whitelist-list { display: grid; gap: 6px; }
.whitelist-item { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 9px 12px; border: 1px solid var(--lyf-line); border-radius: var(--lyf-radius-sm); background: var(--lyf-surface-2); }
.whitelist-value { color: var(--lyf-ink); font-family: var(--lyf-font-data); font-size: 11.5px; }
.whitelist-reason { color: var(--lyf-ink-3); font-size: 10.5px; }

.state-card { padding: 12px 14px; border: 1px solid var(--lyf-line); border-radius: var(--lyf-radius-sm); background: var(--lyf-surface-2); color: var(--lyf-ink-2); font-size: 12px; }
.error-state { border-color: var(--lyf-critical-line); background: var(--lyf-critical-soft); color: var(--lyf-critical); }

@media (max-width: 1280px) { .engine-source-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 760px) {
  .engine-source-grid { grid-template-columns: minmax(0, 1fr); }
  .panel-heading, .upstream-heading { align-items: flex-start; flex-direction: column; }
  .source-head-meta { text-align: left; }
}
</style>
