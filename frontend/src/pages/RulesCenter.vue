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
import { assetAgentClient, ruleClient } from '../api/domain'
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

const severityOptions = [
  { value: 'info', label: '信息', score: 20 },
  { value: 'low', label: '低', score: 35 },
  { value: 'medium', label: '中', score: 55 },
  { value: 'high', label: '高', score: 75 },
  { value: 'critical', label: '严重', score: 95 },
]

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))
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
})
</script>

<style scoped>
.ops-page{height:100%;min-height:0;display:grid;grid-template-rows:auto auto minmax(0,1fr);gap:10px;padding:12px;color:var(--text-primary);box-sizing:border-box}.page-head{display:flex;justify-content:space-between;gap:16px;padding:18px 22px;border-radius:20px;border:1px solid var(--border-light);background:linear-gradient(135deg,rgba(17,31,52,.94),rgba(8,18,32,.78))}.page-head p{margin:0 0 6px;color:var(--primary-light);font-size:11px;font-weight:900;letter-spacing:.16em}.page-head h2{margin:0;font-size:clamp(26px,2.6vw,38px);letter-spacing:-.045em}.page-head span{display:block;max-width:820px;margin-top:6px;color:var(--text-muted)}.head-actions{display:flex;gap:8px;align-self:start}.page-head button,.filters button,.pager button,.source-actions button,.confirm-btn{border:0;border-radius:10px;padding:8px 11px;background:#38bdf8;color:#04111f;font-weight:900}.source-actions button.secondary{background:#1e293b;color:#cbd5e1;border:1px solid rgba(148,163,184,.24)}.feed-list{grid-column:1/-1;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px;padding:0 8px 8px 8px;overflow:hidden}.feed-list span{height:22px;min-width:0;display:flex;align-items:center;padding:0 8px;border:1px solid rgba(56,189,248,.2);border-radius:999px;background:rgba(14,165,233,.08);color:#bae6fd;font-size:12px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}button:disabled,.source-actions button:disabled{opacity:.5;cursor:not-allowed;background:#1e293b;color:#64748b}.surface-card{border:1px solid rgba(148,163,184,.18);background:#0f172a;border-radius:20px;box-shadow:0 18px 52px rgba(0,0,0,.22);overflow:hidden}.state-card{padding:9px 12px;border-radius:13px;background:#0f2f3f;border:1px solid rgba(56,189,248,.28);color:#bae6fd}.error-state{background:#3b1118;border-color:rgba(248,113,113,.34);color:#fecaca}.panel-heading,.panel-title{height:38px;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:0 14px;border-bottom:1px solid var(--border-light);background:rgba(4,12,24,.38)}.panel-heading strong,.panel-title strong{color:var(--text-primary);font-size:13px}.panel-heading span,.panel-title span{color:var(--text-muted);font-size:11px}.source-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;padding:8px}.source-row{display:grid;grid-template-rows:auto 1fr auto;gap:6px;min-width:0;padding:8px;border-radius:14px;background:#111c2f;border:1px solid rgba(148,163,184,.14)}.source-main{display:flex;align-items:flex-start;gap:8px;min-width:0}.source-main b{display:block;font-size:13px;color:#e2e8f0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.source-main small{display:block;margin-top:2px;color:#94a3b8;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.status-dot{width:9px;height:9px;margin-top:4px;border-radius:50%;background:#ef4444;box-shadow:0 0 12px rgba(239,68,68,.5);flex:0 0 auto}.status-dot.ok{background:#22c55e;box-shadow:0 0 14px rgba(34,197,94,.55)}.status-dot.warn{background:#f59e0b}.source-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px 8px}.source-fields>div{display:grid;grid-template-columns:48px minmax(0,1fr);gap:5px;align-items:center;min-width:0}.source-fields span{font-size:12px;color:#64748b;white-space:nowrap}.source-fields strong{min-width:0;color:#cbd5e1;font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.address-field input{width:100%;min-width:0;height:26px;border-radius:8px;border:1px solid rgba(148,163,184,.18);background:#0b1220;color:#bfdbfe;padding:0 8px;box-sizing:border-box;font-size:11px}.path-field strong{color:#7dd3fc}.source-actions{display:flex;align-items:center;gap:6px;min-width:0}.source-actions em{margin-right:auto;font-style:normal;font-size:11px;color:#94a3b8;white-space:nowrap}.source-actions em.run{color:#86efac}.source-actions em.warn{color:#fcd34d}.source-actions em.bad{color:#fca5a5}.source-actions button{height:28px;padding:0 9px;border-radius:9px;font-size:11px;white-space:nowrap}.row-message{grid-column:1/-1;margin:0;color:#7dd3fc;font-size:11px}.rules-panel{min-height:0;display:grid;grid-template-rows:auto minmax(0,1fr) auto}.filters{min-height:44px;height:auto;align-items:center;padding:8px 14px;gap:12px}.panel-copy{display:grid;gap:2px;min-width:180px}.filter-controls{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex:1;min-width:0}.filters label{display:flex;align-items:center;gap:6px;color:#94a3b8;font-size:12px;white-space:nowrap}.filters select,.filters input{height:30px;border-radius:9px;border:1px solid rgba(148,163,184,.18);background:#0b1220;color:#dbeafe;padding:0 9px}.filters input{width:min(260px,28vw);min-width:180px}.table-wrap{overflow:auto}table{width:100%;min-width:1080px;border-collapse:collapse}th,td{padding:10px 12px;border-bottom:1px solid rgba(148,163,184,.12);text-align:left;vertical-align:top}th{color:#94a3b8;font-size:12px;background:#0b1220;position:sticky;top:0;z-index:1}td b{display:block;color:#e2e8f0;font-size:13px}td small{display:block;margin-top:3px;color:#64748b;font-size:11px}.empty-cell{text-align:center;color:#94a3b8;padding:30px}.engine-chip{display:inline-flex;padding:4px 8px;border-radius:999px;background:#10243a;color:#7dd3fc;font-size:12px}.enable-pill{display:inline-flex;align-items:center;gap:6px;padding:5px 8px;border-radius:999px;background:#1e293b;color:#94a3b8}.enable-pill.active{background:rgba(34,197,94,.14);color:#86efac}.enable-pill input{accent-color:#22c55e}.severity-pills{display:flex;flex-wrap:wrap;gap:5px}.severity-pill{height:25px;border-radius:999px;border:1px solid rgba(148,163,184,.18);background:#111827;color:#94a3b8;font-size:11px}.severity-pill.active.info{background:#0e7490;color:#ecfeff}.severity-pill.active.low{background:#166534;color:#dcfce7}.severity-pill.active.medium{background:#854d0e;color:#fef3c7}.severity-pill.active.high{background:#9a3412;color:#ffedd5}.severity-pill.active.critical{background:#991b1b;color:#fee2e2}.confirm-btn{height:28px}.pager{height:42px;display:flex;align-items:center;justify-content:flex-end;gap:8px;padding:0 14px;color:#94a3b8;border-top:1px solid rgba(148,163,184,.14);background:rgba(4,12,24,.22)}.pager span{height:28px;display:inline-flex;align-items:center;padding:0 10px;border-radius:999px;background:#0b1220;border:1px solid rgba(148,163,184,.18);font-size:12px;font-weight:800}.pager button{height:28px;padding:0 10px;border-radius:9px;font-size:11px}@media(max-width:1280px){.source-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:760px){.source-grid,.metric-grid{grid-template-columns:1fr}.page-head{flex-direction:column}.panel-title{height:auto;flex-wrap:wrap;padding:10px}.filter-controls{width:100%;justify-content:flex-start;flex-wrap:wrap}.filters input{width:100%;min-width:0}}

.table-wrap table{table-layout:fixed}.rule-col{width:19%}.engine-col{width:11%}.path-col{width:20%}.status-col{width:9%}.severity-col{width:29%}.action-col{width:12%}.rule-cell,.path-cell{min-width:0}.rule-cell b,.path-cell b{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.status-cell,.engine-cell,.action-cell{vertical-align:middle}.severity-cell{vertical-align:middle;padding-top:8px;padding-bottom:8px}.severity-pills{display:grid!important;grid-template-columns:repeat(5,minmax(38px,1fr));gap:6px;align-items:center;min-width:230px}.severity-pill{height:28px!important;min-width:0;padding:0 8px!important;border-radius:8px!important;border:1px solid rgba(148,163,184,.2)!important;background:#0b1220!important;color:#94a3b8!important;font-size:12px!important;font-weight:800!important;line-height:28px!important;text-align:center;box-sizing:border-box}.severity-pill.active.info{background:#0e7490!important;color:#ecfeff!important;border-color:#22d3ee!important}.severity-pill.active.low{background:#166534!important;color:#dcfce7!important;border-color:#22c55e!important}.severity-pill.active.medium{background:#854d0e!important;color:#fef3c7!important;border-color:#f59e0b!important}.severity-pill.active.high{background:#9a3412!important;color:#ffedd5!important;border-color:#fb923c!important}.severity-pill.active.critical{background:#991b1b!important;color:#fee2e2!important;border-color:#f87171!important}.action-cell{display:flex;flex-direction:column;align-items:flex-start;gap:5px}.action-cell .confirm-btn{height:30px;min-width:76px;padding:0 12px;border-radius:9px}.action-cell .row-message{margin:0;line-height:1.2}.enable-pill{white-space:nowrap}.engine-chip{white-space:nowrap}@media(max-width:1280px){table{min-width:1180px}.severity-col{width:320px}.severity-pills{min-width:280px}}
.ops-page{color:#243149}.page-head{padding:10px 16px;border-color:#dce4ef;border-radius:6px;background:#fff;box-shadow:0 3px 12px rgba(44,66,96,.07)}.page-head p{color:#2782e8;letter-spacing:0}.page-head h2{color:#243149;font-size:22px;letter-spacing:0}.surface-card{border-color:#dce4ef;background:#fff;border-radius:6px;box-shadow:0 3px 12px rgba(44,66,96,.07)}.panel-heading,.panel-title{border-color:#e3e9f1;background:#f6f8fb}.panel-heading strong,.panel-title strong{color:#263247}.panel-heading span,.panel-title span{color:#758195}.source-row{border-color:#dfe6ef;border-radius:5px;background:#fff}.source-main b{color:#263247}.source-main small{color:#7b8798}.source-fields span{color:#758195}.source-fields strong{color:#334155}.address-field input,.filters select,.filters input{border-color:#d5deea;background:#fff;color:#263247}.feed-list span{border-color:#c4dcf5;border-radius:4px;background:#edf6ff;color:#1769d2}.source-actions em{color:#6f7c91}.source-actions em.run{color:#16824f}.source-actions em.warn{color:#a55d08}.source-actions em.bad{color:#b42318}.source-actions button,.filters button,.pager button,.confirm-btn{border-radius:4px;background:#1769d2;color:#fff}.state-card{border-color:#a9cdf3;background:#edf6ff;color:#1769d2}.table-wrap table th{background:#eef3f8;color:#53627a}.table-wrap table td{color:#304058}.table-wrap table th,.table-wrap table td{border-color:#e6ebf2;text-align:center;vertical-align:middle}.table-wrap td b{color:#263247}.table-wrap td small{color:#758195}.engine-chip{border-radius:4px;background:#e8f3ff;color:#1769d2}.enable-pill{border-radius:4px;background:#f0f3f7;color:#66758a}.enable-pill.active{background:#e9f7ef;color:#178653}.severity-pill{border-radius:4px!important;border-color:#d7e0eb!important;background:#fff!important;color:#526078!important}.pager{border-color:#e3e9f1;background:#f7f9fc;color:#68758a}.pager span{border-color:#d7e0eb;border-radius:4px;background:#fff}.action-cell{align-items:center}
/* Backend-driven engine/source sync */
.source-card{display:grid;grid-template-rows:auto auto auto;min-height:0}
.source-card .panel-heading{height:auto;min-height:38px;padding:6px 12px}
.source-heading-copy{display:grid;gap:2px;min-width:0}
.source-heading-copy small{color:#758195;font-size:12px;font-weight:500}
.source-head-meta{display:flex;align-items:center;justify-content:flex-end;gap:8px;min-width:0;flex-wrap:wrap}
.source-warning{color:#b45309;font-size:12px;font-weight:700;white-space:nowrap}
.source-empty{padding:24px 16px;color:#758195;text-align:center;font-size:11px}
.source-empty strong{display:block;margin-bottom:4px;color:#263247;font-size:12px}
.engine-source-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:7px;padding:9px 10px 8px}
.engine-source-card{display:grid;gap:7px;min-width:0;padding:9px;border:1px solid #dfe6ef;border-top:3px solid #2f80ed;border-radius:5px;background:#fff}
.engine-source-card.engine-security-engine{border-top-color:#0f766e}
.engine-source-card.engine-suricata{border-top-color:#2f80ed}
.engine-source-card.engine-wazuh{border-top-color:#7c5cff}
.engine-source-card.engine-yara{border-top-color:#d99a14}
.engine-source-card.engine-rasp{border-top-color:#16a36a}
.engine-source-head{display:flex;align-items:center;gap:7px;min-width:0}
.engine-monogram{display:grid;width:26px;height:26px;flex:0 0 26px;place-items:center;border-radius:5px;background:#e8f3ff;color:#1769d2;font-size:12px;font-weight:900;letter-spacing:.02em}
.engine-monogram.low{background:#e9f7ef;color:#178653}
.engine-monogram.medium{background:#fff4e5;color:#b45309}
.engine-source-head>div{display:grid;gap:2px;min-width:0;flex:1}
.engine-source-head b{overflow:hidden;color:#263247;font-size:12px;font-weight:800;text-overflow:ellipsis;white-space:nowrap}
.engine-source-head small{overflow:hidden;color:#758195;font-size:11px;text-overflow:ellipsis;white-space:nowrap}
.engine-source-head .sx-badge{flex:0 0 auto;font-size:11px}
.engine-source-facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px 8px;padding-top:6px;border-top:1px solid #eef2f7}
.engine-source-facts div{min-width:0}
.engine-source-facts span{display:block;color:#7b8798;font-size:11px}
.engine-source-facts b{display:block;overflow:hidden;color:#334155;font-size:13px;font-weight:800;text-overflow:ellipsis;white-space:nowrap}
.engine-source-note{min-height:23px;margin:0;overflow:hidden;color:#758195;font-size:11px;line-height:1.45;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.upstream-section{border-top:1px solid #e3e9f1}
.upstream-heading{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 12px;background:#f7f9fc}
.upstream-heading div{display:flex;align-items:baseline;gap:8px;min-width:0}
.upstream-heading strong{color:#263247;font-size:12px}
.upstream-heading span{color:#758195;font-size:12px}
.upstream-table-wrap{max-height:280px;overflow:auto;scrollbar-width:thin}
.upstream-table{width:100%;min-width:1120px;border-collapse:collapse;table-layout:fixed}
.upstream-table th{height:28px;padding:0 9px;border-bottom:1px solid #e3e9f1;background:#fbfcfe;color:#65748a;font-size:12px;font-weight:800;text-align:left;position:sticky;top:0;z-index:1}
.upstream-table td{padding:7px 9px;border-bottom:1px solid #edf1f6;color:#334155;font-size:12px;vertical-align:middle}
.upstream-table th:nth-child(1){width:110px}.upstream-table th:nth-child(2){width:210px}.upstream-table th:nth-child(3){width:29%}.upstream-table th:nth-child(4){width:190px}.upstream-table th:nth-child(5){width:140px}.upstream-table th:nth-child(6){width:150px}
.upstream-table td b{display:block;overflow:hidden;color:#263247;font-size:11px;font-weight:700;text-overflow:ellipsis;white-space:nowrap}
.upstream-table td small{display:block;margin-top:2px;overflow:hidden;color:#758195;font-size:11px;text-overflow:ellipsis;white-space:nowrap}
.upstream-address a{display:block;overflow:hidden;color:#1769d2;font-size:12px;text-decoration:none;text-overflow:ellipsis;white-space:nowrap}
.upstream-address a:hover{text-decoration:underline}
.upstream-actions{white-space:nowrap}
.upstream-actions .confirm-btn{margin-left:6px;height:24px;min-width:48px;padding:0 8px;border-radius:4px;font-size:12px}
.update-state{font-size:11px;font-weight:800}
.update-state.available{color:#b45309}
.update-state.synced{color:#178653}
.update-state.unknown{color:#64748b}
.geo-data-note{display:flex;align-items:center;gap:9px;flex-wrap:wrap;padding:8px 12px;border-top:1px dashed #dfe6ef;background:#fbfcfe;color:#758195;font-size:12px}
.geo-data-note b{color:#475569;font-size:12px}
.geo-source-ref{color:#8793a5}
.geo-source-ref a{color:#1769d2;text-decoration:none}
.geo-source-ref a:hover{text-decoration:underline}
@media(max-width:1300px){.engine-source-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:1000px){.engine-source-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:760px){.engine-source-grid{grid-template-columns:1fr}.upstream-heading{align-items:flex-start;flex-direction:column;gap:2px}}
</style>
