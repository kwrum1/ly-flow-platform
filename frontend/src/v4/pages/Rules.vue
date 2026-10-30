<template>
  <section class="v-page">
    <header class="v-head">
      <div>
        <p class="v-eyebrow">RULE LIFECYCLE</p>
        <h1>规则中心</h1>
        <p>规则源、版本与生效状态。规则包版本来自运行时上报；未上报的字段显示为未知，不按最新处理。</p>
      </div>
      <div class="v-head-actions">
        <button class="v-btn" type="button" :disabled="loading" @click="load">{{ loading ? '读取中…' : '刷新' }}</button>
        <button class="v-btn primary" type="button" :disabled="syncing" @click="sync">{{ syncing ? '同步中…' : '同步规则源' }}</button>
      </div>
    </header>

    <div v-if="error" class="v-error">{{ error }}</div>
    <div v-if="syncNotice" class="v-notice">
      <div>{{ syncNotice }}</div>
      <div v-if="syncProgress !== null" class="v-progress"><i :style="{ width: syncProgress + '%' }" /></div>
      <ul v-if="syncFailures.length" class="notes">
        <li v-for="f in syncFailures" :key="f.source_id"><b class="v-mono">{{ f.source_id }}</b> {{ f.error }}</li>
      </ul>
    </div>

    <section class="v-grid c4">
      <article class="v-stat"><span class="v-stat-label"><i />生效规则</span><strong class="v-stat-value">{{ formatNumber(totalRules) }}</strong><span class="v-stat-note">当前规则包编译后条目</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />规则源</span><strong class="v-stat-value">{{ sources.length }}</strong><span class="v-stat-note">已登记的上游来源</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />待应用</span><strong class="v-stat-value warning">{{ pendingApply }}</strong><span class="v-stat-note">同步后立即生效，暂存才会显示在这里</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />隔离规则</span><strong class="v-stat-value" :class="quarantine.length ? 'danger' : ''">{{ quarantine.length }}</strong><span class="v-stat-note">编译失败或不兼容</span></article>
    </section>

    <article class="v-panel">
      <div class="v-panel-head">
        <div class="v-panel-title">四类引擎规则源</div>
        <span class="v-panel-meta">自动更新 + 手动更新 · 最近同步 {{ shortTime(freshness.last_sync_at) }}
          <b v-if="freshness.status === 'degraded'" class="v-state" data-state="degraded" style="margin-left:8px">已过期</b>
        </span>
      </div>
      <div class="v-table-wrap">
        <table class="v-table">
          <thead><tr><th>引擎</th><th>规则源</th><th>自动更新</th><th>最近同步</th><th>状态</th><th class="actions">操作</th></tr></thead>
          <tbody>
            <tr v-for="g in sourceGroups" :key="g.key">
              <td><b>{{ g.label }}</b></td>
              <td class="v-dim">{{ g.sources.length ? g.sources.map((s) => s.name || s.id).join(' · ') : '无上游（本地/构建产物）' }}</td>
              <td>{{ g.cadence }}</td>
              <td class="num">{{ shortTime(g.lastSync) }}</td>
              <td><span class="v-state" :data-state="g.expired ? 'degraded' : g.upstream ? 'healthy' : 'unknown'">{{ g.expired ? '过期' : g.upstream ? '正常' : '无上游' }}</span></td>
              <td class="actions"><button class="v-btn sm" type="button" :disabled="syncing || !g.upstream" @click="sync">手动更新</button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </article>

    <article class="v-panel">
      <div class="v-panel-head">
        <div class="v-panel-title">病毒扫描引擎 · 本地规则导入</div>
        <span class="v-panel-meta">无外部上游 · 导入后由 Agent 自动拉取</span>
      </div>
      <div class="v-panel-body form">
        <dl class="v-kv">
          <dt>总规则数</dt><dd>{{ formatNumber(yaraPack.total_rules || 0) }}</dd>
          <dt>内置规则</dt><dd>{{ formatNumber((yaraPack.total_rules || 0) - (yaraPack.imported_rules || 0)) }}</dd>
          <dt>导入规则</dt><dd>{{ formatNumber(yaraPack.imported_rules || 0) }}</dd>
          <dt>文件大小</dt><dd>{{ formatNumber(Math.round((yaraPack.size_bytes || 0) / 1024)) }} KB</dd>
          <dt>最近更新</dt><dd>{{ shortTime(yaraPack.updated_at) }}</dd>
          <dt>导入路径</dt><dd class="v-mono">{{ yaraPack.import_path || '/data/yara/imported.yar' }}</dd>
        </dl>
        <div class="v-toolbar">
          <label class="v-field grow"><span>YARA 规则文件</span><input class="v-input" type="file" accept=".yar,.yara" @change="onYARAFile" /></label>
          <button class="v-btn primary" type="button" :disabled="yaraBusy || !yaraFile" @click="importYARA">{{ yaraBusy ? '导入中…' : '导入规则' }}</button>
          <button v-if="yaraPack.imported" class="v-btn" type="button" :disabled="yaraBusy" @click="clearYARA">清空导入</button>
        </div>
        <p class="v-dim">导入后写入 {{ yaraPack.import_path || '/data/yara/imported.yar' }}，Agent 在下一次 YARA 扫描周期（约 1–2 分钟）自动拉取。</p>
        <div v-if="yaraNotice" class="v-notice">{{ yaraNotice }}</div>
      </div>
    </article>


    

    <article class="v-panel">
      <div class="v-panel-head">
        <div class="v-panel-title">检测规则</div>
        <span class="v-panel-meta">{{ detailRules.length }} 条可治理规则 · 停用后立即重编译</span>
      </div>
      <div class="v-table-wrap">
        <table class="v-table">
          <thead><tr><th>规则</th><th>引擎</th><th>等级</th><th>状态</th><th class="actions">操作</th></tr></thead>
          <tbody>
            <tr v-if="!detailRules.length"><td colspan="5" class="v-empty">暂无可治理的检测规则</td></tr>
            <tr v-for="r in pagedDetailRules" :key="r.id">
              <td><b>{{ r.name || r.id }}</b><small class="v-mono">{{ r.id }}</small></td>
              <td>{{ r.engine || r.category || '-' }}</td>
              <td><span class="v-badge" :class="r.severity">{{ r.severity || '-' }}</span></td>
              <td><span class="v-state" :data-state="r.enabled ? 'healthy' : 'unknown'">{{ r.enabled ? '启用' : '停用' }}</span></td>
              <td class="actions">
                <button class="v-btn sm" type="button" :disabled="togglingRule === r.id" @click="toggleRule(r)">
                  {{ r.enabled ? '停用' : '启用' }}
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
          <div class="v-panel-body pagination">
        <span class="v-dim">第 {{ rulePage }} / {{ rulePageCount }} 页 · 共 {{ detailRules.length }} 条</span>
        <div class="row">
          <button class="v-btn sm" type="button" :disabled="rulePage <= 1" @click="rulePage -= 1">上一页</button>
          <button class="v-btn sm" type="button" :disabled="rulePage >= rulePageCount" @click="rulePage += 1">下一页</button>
        </div>
      </div>
</article>

    

    <section class="v-grid c2">
      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">引擎规则</div><span class="v-panel-meta">系统 / Web / 流量 / 病毒 四类</span></div>
        <div class="v-table-wrap">
          <table class="v-table">
            <thead><tr><th>引擎</th><th>规则数</th><th>版本</th><th>状态</th></tr></thead>
            <tbody>
              <tr v-for="e in engineRules" :key="e.engine">
                <td><b>{{ e.engine }}</b><small>{{ e.engines }}</small></td>
                <td class="num">{{ formatNumber(e.count) }}</td>
                <td class="v-mono">{{ e.version || '-' }}</td>
                <td><span class="v-state" :data-state="e.count > 0 ? 'healthy' : 'unknown'">{{ e.count > 0 ? '已加载' : '未加载' }}</span></td>
              </tr>
            </tbody>
          </table>
          <div v-if="!engineRules.length" class="v-table-empty">暂无引擎规则上报</div>
        </div>
      </article>

      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">隔离规则</div><span class="v-panel-meta">编译失败 / 不兼容</span></div>
        <div class="v-table-wrap">
          <table class="v-table">
            <thead><tr><th>规则</th><th>来源</th><th>原因</th></tr></thead>
            <tbody>
              <tr v-for="q in quarantine" :key="q.id || q.rule_id">
                <td><b>{{ q.name || q.rule_id }}</b></td>
                <td>{{ q.source || '-' }}</td>
                <td class="reason">{{ q.reason || q.error || '-' }}</td>
              </tr>
            </tbody>
          </table>
          <div v-if="!quarantine.length" class="v-table-empty"><strong>没有隔离规则</strong>当前规则包全部可用。</div>
        </div>
      </article>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { opsClient, ruleClient, yaraClient } from '../../api/domain'
import { formatChinaDateTime } from '../../shared/time'

const loading = ref(false)
const syncing = ref(false)
const error = ref('')
const stats = ref({})
const sources = ref([])
const quarantine = ref([])
const engineRules = ref([])
const engineRuntime = ref({})
const detailRules = ref([])
const artifactEvents = ref([])
const togglingRule = ref('')
const freshness = ref({})
const yaraPack = ref({})
const yaraFile = ref(null)
const yaraBusy = ref(false)
const yaraNotice = ref('')

const totalRules = computed(() => Number(stats.value.totalRules || stats.value.total_rules || stats.value.total || 0))
const pendingApply = computed(() => sources.value.filter((s) => String(s.sync_status || '').toLowerCase() === 'staged').length)
const rulePage = ref(1)
const rulePageSize = 10
const rulePageCount = computed(() => Math.max(1, Math.ceil(detailRules.value.length / rulePageSize)))
const pagedDetailRules = computed(() => {
  const maxPage = rulePageCount.value
  const page = Math.min(Math.max(1, rulePage.value), maxPage)
  const start = (page - 1) * rulePageSize
  return detailRules.value.slice(start, start + rulePageSize)
})

const localSources = computed(() => sources.value.filter((s) => !s.updatable))
const updatableSources = computed(() => sources.value.filter((s) => s.updatable))

const sourceGroups = computed(() => {
  const defs = [
    { key: 'system', label: '系统检测引擎', categories: ['log_audit', 'runtime'] },
    { key: 'web', label: 'Web 检测防护引擎', categories: ['rasp'] },
    { key: 'traffic', label: '流量聚合引擎', categories: ['traffic'] },
    { key: 'virus', label: '病毒扫描引擎', categories: ['artifact', 'yara'] },
  ]
  return defs.map((def) => {
    const members = updatableSources.value.filter((source) => def.categories.includes(String(source.category || '').toLowerCase()))
    const lastSync = members.map((source) => source.last_sync_at || source.updated_at).filter(Boolean).sort().pop() || ''
    const expired = members.some((source) => {
      const state = sourceState(source)
      return state.tone === 'degraded' || state.tone === 'failed'
    })
    return {
      ...def,
      sources: members,
      lastSync,
      expired,
      upstream: members.length > 0,
      cadence: members.length > 0 ? '自动（后端调度）' : '无上游',
    }
  })
})

function sourceKind(source) {
  if (!source.updatable) {
    return { label: source.origin === 'user_provided' ? '自建' : '内置' }
  }
  const raw = String(source.url || '')
  if (raw.includes('github')) return { label: 'GitHub' }
  return { label: '直连' }
}

function localNote(source) {
  if (source.origin === 'user_provided') return '用户提供，需手工更新'
  if (source.origin === 'external_reference') return '上游派生后固化'
  return '随版本发布'
}
const syncNotice = ref('')
const syncFailures = ref([])
const syncProgress = ref(null)

function unwrap(r) { return r?.data?.data ?? r?.data ?? r ?? {} }
function formatNumber(v) { return (Number(v) || 0).toLocaleString('zh-CN') }
function shortTime(v) { return v ? formatChinaDateTime(v) : '-' }

function sourceState(source) {
  const status = String(source.sync_status || '').toLowerCase()
  if (status === 'failed') return { label: '同步失败', tone: 'failed' }
  if (status === 'synced') return { label: '已生效', tone: 'healthy' }
  if (status === 'staged') return { label: '待应用', tone: 'degraded' }
  if (source.updatable) return { label: '待同步', tone: 'unknown' }
  return { label: '本地', tone: 'healthy' }
}

function buildEngineRows(payload) {
  const counts = payload.counts || {}
  const semantics = payload.count_semantics || {}
  const groups = [
    { key: 'system', label: '系统检测引擎', engines: ['runtime', 'log_audit', 'security-engine', 'xdr', 'lyflow'] },
    { key: 'web', label: 'Web 检测防护引擎', engines: ['rasp', 'owasp'] },
    { key: 'traffic', label: '流量聚合引擎', engines: ['suricata', 'lyprobe'] },
    { key: 'virus', label: '病毒扫描引擎', engines: ['yara', 'artifact'] },
  ]
  const rows = groups.map((group) => {
    const present = group.engines.filter((engine) => engine in counts)
    const count = present.reduce((sum, engine) => sum + (Number(counts[engine]) || 0), 0)
    const suricata = semantics.suricata || {}
    return {
      engine: group.label,
      engines: present.length ? present.join(' / ') : '暂无上报',
      count,
      version: group.key === 'traffic' && suricata.ledger_digest ? `ledger-${String(suricata.ledger_digest).slice(0, 12)}` : '',
    }
  })
  // The sensor loads ET Open directly; the converted flow rules above are a
  // much smaller set and must not be presented as the signature inventory.
  const sensor = engineRuntime.value?.engines?.suricata || {}
  if (sensor.signature_count) {
    rows.push({
      engine: 'Suricata 传感器',
      engines: 'et-open + 自写规则',
      count: sensor.signature_count,
      version: sensor.ruleset_updated_at ? String(sensor.ruleset_updated_at).slice(0, 10) : '',
    })
  }
  return rows
}

function onYARAFile(event) {
  yaraFile.value = event?.target?.files?.[0] || null
}

async function importYARA() {
  if (!yaraFile.value) return
  yaraBusy.value = true
  yaraNotice.value = ''
  try {
    const form = new FormData()
    form.append('file', yaraFile.value)
    yaraPack.value = unwrap(await yaraClient.import(form)) || yaraPack.value
    yaraFile.value = null
    yaraNotice.value = '规则已导入，Agent 将在下一次 YARA 扫描周期拉取'
  } catch (e) {
    error.value = e?.response?.data?.message || e?.message || 'YARA 规则导入失败'
  } finally {
    yaraBusy.value = false
  }
}

async function clearYARA() {
  yaraBusy.value = true
  yaraNotice.value = ''
  try {
    yaraPack.value = unwrap(await yaraClient.clear()) || yaraPack.value
    yaraNotice.value = '已清空导入规则，Agent 将在下一次 YARA 扫描周期恢复内置规则'
  } catch (e) {
    error.value = e?.response?.data?.message || e?.message || '清空 YARA 导入失败'
  } finally {
    yaraBusy.value = false
  }
}

async function load() {
  loading.value = true
  error.value = ''
  const [s, src, q, er, yp, rt] = await Promise.allSettled([
    ruleClient.stats(),
    ruleClient.platformSources(),
    ruleClient.quarantine(),
    ruleClient.engineRules({ limit: 200 }),
    yaraClient.status(),
    ruleClient.engineRuntimeStatus(),
  ])
  if (s.status === 'fulfilled') stats.value = unwrap(s.value)
  if (src.status === 'fulfilled') {
    const p = unwrap(src.value)
    sources.value = p.items || p.sources || (Array.isArray(p) ? p : [])
    freshness.value = p.freshness || {}
  }
  if (q.status === 'fulfilled') {
    const p = unwrap(q.value)
    quarantine.value = p.items || (Array.isArray(p) ? p : [])
  }
  if (er.status === 'fulfilled') {
    const p = unwrap(er.value)
    engineRules.value = p.items && p.counts ? buildEngineRows(p) : (p.engines || [])
  }
  if (yp.status === 'fulfilled') {
    yaraPack.value = unwrap(yp.value) || {}
  }
  if (rt.status === 'fulfilled') {
    engineRuntime.value = unwrap(rt.value) || {}
  }
  const detailSources = await Promise.allSettled([
    ruleClient.engineRules({ engine: 'log_audit', limit: 200 }),
    ruleClient.engineRules({ engine: 'runtime', limit: 200 }),
  ])
  const detail = []
  for (const result of detailSources) {
    if (result.status !== 'fulfilled') continue
    const payload = unwrap(result.value)
    for (const item of payload.items || []) {
      if (item.source_id) detail.push(item)
    }
  }
  detailRules.value = detail
  try {
    const artifacts = await opsClient.eventSample({ category: 'artifact', limit: 20 })
    artifactEvents.value = unwrap(artifacts).items || []
  } catch {
    artifactEvents.value = []
  }
  const failed = [s, src, q, er].filter((x) => x.status === 'rejected').length
  if (failed) error.value = `${failed} 个规则接口读取失败，对应区域显示为未知。`
  loading.value = false
}

async function toggleRule(rule) {
  togglingRule.value = rule.id
  error.value = ''
  try {
    await ruleClient.updateRuleItem(rule.id, { enabled: !rule.enabled })
    await load()
  } catch (e) {
    error.value = e?.message || '规则状态更新失败'
  } finally {
    togglingRule.value = ''
  }
}

async function sync() {
  syncing.value = true
  error.value = ''
  syncNotice.value = ''
  syncFailures.value = []
  syncProgress.value = 0
  try {
    const started = unwrap(await ruleClient.platformSync({}))
    if (started.running) {
      // Background job: poll the same route until it reports completion.
      for (let attempt = 0; attempt < 200; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 2000))
        const status = unwrap(await ruleClient.platformSyncStatus())
        syncProgress.value = Number(status.progress_percent) || 0
        const current = status.current_source ? ` · 正在同步 ${status.current_source}` : ''
        syncNotice.value = `同步中：${status.applied || 0} 已应用 / ${status.unchanged || 0} 未变化 / ${status.failed || 0} 失败${current}（${status.applied + status.unchanged + status.failed || 0}/${status.total || 0}）`
        if (!status.running) {
          syncProgress.value = 100
          syncNotice.value = `同步完成：${status.applied || 0} 个已应用，${status.unchanged || 0} 个未变化，${status.failed || 0} 个失败（共 ${status.total || 0} 个来源）。`
          syncFailures.value = (status.results || []).filter((r) => r.status === 'failed')
          break
        }
      }
    }
    await load()
  } catch (e) {
    error.value = e?.message || '规则同步失败'
  } finally {
    syncing.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.reason { max-width: 360px; overflow: hidden; text-overflow: ellipsis; color: var(--v-ink-3); }
.pagination { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
</style>
