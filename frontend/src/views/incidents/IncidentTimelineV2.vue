<template>
  <section class="sx-page incident-page">
    <header class="sx-page-head">
      <div>
        <p class="sx-kicker">ATTACK CHAIN RESPONSE</p>
        <h2 class="sx-title">鏀诲嚮閾惧缃?/h2>
        <p class="sx-subtitle">鎸?Incident 鑱氬悎璺ㄦ簮璇佹嵁銆侀樁娈垫椂闂寸嚎涓庡搷搴斿姩浣滐紱瀹℃壒浣跨敤褰撳墠鐧诲綍韬唤锛孡3 鍔ㄤ綔闇€瑕佺浜屽悕绠＄悊鍛樸€?/p>
      </div>
      <div class="sx-head-actions">
        <span class="sx-live"><i />LIVE</span>
        <button class="sx-btn" type="button" :disabled="loading" @click="loadIncidents">鍒锋柊</button>
      </div>
    </header>

    <div v-if="error" class="sx-error">{{ error }}</div>

    <section class="incident-layout">
      <aside class="sx-panel incident-sidebar">
        <div class="sidebar-head">
          <div><b>Incident</b><span>{{ formatNumber(incidentTotal) }} 鏉?/span></div>
          <div class="sidebar-filters">
            <select v-model="statusFilter" class="sx-select">
              <option value="">鍏ㄩ儴鐘舵€?/option>
              <option value="open">鏂板彂</option>
              <option value="triaged">宸插垎璇?/option>
              <option value="processing">澶勭悊涓?/option>
              <option value="resolved">宸茶В鍐?/option>
              <option value="closed">宸插叧闂?/option>
            </select>
            <select v-model="severityFilter" class="sx-select">
              <option value="">鍏ㄩ儴绛夌骇</option>
              <option value="critical">涓ラ噸</option>
              <option value="high">楂樺嵄</option>
              <option value="medium">涓嵄</option>
              <option value="low">浣庡嵄</option>
            </select>
          </div>
        </div>
        <div class="incident-list sx-scroll">
          <button
            v-for="item in filteredIncidents"
            :key="item.id"
            type="button"
            class="incident-list-row"
            :class="{ active: selected?.id === item.id }"
            @click="selectIncident(item)"
          >
            <span class="sx-badge" :class="item.severity">{{ severityLabel(item.severity) }}</span>
            <div>
              <b>{{ item.title }}</b>
              <small>{{ item.affectedAsset || item.entityId || '鏈粦瀹氳祫浜? }} 路 {{ formatShort(item.updatedAt || item.createdAt) }}</small>
              <div class="row-stage-line">
                <span v-for="stage in (item.stages || []).slice(0, 4)" :key="stage.id">{{ stage.name }}</span>
              </div>
            </div>
            <span class="row-status">{{ statusLabel(item.status) }}</span>
          </button>
          <div v-if="!filteredIncidents.length" class="sx-empty"><div><strong>鏆傛棤鍖归厤 Incident</strong>璋冩暣绛涢€夋潯浠舵垨绛夊緟鍏宠仈閾剧敓鎴愩€?/div></div>
        </div>
      </aside>

      <main class="incident-main">
        <div v-if="!selected" class="sx-panel no-selection">
          <div class="sx-empty"><div><strong>閫夋嫨宸︿晶 Incident</strong>鏌ョ湅闃舵鏃堕棿绾裤€佽瘉鎹拰鍝嶅簲鍔ㄤ綔銆?/div></div>
        </div>
        <template v-else>
          <section class="sx-panel incident-hero">
            <div class="incident-hero-main">
              <div class="incident-hero-top">
                <span class="sx-badge" :class="selected.severity">{{ severityLabel(selected.severity) }}</span>
                <span class="sx-badge muted">{{ selected.id }}</span>
              </div>
              <h3>{{ selected.title }}</h3>
              <p>{{ selected.affectedAsset || selected.entityId || '鏈粦瀹氳祫浜? }} 路 鍒涘缓浜?{{ formatTime(selected.createdAt) }} 路 鏇存柊浜?{{ formatTime(selected.updatedAt) }}</p>
            </div>
            <div class="incident-hero-actions">
              <select class="sx-select" :value="selected.status" :disabled="updatingStatus" @change="updateStatus($event.target.value)">
                <option v-for="status in statuses" :key="status" :value="status">{{ statusLabel(status) }}</option>
              </select>
            </div>
          </section>

          <section class="incident-facts">
            <div><span>婧?IP</span><b class="sx-mono">{{ selected.sourceIPs?.join(', ') || '-' }}</b></div>
            <div><span>鍙楀 IP</span><b class="sx-mono">{{ selected.victimIPs?.join(', ') || '-' }}</b></div>
            <div><span>瀹炰綋 / Agent</span><b>{{ selected.entityId || selected.affectedAsset || '-' }}</b></div>
            <div><span>璇佹嵁</span><b>{{ selected.evidence?.length || 0 }} 鏉?/b></div>
            <div><span>寤鸿鍔ㄤ綔</span><b>{{ selected.recommendedAction || '寰呯爺鍒? }}</b></div>
          </section>

          <section class="sx-panel stage-ribbon-panel">
            <div class="sx-panel-head">
              <div class="sx-panel-title">鏀诲嚮闃舵</div>
              <span class="sx-panel-meta">闃舵鐘舵€佹潵鑷?Incident 鍏宠仈閾?/span>
            </div>
            <div class="sx-panel-body">
              <div class="sx-stage-ribbon">
                <div v-for="stage in stageRibbon" :key="stage.key" class="sx-stage" :class="{ active: stage.active }">
                  <span>{{ stage.label }}</span>
                  <strong>{{ stage.count }}</strong>
                  <i :style="{ width: stage.active ? '100%' : '0%' }" />
                </div>
              </div>
            </div>
          </section>

          <div class="incident-detail-grid">
            <article class="sx-panel timeline-panel">
              <div class="sx-panel-head">
                <div class="sx-panel-title">闃舵鏃堕棿绾?/div>
                <span class="sx-panel-meta">{{ groups.length }} 涓樁娈?路 {{ selected.evidence?.length || 0 }} 鏉¤瘉鎹?/span>
              </div>
              <div v-if="groups.length" class="timeline sx-scroll">
                <div v-for="group in groups" :key="group.id" class="timeline-group">
                  <div class="timeline-marker"><i /><span>{{ group.name || stageLabel(group.stage) }}</span><small>{{ group.tactic || '' }}</small></div>
                  <div class="timeline-body">
                    <div v-if="group.evidence.length" class="timeline-evidence">
                      <button v-for="evidence in group.evidence" :key="evidence.id" type="button" class="timeline-evidence-row" @click="toggleEvidence(group.id)">
                        <span class="sx-badge info">{{ evidence.sourceModule || 'xdr' }}</span>
                        <div><b>{{ evidence.title }}</b><small>{{ evidence.summary }}</small></div>
                        <time>{{ formatTime(evidence.time) }}</time>
                      </button>
                      <pre v-if="expandedEvidence === group.id" class="evidence-raw sx-scroll">{{ prettyEvidence(group.evidence[0]) }}</pre>
                    </div>
                    <div v-else class="timeline-empty">璇ラ樁娈垫殏鏃犲彲灞曠ず璇佹嵁銆?/div>
                  </div>
                </div>
              </div>
              <div v-else class="sx-empty"><div><strong>鏆傛棤闃舵璇佹嵁</strong>Incident 灏氭湭浜х敓鍙睍绀虹殑鍏宠仈閾俱€?/div></div>
            </article>

            <aside class="incident-side-stack">
              <article class="sx-panel response-panel">
                <div class="sx-panel-head">
                  <div class="sx-panel-title">鍝嶅簲澶勭疆</div>
                  <span class="sx-panel-meta">{{ actionsForIncident.length }} 鏉¤褰?/span>
                </div>
                <div class="sx-panel-body">
                  <div class="response-form">
                    <div class="response-form-row">
                      <label><span>鍔ㄤ綔</span>
                        <select v-model="actionForm.action" class="sx-select">
                          <option value="observe">瑙傚療</option>
                          <option value="block_ip">灏佺 IP</option>
                          <option value="isolate_host">涓绘満闅旂</option>
                          <option value="process_kill">缁堟杩涚▼</option>
                          <option value="file_delete">闅旂鏂囦欢</option>
                          <option value="account_disable">绂佺敤璐﹀彿</option>
                          <option value="namespace_isolate">瀹瑰櫒缃戠粶闅旂</option>
                        </select>
                      </label>
                      <label><span>鐩爣</span><input v-model.trim="actionForm.target" class="sx-input" placeholder="IP / PID / 璺緞 / 鐢ㄦ埛鍚? /></label>
                    </div>
                    <label><span>Agent ID</span><input v-model.trim="actionForm.agent_id" class="sx-input" placeholder="g5-real-agent" /></label>
                    <label><span>鍘熷洜</span><input v-model.trim="actionForm.reason" class="sx-input" placeholder="璇存槑澶勭疆渚濇嵁" /></label>
                    <div class="response-form-actions">
                      <span v-if="actionMessage" :class="['response-message', actionMessageType]">{{ actionMessage }}</span>
                      <button class="sx-btn primary" type="button" :disabled="creatingAction || !canCreateAction" @click="createAction">{{ creatingAction ? '鎻愪氦涓€? : '鎻愪氦瀹℃壒' }}</button>
                    </div>
                  </div>

                  <div v-if="actionsForIncident.length" class="action-list">
                    <div v-for="action in actionsForIncident" :key="action.id" class="action-row">
                      <div>
                        <b>{{ actionLabel(action.action) }}</b>
                        <small>{{ action.target || '-' }} 路 {{ action.risk }} 路 {{ action.requested_by }}</small>
                        <em v-if="action.error">{{ action.error }}</em>
                      </div>
                      <span class="sx-badge" :class="actionTone(action.status)">{{ actionStatusLabel(action.status) }}</span>
                      <div class="action-buttons">
                        <button v-if="action.status === 'pending_approval'" class="sx-btn" type="button" :disabled="updatingAction === action.id" @click="approveAction(action)">瀹℃壒</button>
                        <button v-if="canRollback(action)" class="sx-btn ghost" type="button" :disabled="updatingAction === action.id" @click="rollbackAction(action)">鍥炴粴</button>
                      </div>
                    </div>
                  </div>
                  <div v-else class="sx-muted response-empty">璇?Incident 杩樻病鏈夊搷搴斿姩浣溿€?/div>
                </div>
              </article>

              <article class="sx-panel evidence-panel">
                <div class="sx-panel-head">
                  <div class="sx-panel-title">璇佹嵁鍖?/div>
                  <span class="sx-panel-meta">{{ bundlesForIncident.length }} 涓?/span>
                </div>
                <div class="sx-panel-body">
                  <div class="evidence-actions">
                    <button class="sx-btn primary" type="button" :disabled="creatingBundle || !selected.evidence?.length" @click="createBundle">{{ creatingBundle ? '鎵撳寘涓€? : '鐢熸垚璇佹嵁鍖? }}</button>
                    <span class="sx-muted">浣跨敤褰撳墠 Incident 鐨勮瘉鎹簨浠?/span>
                  </div>
                  <div v-if="bundleMessage" class="response-message" :class="bundleMessageType">{{ bundleMessage }}</div>
                  <div v-if="bundlesForIncident.length" class="bundle-list">
                    <div v-for="bundle in bundlesForIncident" :key="bundle.id" class="bundle-row">
                      <div><b class="sx-mono">{{ bundle.id }}</b><small>{{ formatSize(bundle.size) }} 路 {{ formatTime(bundle.created_at) }}</small></div>
                      <button class="sx-btn" type="button" @click="downloadBundle(bundle)">涓嬭浇</button>
                    </div>
                  </div>
                  <div v-else class="sx-muted evidence-empty">灏氭湭鐢熸垚璇佹嵁鍖呫€?/div>
                </div>
              </article>
            </aside>
          </div>
        </template>
      </main>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { attackWorkbenchClient, evidenceClient, responseClient } from '../../api/domain'
import { incidentsAPI } from '../../api/events'
import { severityLabel, stageLabel } from '../../domain/attack-labels'
import { normalizeIncident, normalizeIncidents } from '../../domain/incidents'

const route = useRoute()
const incidents = ref([])
const incidentTotal = ref(0)
const selected = ref(null)
const loading = ref(false)
const updatingStatus = ref(false)
const updatingAction = ref('')
const creatingAction = ref(false)
const creatingBundle = ref(false)
const error = ref('')
const actionMessage = ref('')
const actionMessageType = ref('success')
const bundleMessage = ref('')
const bundleMessageType = ref('success')
const expandedEvidence = ref('')
const statusFilter = ref('')
const severityFilter = ref('')
const actions = ref([])
const bundles = ref([])
const statuses = ['open', 'triaged', 'processing', 'resolved', 'closed']
const actionForm = reactive({ action: 'observe', target: '', agent_id: '', reason: '' })

const stageDefinitions = [
  ['detection', '妫€娴嬪懡涓?], ['recon', '渚﹀療'], ['initial_access', '鍒濆璁块棶'], ['execution', '鎵ц'],
  ['persistence', '鎸佷箙鍖?], ['privilege_escalation', '鎻愭潈'], ['lateral_movement', '妯悜绉诲姩'],
  ['command_and_control', '鍛戒护鎺у埗'], ['exfiltration', '澶栦紶'], ['impact', '褰卞搷'],
]

const filteredIncidents = computed(() => incidents.value.filter((item) => {
  if (statusFilter.value && item.status !== statusFilter.value) return false
  if (severityFilter.value && item.severity !== severityFilter.value) return false
  return true
}))
const groups = computed(() => {
  if (!selected.value) return []
  if (selected.value.stageGroups?.length) return selected.value.stageGroups
  const evidence = selected.value.evidence || []
  return (selected.value.stages || []).map((stage) => ({
    ...stage,
    id: stage.id,
    stage: stage.stageKey,
    name: stage.name,
    tactic: stage.tactic,
    evidence: evidence.filter((item) => item.stage === stage.stageKey),
  }))
})
const stageRibbon = computed(() => {
  const counts = {}
  for (const stage of selected.value?.stages || []) counts[stage.stageKey] = (counts[stage.stageKey] || 0) + 1
  return stageDefinitions.map(([key, label]) => ({ key, label, active: Boolean(counts[key]), count: counts[key] || 0 }))
})
const actionsForIncident = computed(() => actions.value.filter((item) => item.incident_id === selected.value?.id))
const bundlesForIncident = computed(() => bundles.value.filter((item) => item.incident_id === selected.value?.id))
const canCreateAction = computed(() => Boolean(actionForm.agent_id && (actionForm.action === 'observe' || actionForm.target)))

function unwrap(response) { return response?.data?.data ?? response?.data ?? response ?? {} }
function formatNumber(value) { return Number(value || 0).toLocaleString('zh-CN') }
function formatTime(value) { if (!value) return '-'; const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false }) }
function formatShort(value) { if (!value) return '-'; const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) }
function formatSize(value) { const size = Number(value || 0); return size > 1024 ? `${(size / 1024).toFixed(1)} KB` : `${size} B` }
function statusLabel(value) { return ({ new: '鏂板彂', open: '鏂板彂', triaged: '宸插垎璇?, processing: '澶勭悊涓?, resolved: '宸茶В鍐?, closed: '宸插叧闂? })[value] || value || '-' }
function actionStatusLabel(value) { return ({ pending_approval: '寰呭鎵?, approved: '宸叉壒鍑?, executed: '宸叉墽琛?, failed: '澶辫触', rolled_back: '宸插洖婊? })[value] || value || '-' }
function actionTone(value) { return ({ pending_approval: 'medium', approved: 'info', executed: 'low', failed: 'critical', rolled_back: 'muted' })[value] || 'muted' }
function actionLabel(value) { return ({ observe: '瑙傚療', block_ip: '灏佺 IP', isolate_host: '涓绘満闅旂', process_kill: '缁堟杩涚▼', file_delete: '闅旂鏂囦欢', account_disable: '绂佺敤璐﹀彿', namespace_isolate: '瀹瑰櫒闅旂' })[value] || value || '-' }
function canRollback(action) { return ['executed', 'failed'].includes(action.status) && ['block_ip', 'isolate_host', 'file_delete', 'account_disable', 'namespace_isolate'].includes(action.action) }
function prettyEvidence(evidence) { try { return JSON.stringify(evidence?.raw || evidence, null, 2) } catch { return String(evidence?.raw || '') } }
function toggleEvidence(id) { expandedEvidence.value = expandedEvidence.value === id ? '' : id }

async function loadIncidents() {
  loading.value = true
  error.value = ''
  try {
    const data = unwrap(await attackWorkbenchClient.incidents({ limit: 20 }))
    incidents.value = normalizeIncidents(Array.isArray(data.items) ? data.items : [])
    incidentTotal.value = Number(data.total ?? incidents.value.length) || incidents.value.length
    const wanted = String(route.query.id || '')
    const current = incidents.value.find((item) => item.id === wanted) || incidents.value.find((item) => item.id === selected.value?.id) || incidents.value[0]
    if (current) await selectIncident(current)
  } catch (cause) {
    error.value = 'Incident 鏁版嵁鍔犺浇澶辫触锛岃妫€鏌ュ悗绔繛鎺ャ€?
  } finally {
    loading.value = false
  }
}

async function selectIncident(item) {
  if (!item) return
  selected.value = item
  const evidenceAgent = (item.evidence || []).map((evidence) => evidence.entityId).find((value) => value && !/^(inc-|hyp-)/.test(value))
  actionForm.agent_id = evidenceAgent || item.affectedAsset || item.entityId || ''
  try {
    const detail = unwrap(await attackWorkbenchClient.incident(item.id))
    selected.value = normalizeIncident(Object.keys(detail).length ? detail : item)
  } catch { /* keep list row */ }
  await Promise.all([loadActions(), loadBundles()])
}

async function loadActions() {
  try {
    const data = unwrap(await responseClient.actions({ limit: 100 }))
    actions.value = Array.isArray(data.items) ? data.items : []
  } catch { actions.value = [] }
}

async function loadBundles() {
  try {
    const data = unwrap(await evidenceClient.bundles({ limit: 100 }))
    bundles.value = Array.isArray(data.items) ? data.items : []
  } catch { bundles.value = [] }
}

async function updateStatus(status) {
  if (!selected.value || status === selected.value.status) return
  updatingStatus.value = true
  try {
    await incidentsAPI.updateStatus(selected.value.id, status)
    selected.value = { ...selected.value, status }
    await loadIncidents()
  } catch {
    error.value = 'Incident 鐘舵€佹洿鏂板け璐ャ€?
  } finally {
    updatingStatus.value = false
  }
}

async function createAction() {
  if (!selected.value || !canCreateAction.value) return
  creatingAction.value = true
  actionMessage.value = ''
  try {
    await responseClient.create({
      incident_id: selected.value.id,
      agent_id: actionForm.agent_id,
      action: actionForm.action,
      target: actionForm.action === 'observe' ? actionForm.agent_id : actionForm.target,
      reason: actionForm.reason || `Incident ${selected.value.id} 浜哄伐澶勭疆`,
      ttl_seconds: 300,
    })
    actionMessage.value = '宸叉彁浜ゅ鎵归槦鍒椼€?
    actionMessageType.value = 'success'
    actionForm.target = ''
    actionForm.reason = ''
    await loadActions()
  } catch (cause) {
    actionMessage.value = cause?.message || '鍝嶅簲鍔ㄤ綔鎻愪氦澶辫触銆?
    actionMessageType.value = 'error'
  } finally {
    creatingAction.value = false
  }
}

async function approveAction(action) {
  updatingAction.value = action.id
  try {
    await responseClient.approve(action.id, {})
    await loadActions()
  } catch (cause) {
    error.value = cause?.message || '瀹℃壒澶辫触锛氶渶瑕佷笌鍙戣捣浜轰笉鍚岀殑绠＄悊鍛樿韩浠姐€?
  } finally {
    updatingAction.value = ''
  }
}

async function rollbackAction(action) {
  updatingAction.value = action.id
  try {
    await responseClient.rollback(action.id)
    await loadActions()
  } catch (cause) {
    error.value = cause?.message || '鍥炴粴澶辫触銆?
  } finally {
    updatingAction.value = ''
  }
}

async function createBundle() {
  if (!selected.value || !selected.value.evidence?.length) return
  creatingBundle.value = true
  bundleMessage.value = ''
  try {
    const eventUIDs = [...new Set(selected.value.evidence.map((item) => item.id).filter(Boolean))]
    const result = unwrap(await evidenceClient.createBundle({
      incident_id: selected.value.id,
      agent_id: selected.value.entityId || '',
      event_uids: eventUIDs,
      note: `Incident ${selected.value.id} evidence bundle`,
    }))
    bundleMessage.value = `璇佹嵁鍖呭凡鐢熸垚锛?{result.id || '宸叉彁浜?}`
    bundleMessageType.value = 'success'
    await loadBundles()
  } catch (cause) {
    bundleMessage.value = cause?.message || '璇佹嵁鍖呯敓鎴愬け璐ワ細璇佹嵁浜嬩欢鍙兘涓嶅湪 Event v2 瀛樺偍涓€?
    bundleMessageType.value = 'error'
  } finally {
    creatingBundle.value = false
  }
}

async function downloadBundle(bundle) {
  try {
    const blob = await evidenceClient.download(bundle.id)
    const url = URL.createObjectURL(blob instanceof Blob ? blob : new Blob([blob]))
    const link = document.createElement('a')
    link.href = url
    link.download = `${bundle.id}.json`
    link.click()
    URL.revokeObjectURL(url)
  } catch {
    error.value = '璇佹嵁鍖呬笅杞藉け璐ャ€?
  }
}

onMounted(() => {
  loadActions()
  loadBundles()
  loadIncidents()
})
</script>

<style scoped>
.incident-page { gap: 14px; }
.incident-layout { display: grid; grid-template-columns: 306px minmax(0, 1fr); gap: 14px; min-height: 620px; }
.incident-sidebar { display: flex; min-height: 620px; flex-direction: column; }
.sidebar-head { display: grid; gap: 8px; padding: 11px 12px; border-bottom: 1px solid var(--sx-line-soft); }
.sidebar-head > div:first-child { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.sidebar-head b { color: var(--sx-text); font-size: 12px; }
.sidebar-head span { color: var(--sx-text-3); font-size: 10px; }
.sidebar-filters { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
.incident-list { flex: 1; }
.incident-list-row { display: grid; width: 100%; grid-template-columns: 46px minmax(0, 1fr) auto; align-items: start; gap: 8px; padding: 10px 12px; border: 0; border-bottom: 1px solid var(--sx-line-soft); background: transparent; color: inherit; text-align: left; cursor: pointer; transition: background var(--transition-fast); }
.incident-list-row:hover, .incident-list-row.active { background: var(--sx-accent-soft); }
.incident-list-row.active { box-shadow: inset 3px 0 var(--sx-accent); }
.incident-list-row > div { min-width: 0; }
.incident-list-row b { display: block; overflow: hidden; color: var(--sx-text); font-size: 11px; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
.incident-list-row small { display: block; overflow: hidden; margin-top: 2px; color: var(--sx-text-3); font-size: 9px; text-overflow: ellipsis; white-space: nowrap; }
.row-stage-line { display: flex; flex-wrap: wrap; gap: 3px; margin-top: 4px; }
.row-stage-line span { padding: 1px 4px; border-radius: 3px; background: var(--sx-surface-3); color: var(--sx-text-2); font-size: 8px; }
.row-status { color: var(--sx-text-3); font-size: 9px; white-space: nowrap; }
.incident-main { display: grid; min-width: 0; align-content: start; gap: 12px; }
.no-selection { min-height: 320px; }
.incident-hero { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 15px 17px; }
.incident-hero-top { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
.incident-hero h3 { margin: 7px 0 0; color: var(--sx-text); font-size: 19px; font-weight: 720; letter-spacing: -0.03em; }
.incident-hero p { margin: 4px 0 0; color: var(--sx-text-3); font-size: 10px; }
.incident-hero-actions { flex: 0 0 auto; }
.incident-facts { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 8px; }
.incident-facts > div { min-width: 0; padding: 9px 11px; border: 1px solid var(--sx-line); border-radius: var(--sx-radius-sm); background: var(--sx-surface); }
.incident-facts span { display: block; color: var(--sx-text-3); font-size: 9px; }
.incident-facts b { display: block; overflow: hidden; margin-top: 2px; color: var(--sx-text); font-size: 11px; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
.incident-detail-grid { display: grid; grid-template-columns: minmax(0, 1.55fr) minmax(300px, 0.9fr); gap: 12px; align-items: start; }
.timeline { max-height: 620px; padding: 12px 14px 16px; }
.timeline-group { display: grid; grid-template-columns: 116px minmax(0, 1fr); gap: 10px; }
.timeline-marker { position: relative; display: flex; flex-direction: column; gap: 2px; padding: 2px 0 18px 16px; color: var(--sx-accent); font-size: 10px; font-weight: 650; }
.timeline-marker::before { content: ""; position: absolute; top: 1px; left: 0; width: 7px; height: 7px; border-radius: 50%; background: var(--sx-accent); box-shadow: 0 0 0 3px var(--sx-accent-soft); }
.timeline-marker::after { content: ""; position: absolute; top: 12px; bottom: 0; left: 3px; width: 1px; background: var(--sx-line); }
.timeline-group:last-child .timeline-marker::after { display: none; }
.timeline-marker small { color: var(--sx-text-3); font-size: 8px; font-weight: 500; }
.timeline-body { min-width: 0; padding-bottom: 12px; }
.timeline-evidence { display: grid; gap: 5px; }
.timeline-evidence-row { display: grid; grid-template-columns: 58px minmax(0, 1fr) 90px; align-items: center; gap: 8px; width: 100%; padding: 7px 8px; border: 1px solid var(--sx-line-soft); border-radius: 5px; background: var(--sx-surface-2); color: inherit; text-align: left; cursor: pointer; }
.timeline-evidence-row:hover { border-color: var(--sx-accent-line); }
.timeline-evidence-row > div { min-width: 0; }
.timeline-evidence-row b { display: block; overflow: hidden; color: var(--sx-text); font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.timeline-evidence-row small { display: block; overflow: hidden; margin-top: 1px; color: var(--sx-text-3); font-size: 9px; text-overflow: ellipsis; white-space: nowrap; }
.timeline-evidence-row time { color: var(--sx-text-3); font-size: 8px; text-align: right; }
.evidence-raw { max-height: 220px; margin: 4px 0 0; padding: 9px; overflow: auto; border-radius: 5px; background: #071a2d; color: #c7e7ff; font-family: var(--sx-font-mono); font-size: 9px; line-height: 1.5; }
.timeline-empty { padding: 8px 0; color: var(--sx-text-3); font-size: 10px; }
.incident-side-stack { display: grid; gap: 12px; }
.response-form { display: grid; gap: 7px; }
.response-form-row { display: grid; grid-template-columns: 1fr 1.1fr; gap: 7px; }
.response-form label { display: grid; gap: 3px; }
.response-form label > span { color: var(--sx-text-3); font-size: 9px; }
.response-form-actions { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.response-message { margin-top: 6px; font-size: 10px; }
.response-message.success { color: var(--sx-success); }
.response-message.error { color: var(--sx-danger); }
.response-empty { margin-top: 10px; font-size: 10px; }
.action-list { display: grid; gap: 5px; margin-top: 10px; }
.action-row { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; align-items: center; gap: 6px; padding: 7px 8px; border: 1px solid var(--sx-line-soft); border-radius: 5px; background: var(--sx-surface-2); }
.action-row > div:first-child { min-width: 0; }
.action-row b { display: block; color: var(--sx-text); font-size: 10px; }
.action-row small { display: block; overflow: hidden; color: var(--sx-text-3); font-size: 8px; text-overflow: ellipsis; white-space: nowrap; }
.action-row em { display: block; color: var(--sx-danger); font-size: 8px; font-style: normal; }
.action-buttons { display: flex; gap: 4px; }
.action-buttons .sx-btn { height: 25px; padding: 0 7px; font-size: 9px; }
.evidence-actions { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.evidence-actions .sx-muted { font-size: 9px; }
.evidence-empty { margin-top: 9px; font-size: 10px; }
.bundle-list { display: grid; gap: 5px; margin-top: 8px; }
.bundle-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 6px 8px; border: 1px solid var(--sx-line-soft); border-radius: 5px; background: var(--sx-surface-2); }
.bundle-row b { display: block; color: var(--sx-text); font-size: 9px; }
.bundle-row small { display: block; color: var(--sx-text-3); font-size: 8px; }
.bundle-row .sx-btn { height: 25px; padding: 0 7px; font-size: 9px; }

@media (max-width: 1180px) {
  .incident-layout { grid-template-columns: 260px minmax(0, 1fr); }
  .incident-detail-grid { grid-template-columns: 1fr; }
  .incident-facts { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 900px) {
  .incident-layout { grid-template-columns: 1fr; }
  .incident-sidebar { min-height: 260px; max-height: 360px; }
  .incident-list { max-height: 240px; }
  .incident-facts { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 620px) {
  .incident-hero { flex-direction: column; }
  .incident-facts { grid-template-columns: 1fr; }
  .timeline-group { grid-template-columns: 1fr; }
  .timeline-marker::after { display: none; }
  .response-form-row { grid-template-columns: 1fr; }
}
</style>

