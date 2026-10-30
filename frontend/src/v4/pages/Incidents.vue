<template>
  <section class="v-page">
    <header class="v-head">
      <div>
        <p class="v-eyebrow">ATTACK CHAIN</p>
        <h1>攻击链处置</h1>
        <p>按 Incident 聚合事件依据。默认已分诊；填写处理人与处理意见后进入处理中，再次打开详情才能闭环。</p>
      </div>
      <div class="v-head-actions">
        <button class="v-btn" type="button" :disabled="loading" @click="load">{{ loading ? '刷新中…' : '刷新' }}</button>
      </div>
    </header>

    <div v-if="error" class="v-error">{{ error }}</div>

    <section class="v-grid c4">
      <article class="v-stat"><span class="v-stat-label"><i />已分诊</span><strong class="v-stat-value">{{ counts.triage }}</strong><span class="v-stat-note">新发现，等待填写处理意见</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />处理中</span><strong class="v-stat-value warning">{{ counts.processing }}</strong><span class="v-stat-note">已填写处理意见</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />闭环</span><strong class="v-stat-value success">{{ counts.closed }}</strong><span class="v-stat-note">人工关闭，保留审计</span></article>
      <article class="v-stat"><span class="v-stat-label"><i />高 / 严重</span><strong class="v-stat-value danger">{{ counts.high }}</strong><span class="v-stat-note">未闭环中的高危项</span></article>
    </section>

    <article class="v-panel">
      <div class="v-panel-body">
        <div class="v-toolbar">
          <label class="v-field grow"><span>检索</span><input v-model.trim="query" class="v-input" placeholder="标题 / 受害服务器 / 实体"></label>
          <label class="v-field"><span>状态</span>
            <select v-model="statusFilter" class="v-select">
              <option value="active">未闭环</option><option value="">全部</option>
              <option value="triage">已分诊</option><option value="processing">处理中</option><option value="closed">闭环</option>
            </select>
          </label>
          <label class="v-field"><span>等级</span>
            <select v-model="severityFilter" class="v-select">
              <option value="">全部</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option>
            </select>
          </label>
        </div>
      </div>
      <div class="v-table-wrap">
        <table class="v-table">
          <thead><tr><th>等级</th><th>标题</th><th>受害服务器</th><th>阶段</th><th>状态</th><th>最近更新</th><th class="actions" /></tr></thead>
          <tbody>
            <tr v-for="i in filtered" :key="i.id" class="clickable" @click="open(i)">
              <td><span class="v-badge" :class="i.severity">{{ severityLabel(i.severity) }}</span></td>
              <td class="title-cell"><b>{{ i.title }}</b><small>{{ i.id }}</small></td>
              <td>{{ i.affectedAsset || '-' }}</td>
              <td><span v-for="s in (i.stages || []).slice(0, 3)" :key="s.id" class="stage-chip">{{ s.name }}</span></td>
              <td><span class="v-badge" :class="statusTone(i.status)">{{ statusLabel(i.status) }}</span></td>
              <td class="num">{{ shortTime(i.updatedAt || i.createdAt) }}</td>
              <td class="actions"><button class="v-btn sm" type="button" @click.stop="open(i)">详情</button></td>
            </tr>
          </tbody>
        </table>
        <div v-if="!filtered.length" class="v-table-empty">
          <strong>{{ loading ? '正在读取 Incident' : '没有匹配的 Incident' }}</strong>
          <span v-if="!loading">调整筛选，或等待关联链生成。</span>
        </div>
      </div>
    </article>

    <div v-if="selected" class="v-scrim" @click.self="selected = null">
      <aside class="v-drawer incident-drawer">
        <div class="v-drawer-head">
          <div>
            <p class="v-eyebrow">INCIDENT</p>
            <div class="v-panel-title">{{ selected.title }}</div>
          </div>
          <button class="v-btn ghost" type="button" @click="selected = null">关闭</button>
        </div>
        <div class="v-drawer-body detail">
          <div class="detail-top">
            <span class="v-badge" :class="selected.severity">{{ severityLabel(selected.severity) }}</span>
            <span class="v-badge" :class="statusTone(selected.status)">{{ statusLabel(selected.status) }}</span>
          </div>

          <dl class="v-kv">
            <dt>受害服务器</dt><dd>{{ selected.affectedAsset || '-' }}</dd>
            <dt>处理人</dt><dd>{{ selected.assignee || '未填写' }}</dd>
            <dt>首次出现</dt><dd>{{ shortTime(selected.createdAt) }}</dd>
            <dt>最近更新</dt><dd>{{ shortTime(selected.updatedAt) }}</dd>
          </dl>

          <section v-if="statusGroup(selected.status) !== 'closed'">
            <h3>处理</h3>
            <label class="v-field"><span>处理人</span><input v-model.trim="handler" class="v-input" placeholder="填写实际处理人姓名"></label>
            <label v-if="statusGroup(selected.status) === 'triage'" class="v-field"><span>处理意见</span><textarea v-model.trim="opinion" class="v-input" rows="3" placeholder="填写判断依据、处置思路或交接信息"></textarea></label>
            <label v-else class="v-field"><span>关闭原因</span><input v-model.trim="closeReason" class="v-input" placeholder="误报 / 已修复 / 风险接受 / 重复告警"></label>
            <div class="disposition">
              <span class="disposition-label">处置动作</span>
              <button class="v-btn sm" :class="{ primary: disposition === 'protect' }" type="button" @click="disposition = 'protect'">开启防护</button>
              <button class="v-btn sm" :class="{ primary: disposition === 'observe' }" type="button" @click="disposition = 'observe'">观察</button>
            </div>
            <button class="v-btn primary save-btn" type="button" :disabled="saving" @click="save">
              {{ saving ? '保存中…' : statusGroup(selected.status) === 'triage' ? '保存并转处理中' : '保存并闭环' }}
            </button>
          </section>

          <section v-else>
            <h3>闭环信息</h3>
            <dl class="v-kv">
              <dt>处理人</dt><dd>{{ selected.assignee || '未填写' }}</dd>
              <dt>闭环时间</dt><dd>{{ shortTime(selected.resolvedAt || selected.updatedAt) }}</dd>
            </dl>
          </section>

          <section>
            <h3>处理记录</h3>
            <ul v-if="notes.length" class="notes">
              <li v-for="n in notes" :key="n.id"><b>{{ n.author }}</b> {{ n.body }} <small class="v-dim">{{ shortTime(n.created_at) }}</small></li>
            </ul>
            <p v-else class="v-dim">暂无处理记录</p>
          </section>

          <section>
            <h3>事件依据</h3>
            <div v-if="!stageGroups.length" class="v-empty"><div><strong>暂无事件依据</strong>关联链生成后展示。</div></div>
            <div v-else class="timeline">
              <div v-for="g in stageGroups" :key="g.id" class="tl-group">
                <div class="tl-head">
                  <span class="tl-dot" />
                  <b>{{ g.name }}</b>
                  <small>{{ g.count }} 条 · {{ shortTime(g.firstSeen) }}</small>
                </div>
                <div v-for="ev in g.evidence" :key="ev.id" class="tl-ev">
                  <span class="v-badge info">{{ ev.sourceModule || ev.detectionSurface || '未知来源' }}</span>
                  <span class="tl-ev-main">
                    <b>{{ ev.title || ev.ruleName || '事件证据' }}</b>
                    <small>{{ ev.summary }}</small>
                    <small v-if="ev.whyStage" class="v-dim">判定：{{ ev.whyStage.reason || ev.whyStage.source }} · 置信度 {{ ev.whyStage.confidence }}</small>
                  </span>
                  <time>{{ shortTime(ev.time) }}</time>
                </div>
              </div>
            </div>
          </section>
        </div>
      </aside>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { incidentsAPI } from '../../api/events'
import { assetAgentClient } from '../../api/domain'
import { normalizeIncidents } from '../../domain/incidents'
import { severityLabel } from '../../domain/attack-labels'
import { formatChinaDateTime } from '../../shared/time'

const loading = ref(false)
const error = ref('')
const items = ref([])
const agents = ref([])
const query = ref('')
const statusFilter = ref('active')
const severityFilter = ref('')
const selected = ref(null)
const stageGroups = ref([])
const notes = ref([])
const handler = ref('')
const opinion = ref('')
const closeReason = ref('')
const disposition = ref('')
const saving = ref(false)

const agentNameById = computed(() => {
  const map = new Map()
  for (const agent of agents.value) {
    const name = agent.display_name || agent.hostname || agent.agent_id
    if (agent.agent_id && name) map.set(String(agent.agent_id), name)
  }
  return map
})

const normalized = computed(() => normalizeIncidents(items.value).map((item) => ({
  ...item,
  affectedAsset: agentNameById.value.get(String(item.agentId || '')) || item.affectedAsset,
})))

function unwrap(response) { return response?.data?.data ?? response?.data ?? response ?? {} }

function statusGroup(status) {
  const value = String(status || '').toLowerCase()
  if (['closed', 'resolved'].includes(value)) return 'closed'
  if (value === 'processing') return 'processing'
  return 'triage'
}

const counts = computed(() => {
  const result = { triage: 0, processing: 0, closed: 0, high: 0 }
  for (const item of normalized.value) {
    const group = statusGroup(item.status)
    result[group] += 1
    if (group !== 'closed' && ['critical', 'high'].includes(item.severity)) result.high += 1
  }
  return result
})

const filtered = computed(() => {
  const q = query.value.toLowerCase()
  return normalized.value.filter((item) => {
    const group = statusGroup(item.status)
    if (statusFilter.value === 'active' && group === 'closed') return false
    if (statusFilter.value && statusFilter.value !== 'active' && group !== statusFilter.value) return false
    if (severityFilter.value && item.severity !== severityFilter.value) return false
    if (!q) return true
    return [item.title, item.affectedAsset, item.entityId, item.id].some((v) => String(v || '').toLowerCase().includes(q))
  })
})

function statusLabel(value) {
  return ({ new: '已分诊', open: '已分诊', triaged: '已分诊', processing: '处理中', resolved: '闭环', closed: '闭环' })[value] || value || '-'
}
function statusTone(value) {
  const group = statusGroup(value)
  return ({ triage: 'medium', processing: 'info', closed: 'muted' })[group] || 'muted'
}
function shortTime(value) { return value ? formatChinaDateTime(value) : '-' }

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [incidentResult, agentResult] = await Promise.allSettled([
      incidentsAPI.list({ limit: 200, live: 1 }),
      assetAgentClient.agents({ limit: 500 }),
    ])
    if (incidentResult.status === 'fulfilled') {
      items.value = incidentResult.value.items || []
    } else {
      throw incidentResult.reason
    }
    agents.value = agentResult.status === 'fulfilled' ? (unwrap(agentResult.value).items || []) : []
  } catch (e) {
    error.value = e?.message || 'Incident 读取失败'
  } finally {
    loading.value = false
  }
}

async function open(row) {
  selected.value = row
  handler.value = row.assignee || ''
  opinion.value = ''
  closeReason.value = ''
  disposition.value = ''
  stageGroups.value = []
  notes.value = []
  try {
    const detail = await incidentsAPI.detail(row.id)
    const merged = normalizeIncidents([{ ...row, ...(detail.incident || {}), stage_groups: detail.stageGroups || [] }])[0]
    if (merged) {
      selected.value = merged
      stageGroups.value = merged.stageGroups || []
      handler.value = merged.assignee || ''
    }
  } catch { /* keep list row */ }
  try {
    const payload = await incidentsAPI.notes(row.id)
    notes.value = payload.items || []
  } catch {
    notes.value = []
  }
}

function actionLabel(value) {
  return ({ protect: '开启防护', observe: '观察' })[value] || value || ''
}

async function save() {
  if (!selected.value) return
  const group = statusGroup(selected.value.status)
  if (!handler.value.trim()) {
    error.value = '请填写处理人'
    return
  }
  if (!disposition.value) {
    error.value = '请选择处置动作：开启防护或观察'
    return
  }
  if (group === 'triage' && !opinion.value.trim()) {
    error.value = '请填写处理意见'
    return
  }
  if (group === 'processing' && !closeReason.value.trim()) {
    error.value = '请填写关闭原因'
    return
  }
  saving.value = true
  error.value = ''
  try {
    await incidentsAPI.assign(selected.value.id, handler.value.trim())
    if (group === 'triage') {
      await incidentsAPI.addNote(selected.value.id, `处置动作：${actionLabel(disposition.value)}。${opinion.value.trim()}`)
    } else {
      await incidentsAPI.updateStatus(selected.value.id, 'closed', { reason: closeReason.value.trim() })
    }
    await load()
    const updated = normalized.value.find((item) => item.id === selected.value.id)
    if (updated) await open(updated)
  } catch (e) {
    error.value = e?.message || '保存失败'
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.clickable { cursor: pointer; }
.title-cell { max-width: 380px; }
.title-cell b { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.stage-chip { display: inline-flex; margin-right: 4px; padding: 1px 7px; border: 1px solid var(--v-line); border-radius: 999px; color: var(--v-ink-3); font-size: 10px; }
.detail { display: grid; gap: 18px; }
.detail-top { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.detail h3 { margin-bottom: 10px; color: var(--v-ink); font-size: 12.5px; font-weight: 620; }
.incident-drawer { width: min(38vw, 520px); max-width: 520px; }
.disposition { display: flex; align-items: center; gap: 8px; margin-top: 10px; }
.disposition-label { color: var(--v-ink-3); font-size: 11px; }
.save-btn { margin-top: 12px; width: 100%; }
.timeline { display: grid; gap: 16px; }
.tl-head { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.tl-head b { color: var(--v-ink); font-size: 12px; font-weight: 600; }
.tl-head small { color: var(--v-ink-3); font-size: 10.5px; }
.tl-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--v-accent); }
.tl-ev { display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: start; gap: 10px; padding: 8px 0 8px 15px; border-left: 1px solid var(--v-line); }
.tl-ev-main { display: grid; gap: 2px; min-width: 0; }
.tl-ev-main b { color: var(--v-ink); font-size: 12px; font-weight: 550; }
.tl-ev-main small { color: var(--v-ink-3); font-size: 10.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tl-ev time { color: var(--v-ink-3); font-family: var(--v-mono); font-size: 10px; }
</style>
