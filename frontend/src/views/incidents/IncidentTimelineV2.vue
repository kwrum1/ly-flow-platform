<template>
  <section class="incident-v2">
    <header class="page-head">
      <div>
        <p>ATTACK CHAINS</p>
        <h2>攻击链处置</h2>
      </div>
      <button type="button" :disabled="loading" @click="loadIncidents">刷新</button>
    </header>

    <div v-if="error" class="state-message">{{ error }}</div>

    <div class="incident-layout">
      <aside class="incident-list">
        <div class="list-head"><strong>Incident</strong><span>{{ incidents.length }} 条</span></div>
        <div v-if="loading && incidents.length === 0" class="empty">正在加载</div>
        <div v-else-if="incidents.length === 0" class="empty">暂无 Incident</div>
        <button
          v-for="item in incidents"
          :key="item.id"
          type="button"
          class="incident-row"
          :class="{ active: selected?.id === item.id }"
          @click="selectIncident(item)"
        >
          <span :class="['severity', item.severity]">{{ severityLabel(item.severity) }}</span>
          <span class="row-main"><b>{{ item.title }}</b><small>{{ item.affectedAsset || item.entityId || '-' }}</small></span>
          <span class="status">{{ statusLabel(item.status) }}</span>
        </button>
      </aside>

      <main class="incident-detail">
        <div v-if="!selected" class="empty large">选择左侧 Incident 查看攻击链</div>
        <template v-else>
          <header class="detail-head">
            <div>
              <h3>{{ selected.title }}</h3>
              <p>{{ selected.affectedAsset || selected.entityId || '-' }} · {{ selected.createdAt ? formatTime(selected.createdAt) : '-' }}</p>
            </div>
            <div class="detail-actions">
              <span :class="['severity', selected.severity]">{{ severityLabel(selected.severity) }}</span>
              <select :value="selected.status" :disabled="updating" @change="updateStatus($event.target.value)">
                <option v-for="status in statuses" :key="status" :value="status">{{ statusLabel(status) }}</option>
              </select>
            </div>
          </header>

          <div class="detail-meta">
            <div><span>源 IP</span><b>{{ selected.sourceIPs?.join(', ') || '-' }}</b></div>
            <div><span>受害 IP</span><b>{{ selected.victimIPs?.join(', ') || '-' }}</b></div>
            <div><span>建议</span><b>{{ selected.recommendedAction || '-' }}</b></div>
            <div><span>更新时间</span><b>{{ selected.updatedAt ? formatTime(selected.updatedAt) : '-' }}</b></div>
          </div>

          <section class="timeline">
            <h4>阶段时间线</h4>
            <div v-if="groups.length" class="timeline-list">
              <div v-for="group in groups" :key="group.id" class="timeline-group">
                <div class="timeline-marker"><i /> <span>{{ stageLabel(group.stage) }}</span></div>
                <div class="timeline-body">
                  <div class="timeline-title"><b>{{ group.name }}</b><small>{{ group.tactic || '' }}</small></div>
                  <div v-if="group.evidence.length" class="evidence-list">
                    <div v-for="evidence in group.evidence" :key="evidence.id" class="evidence-row">
                      <span class="evidence-source">{{ evidence.sourceModule }}</span>
                      <div><b>{{ evidence.title }}</b><small>{{ evidence.summary }}</small></div>
                      <span class="evidence-time">{{ evidence.time ? formatTime(evidence.time) : '-' }}</span>
                    </div>
                  </div>
                  <div v-else class="empty small">该阶段暂无证据</div>
                </div>
              </div>
            </div>
            <div v-else class="empty">暂无阶段证据</div>
          </section>

          <section class="evidence-matrix">
            <h4>证据矩阵</h4>
            <div v-if="selected.evidence?.length" class="evidence-grid">
              <div v-for="evidence in selected.evidence" :key="evidence.id" class="evidence-card">
                <span>{{ evidence.sourceModule }}</span>
                <b>{{ evidence.title }}</b>
                <small>{{ evidence.summary }}</small>
                <code v-if="evidence.rawReference">{{ evidence.rawReference }}</code>
              </div>
            </div>
            <div v-else class="empty">暂无证据</div>
          </section>
        </template>
      </main>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { attackWorkbenchClient } from '../../api/domain'
import { incidentsAPI } from '../../api/events'
import { severityLabel, stageLabel } from '../../domain/attack-labels'
import { normalizeIncident, normalizeIncidents } from '../../domain/incidents'

const incidents = ref([])
const selected = ref(null)
const loading = ref(false)
const updating = ref(false)
const error = ref('')
const statuses = ['open', 'triaged', 'processing', 'resolved', 'closed']

const groups = computed(() => {
  if (!selected.value) return []
  if (selected.value.stageGroups?.length) return selected.value.stageGroups
  return (selected.value.stages || []).map((stage, index) => ({
    id: stage.id || `stage-${index}`,
    stage: stage.name,
    name: stage.name,
    tactic: stage.tactic,
    evidence: selected.value.evidence?.filter((evidence) => evidence.stage === stage.name) || [],
  }))
})

function unwrap(response) {
  return response?.data?.data ?? response?.data ?? {}
}

function formatTime(value) {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString('zh-CN', { hour12: false })
}

function statusLabel(value) {
  return ({ open: '新发', triaged: '已分诊', processing: '处理中', resolved: '已解决', closed: '已关闭' })[value] || value || '-'
}

async function loadIncidents() {
  loading.value = true
  error.value = ''
  try {
    const data = unwrap(await attackWorkbenchClient.incidents({ limit: 50 }))
    const items = Array.isArray(data.items) ? data.items : Array.isArray(data) ? data : []
    incidents.value = normalizeIncidents(items)
    if (selected.value) {
      const current = incidents.value.find((item) => item.id === selected.value.id)
      if (current) selected.value = current
    }
  } catch (cause) {
    error.value = 'Incident 列表加载失败'
  } finally {
    loading.value = false
  }
}

async function selectIncident(item) {
  selected.value = item
  try {
    const data = unwrap(await attackWorkbenchClient.incident(item.id))
    selected.value = normalizeIncident(data)
  } catch (cause) {
    // Keep the normalized list row when detail is unavailable.
  }
}

async function updateStatus(status) {
  if (!selected.value || status === selected.value.status) return
  updating.value = true
  error.value = ''
  try {
    await incidentsAPI.updateStatus(selected.value.id, status)
    selected.value = { ...selected.value, status }
    await loadIncidents()
  } catch (cause) {
    error.value = '状态更新失败'
  } finally {
    updating.value = false
  }
}

onMounted(loadIncidents)
</script>

<style scoped>
.incident-v2 { display: grid; gap: 14px; color: #1f2a37; }
.page-head { display: flex; align-items: flex-end; justify-content: space-between; }
.page-head p { margin: 0 0 2px; color: #98a2b3; font-size: 10px; letter-spacing: .08em; }
.page-head h2 { margin: 0; font-size: 20px; font-weight: 600; }
.page-head button { height: 32px; padding: 0 14px; border: 1px solid #d8e1ec; border-radius: 6px; background: #fff; color: #475467; cursor: pointer; }
.state-message { padding: 10px 12px; border: 1px solid #f3c2c2; border-radius: 6px; background: #fff5f5; color: #c43838; font-size: 13px; }
.incident-layout { display: grid; grid-template-columns: 360px minmax(0, 1fr); gap: 14px; min-height: 560px; }
.incident-list { overflow: hidden; border: 1px solid #d8e1ec; border-radius: 8px; background: #fff; }
.list-head { display: flex; align-items: center; justify-content: space-between; padding: 12px 14px; border-bottom: 1px solid #e6ebf1; }
.list-head span { color: #98a2b3; font-size: 11px; }
.incident-row { display: grid; width: 100%; grid-template-columns: 56px minmax(0, 1fr) 56px; align-items: center; gap: 8px; padding: 10px 12px; border: 0; border-bottom: 1px solid #eef2f6; background: #fff; color: inherit; text-align: left; cursor: pointer; }
.incident-row:hover, .incident-row.active { background: #f7fbff; }
.row-main { min-width: 0; }
.row-main b { display: block; overflow: hidden; font-size: 12px; text-overflow: ellipsis; white-space: nowrap; }
.row-main small { display: block; overflow: hidden; color: #98a2b3; font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.status { color: #667085; font-size: 11px; text-align: right; }
.severity { display: inline-block; padding: 2px 6px; border-radius: 4px; background: #f1f5f9; color: #475467; font-size: 10px; text-align: center; }
.severity.critical { background: #fdecec; color: #c43838; }
.severity.high { background: #fff3e6; color: #ad6800; }
.severity.medium { background: #fff8db; color: #8a6d00; }
.severity.low { background: #eef7f1; color: #168a55; }
.incident-detail { min-width: 0; padding: 14px 16px; border: 1px solid #d8e1ec; border-radius: 8px; background: #fff; }
.detail-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
.detail-head h3 { margin: 0; font-size: 16px; }
.detail-head p { margin: 4px 0 0; color: #98a2b3; font-size: 11px; }
.detail-actions { display: flex; align-items: center; gap: 8px; }
.detail-actions select { height: 30px; border: 1px solid #d8e1ec; border-radius: 5px; background: #fff; color: #475467; font-size: 12px; }
.detail-meta { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin: 14px 0; padding: 12px; border-radius: 6px; background: #f8fafc; }
.detail-meta span { display: block; color: #98a2b3; font-size: 10px; }
.detail-meta b { display: block; overflow: hidden; font-size: 12px; font-weight: 500; text-overflow: ellipsis; white-space: nowrap; }
.timeline h4, .evidence-matrix h4 { margin: 16px 0 10px; font-size: 13px; }
.timeline-list { display: grid; gap: 10px; }
.timeline-group { display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 12px; }
.timeline-marker { display: flex; align-items: center; gap: 8px; color: #1268bd; font-size: 12px; font-weight: 600; }
.timeline-marker i { width: 9px; height: 9px; border-radius: 50%; background: #1976d2; box-shadow: 0 0 0 3px #e8f3ff; }
.timeline-body { padding: 0 0 12px 12px; border-left: 1px solid #d8e1ec; }
.timeline-title { display: flex; align-items: baseline; gap: 8px; margin-bottom: 6px; }
.timeline-title b { font-size: 12px; }
.timeline-title small { color: #98a2b3; font-size: 10px; }
.evidence-list { display: grid; gap: 6px; }
.evidence-row { display: grid; grid-template-columns: 70px minmax(0, 1fr) 128px; gap: 8px; align-items: center; padding: 6px 8px; border: 1px solid #eef2f6; border-radius: 5px; }
.evidence-source { color: #1268bd; font-size: 10px; }
.evidence-row b { display: block; overflow: hidden; font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.evidence-row small { display: block; overflow: hidden; color: #98a2b3; font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.evidence-time { color: #667085; font-size: 10px; text-align: right; }
.evidence-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.evidence-card { display: grid; gap: 4px; padding: 10px; border: 1px solid #eef2f6; border-radius: 6px; }
.evidence-card span { color: #1268bd; font-size: 10px; }
.evidence-card b { font-size: 12px; }
.evidence-card small { color: #667085; font-size: 11px; }
.evidence-card code { overflow: hidden; color: #98a2b3; font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
.empty { padding: 24px 0; color: #98a2b3; font-size: 12px; text-align: center; }
.empty.large { padding-top: 120px; }
.empty.small { padding: 8px 0; text-align: left; }
@media (max-width: 960px) { .incident-layout { grid-template-columns: 1fr; } .detail-meta { grid-template-columns: repeat(2, minmax(0, 1fr)); } .evidence-grid { grid-template-columns: 1fr; } }
</style>
