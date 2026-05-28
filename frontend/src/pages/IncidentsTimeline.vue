<template>
  <section class="incident-page">
    <header class="page-head">
      <div>
        <p>{{ mode === 'timeline' ? '攻击时间线' : '安全事故' }}</p>
        <h2>{{ mode === 'timeline' ? '攻击时间线' : '安全事故' }}</h2>
        <span>展示后端生成的事故、攻击阶段、证据摘要和时间线节点，所有时间均按中国时间呈现。</span>
      </div>
      <button type="button" @click="loadAll" :disabled="loading">刷新调查结果</button>
    </header>

    <div v-if="error" class="state-card error-state">{{ error }}</div>

    <article v-if="mode !== 'timeline'" class="surface-card data-card">
      <div class="panel-heading"><strong>事故列表</strong><span>{{ incidentTotal }} 起</span></div>
      <div v-if="loading" class="state-card">正在读取事故接口</div>
      <div v-else-if="incidents.length === 0" class="state-card">当前没有安全事故。</div>
      <ul v-else class="incident-list">
        <li v-for="incident in incidents" :key="incident.id">
          <strong>{{ pickText(incident.title, '未命名事故') }}</strong>
          <span>{{ pickText(incident.severity_label, '提示') }} · {{ pickText(incident.status_label, '待确认') }}</span>
          <p>{{ pickText(incident.summary, '后端未提供事故摘要') }}</p>
          <div v-if="stageGroups(incident).length" class="stage-evidence-groups">
            <section v-for="group in stageGroups(incident)" :key="group.stage" class="stage-evidence-group">
              <h4>{{ pickText(group.stage_label, group.stage) }}</h4>
              <p v-for="item in group.evidence" :key="item.event_id || item.summary || item.time">
                <time>{{ formatChinaDateTime(item.time || item.date || item.timestamp || item.created_at) }}</time>
                <span>{{ pickText(item.summary || item.message, '暂无证据说明') }}</span>
              </p>
            </section>
          </div>
          <em>首次发现：{{ formatChinaDateTime(incident.first_seen) }} 最近更新：{{ formatChinaDateTime(incident.last_seen) }}</em>
        </li>
      </ul>
    </article>

    <article class="surface-card data-card">
      <div class="panel-heading"><strong>攻击时间线</strong><span>{{ timelineTotal }} 个节点</span></div>
      <div v-if="loading" class="state-card">正在读取时间线接口</div>
      <div v-else-if="timeline.length === 0" class="state-card">当前没有时间线节点。</div>
      <ol v-else class="timeline-list">
        <li v-for="item in timeline" :key="item.id">
          <time>{{ formatChinaDateTime(item.timestamp) }}</time>
          <strong>{{ pickText(item.stage_label, '风险发现') }}</strong>
          <p>{{ pickText(item.summary || item.message, '后端未提供时间线说明') }}</p>
        </li>
      </ol>
    </article>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { attackWorkbenchClient } from '../api/domain'
import { normalizeItems, pickText } from '../shared/api-normalize'
import { formatChinaDateTime } from '../shared/time'

defineProps({ mode: { type: String, default: 'incidents' } })

const loading = ref(false)
const error = ref('')
const incidentsPayload = ref({ items: [], total: 0 })
const timelinePayload = ref({ items: [], total: 0 })
const incidents = computed(() => incidentsPayload.value.items)
const timeline = computed(() => timelinePayload.value.items)
const incidentTotal = computed(() => incidentsPayload.value.total)
const timelineTotal = computed(() => timelinePayload.value.total)

function stageGroups(incident) {
  if (Array.isArray(incident.stage_groups) && incident.stage_groups.length) return incident.stage_groups
  const evidence = Array.isArray(incident.attack_chain) ? incident.attack_chain : Array.isArray(incident.evidence) ? incident.evidence : []
  const stages = Array.isArray(incident.stages) ? incident.stages : []
  return stages.map((stage, index) => ({
    stage,
    stage_label: Array.isArray(incident.stage_labels) ? incident.stage_labels[index] : stage,
    evidence: evidence.filter((item) => (item.stage || item.stage_hint) === stage),
  })).filter((group) => group.evidence.length)
}

async function loadAll() {
  loading.value = true
  error.value = ''
  try {
    const [nextIncidents, nextTimeline] = await Promise.all([
      attackWorkbenchClient.incidents({ limit: 50 }),
      attackWorkbenchClient.timeline({ limit: 100 }),
    ])
    incidentsPayload.value = normalizeItems(nextIncidents)
    timelinePayload.value = normalizeItems(nextTimeline)
  } catch (requestError) {
    error.value = requestError?.message || '无法读取事故与时间线'
  } finally {
    loading.value = false
  }
}

onMounted(loadAll)
</script>

<style scoped>
.incident-page { display: grid; gap: 22px; padding: 28px; }
.page-head { display: flex; justify-content: space-between; gap: 24px; padding: 30px; border-radius: 26px; border: 1px solid var(--border-light); background: linear-gradient(135deg, rgba(17,31,52,.94), rgba(8,18,32,.78)); }
.page-head p { margin: 0 0 8px; color: var(--primary-light); font-size: 12px; font-weight: 900; letter-spacing: .16em; }
.page-head h2 { margin: 0; font-size: clamp(32px, 4vw, 54px); letter-spacing: -.055em; }
.page-head span { display: block; max-width: 760px; margin-top: 12px; color: var(--text-secondary); line-height: 1.8; }
button { height: 44px; padding: 0 18px; border: 0; border-radius: 14px; color: #06101d; font-weight: 900; background: linear-gradient(135deg, #7dd3fc, #34d399); cursor: pointer; }
.data-card { padding: 22px; }
.panel-heading { display: flex; justify-content: space-between; margin-bottom: 16px; }
.state-card { padding: 18px; color: var(--text-secondary); border-radius: 16px; border: 1px solid var(--border-light); background: rgba(255,255,255,.04); }
.error-state { color: #fecaca; border-color: rgba(248,113,113,.34); background: rgba(248,113,113,.12); }
.incident-list, .timeline-list { display: grid; gap: 12px; list-style: none; }
.incident-list li, .timeline-list li { padding: 16px; border-radius: 16px; border: 1px solid var(--border-light); background: rgba(255,255,255,.04); }
.incident-list span, .incident-list em, .timeline-list time { display: block; margin-top: 6px; color: var(--primary-light); font-style: normal; font-size: 12px; }
.incident-list p, .timeline-list p { margin-top: 8px; color: var(--text-secondary); line-height: 1.75; }
.stage-evidence-groups { display: grid; gap: 10px; margin-top: 12px; }
.stage-evidence-group { padding: 10px 12px; border-radius: 12px; border: 1px solid var(--border-light); background: rgba(15, 23, 42, .36); }
.stage-evidence-group h4 { margin: 0 0 8px; color: var(--text-primary); }
.stage-evidence-group p { display: grid; gap: 4px; margin: 8px 0 0; }
.stage-evidence-group time { color: var(--primary-light); font-size: 12px; }
@media (max-width: 980px) { .page-head { flex-direction: column; align-items: flex-start; } }
</style>
