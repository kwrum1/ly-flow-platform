<template>
  <section class="attack-page">
    <header class="attack-hero">
      <div>
        <p>攻击链调查</p>
        <h2>攻击链工作台</h2>
        <span>仅展示能按渗透阶段串联会话记录或安全事件的攻击链；单点告警留在检测面。</span>
      </div>
      <button type="button" @click="loadAll" :disabled="loading">刷新调查数据</button>
    </header>

    <div v-if="error" class="state-card error-state">{{ error }}</div>

    <section class="metric-grid">
      <article class="surface-card metric-card">
        <span>组件告警</span>
        <strong>{{ stats.total_alerts ?? stats.total_events ?? 0 }}</strong>
        <em>今日 {{ stats.today_alerts ?? stats.alerts_today ?? stats.today_events ?? 0 }} 条</em>
      </article>
      <article class="surface-card metric-card">
        <span>活跃攻击链</span>
        <strong>{{ chainTotal }}</strong>
        <em>XDR 组件告警关联结果</em>
      </article>
      <article class="surface-card metric-card">
        <span>态势评分</span>
        <strong>{{ posture.risk_score ?? stats.posture_score ?? 0 }}</strong>
        <em>{{ posture.risk_level || stats.posture_level || 'low' }}</em>
      </article>
      <article class="surface-card metric-card">
        <span>高危及以上</span>
        <strong>{{ highRiskCount }}</strong>
        <em>建议优先处置</em>
      </article>
    </section>

    <section class="workbench-grid">
      <article class="surface-card panel-card-main">
        <div class="panel-heading">
          <strong>XDR 攻击链</strong>
          <span>{{ chainTotal }} 条</span>
        </div>
        <div v-if="loading" class="state-card">正在读取 XDR 攻击链</div>
        <div v-else-if="chains.length === 0" class="state-card">当前没有满足关联阈值的攻击链。</div>
        <ul v-else class="incident-list">
          <li v-for="chain in chains" :key="chain.id">
            <div>
              <strong>{{ chainTitle(chain) }} · {{ scoreText(chain.score) }} 分</strong>
              <p>{{ pickText(chain.summary, '该攻击链没有摘要字段') }}</p>
              <div v-if="stageGroups(chain).length" class="stage-evidence-groups">
                <section v-for="group in stageGroups(chain)" :key="group.stage" class="stage-evidence-group">
                  <h4>{{ pickText(group.stage_label, group.stage) }}</h4>
                  <p v-for="item in group.evidence" :key="item.event_id || item.summary || item.time">
                    <time>{{ formatChinaDateTime(item.time || item.date || item.timestamp || item.created_at) }}</time>
                    <span>{{ readableText(item.summary || item.message, '暂无证据说明') }}</span>
                  </p>
                </section>
              </div>
            </div>
            <span :class="['severity-pill', chain.severity || 'info']">{{ pickText(chain.severity, '提示') }}</span>
          </li>
        </ul>
      </article>

      <article class="surface-card panel-card-main">
        <div class="panel-heading">
          <strong>攻击时间线</strong>
          <span>{{ timelineTotal }} 个节点</span>
        </div>
        <div v-if="loading" class="state-card">正在读取后端时间线</div>
        <div v-else-if="timeline.length === 0" class="state-card">当前攻击链没有可展示的时间线节点。</div>
        <ol v-else class="timeline-list">
          <li v-for="item in timeline" :key="item.id">
            <time>{{ formatChinaDateTime(item.timestamp) }}</time>
            <strong>{{ pickText(item.stage_label, '风险发现') }}</strong>
            <p>{{ readableText(item.summary || item.message, '后端未提供事件说明') }}</p>
          </li>
        </ol>
      </article>
    </section>

    <section class="surface-card event-panel">
      <div class="panel-heading">
        <strong>关联证据事件</strong>
        <span>{{ eventTotal }} 条</span>
      </div>
      <div v-if="events.length === 0" class="state-card">当前没有可串联到攻击链的证据事件。</div>
      <table v-else class="event-table">
        <thead>
          <tr>
            <th>时间</th>
            <th>级别</th>
            <th>来源</th>
            <th>事件说明</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="event in events" :key="event.id">
            <td>{{ formatChinaDateTime(event.timestamp || event.created_at) }}</td>
            <td>{{ pickText(event.severity_label || event.severity, '提示') }}</td>
            <td>{{ pickText(event.source, '未知来源') }}</td>
            <td>{{ readableText(event.message, '后端未提供事件说明') }}</td>
          </tr>
        </tbody>
      </table>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { attackWorkbenchClient } from '../api/domain'
import { normalizeItems, pickNumber, pickText } from '../shared/api-normalize'
import { formatChinaDateTime } from '../shared/time'

const loading = ref(false)
const error = ref('')
const stats = ref({})
const incidentsPayload = ref({ items: [], total: 0 })
const chainsPayload = ref({ items: [], total: 0 })
const timelinePayload = ref({ items: [], total: 0 })
const eventsPayload = ref({ items: [], total: 0 })
const posture = ref({})

const incidents = computed(() => incidentsPayload.value.items)
const chains = computed(() => chainsPayload.value.items)
const timeline = computed(() => timelinePayload.value.items)
const events = computed(() => eventsPayload.value.items)
const incidentTotal = computed(() => incidentsPayload.value.total)
const chainTotal = computed(() => chainsPayload.value.total)
const timelineTotal = computed(() => timelinePayload.value.total)
const eventTotal = computed(() => eventsPayload.value.total)
const highRiskCount = computed(() => events.value.filter((event) => ['critical', 'high', '严重', '高危'].includes(String(event.severity || event.severity_label).toLowerCase())).length)

function readableText(value, fallback) {
  const result = String(pickText(value, fallback))
  return /\?{2,}/.test(result) ? '检测引擎命中关联事件' : result
}

function scoreText(value) {
  const score = Number(value)
  return Number.isFinite(score) ? String(Math.round(score * 10) / 10) : '0'
}

function chainTitle(chain) {
  const name = pickText(chain.entity || chain.victim, '目标资产')
  const ip = Array.isArray(chain.victim_ips) && chain.victim_ips.length ? chain.victim_ips[0] : Array.isArray(chain.source_ips) && chain.source_ips.length ? chain.source_ips[0] : ''
  const target = ip && !String(name).includes(ip) ? `${name}(${ip})` : name
  return `${target} 出现攻击链`
}

function stageGroups(chain) {
  if (Array.isArray(chain.stage_groups) && chain.stage_groups.length) return chain.stage_groups
  const evidence = Array.isArray(chain.event_evidence) ? chain.event_evidence : Array.isArray(chain.evidence) ? chain.evidence : []
  const stages = Array.isArray(chain.stages) ? chain.stages : []
  return stages.map((stage, index) => ({
    stage,
    stage_label: Array.isArray(chain.stage_labels) ? chain.stage_labels[index] : stage,
    evidence: evidence.filter((item) => (item.stage || item.stage_hint) === stage),
  })).filter((group) => group.evidence.length)
}

const loadAll = async () => {
  loading.value = true
  error.value = ''
  try {
    const [nextStats, nextIncidents, nextChains, nextPosture, nextTimeline, nextEvents] = await Promise.allSettled([
      attackWorkbenchClient.stats(),
      attackWorkbenchClient.incidents({ limit: 20 }),
      attackWorkbenchClient.xdrChains({ limit: 20 }),
      attackWorkbenchClient.xdrPosture(),
      attackWorkbenchClient.timeline({ limit: 30 }),
      attackWorkbenchClient.events({ limit: 20 }),
    ])
    if (nextStats.status === 'fulfilled') stats.value = nextStats.value || {}
    if (nextIncidents.status === 'fulfilled') incidentsPayload.value = normalizeItems(nextIncidents.value)
    if (nextChains.status === 'fulfilled') chainsPayload.value = normalizeItems(nextChains.value)
    if (nextPosture.status === 'fulfilled') posture.value = nextPosture.value || {}
    if (nextTimeline.status === 'fulfilled') timelinePayload.value = normalizeItems(nextTimeline.value)
    if (nextEvents.status === 'fulfilled') eventsPayload.value = normalizeItems(nextEvents.value)
    if ([nextStats, nextIncidents, nextChains, nextPosture, nextEvents].every((result) => result.status === 'rejected')) {
      error.value = '无法读取攻击链工作台数据'
    }
  } catch (requestError) {
    error.value = requestError?.message || '无法读取攻击链工作台数据'
  } finally {
    loading.value = false
  }
}

onMounted(loadAll)
</script>

<style scoped>
.attack-page {
  display: grid;
  gap: 12px;
  padding: 16px;
  color: #243149;
  background: #f3f6fa;
}

.attack-hero {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 16px 18px;
  border-radius: 6px;
  background: #fff;
  border: 1px solid #dce3ec;
}

.attack-hero p {
  margin: 0 0 8px;
  color: #1976d2;
  font-size: 12px;
  font-weight: 900;
  letter-spacing: 0;
}

.attack-hero h2 {
  margin: 0;
  color: #1d2939;
  font-size: 22px;
  letter-spacing: 0;
}

.attack-hero span {
  display: block;
  max-width: 780px;
  margin-top: 6px;
  color: #667085;
  font-size: 12px;
  line-height: 1.6;
}

.attack-hero button {
  height: 44px;
  padding: 0 18px;
  border: 0;
  border-radius: 5px;
  color: #fff;
  font-weight: 900;
  background: #1976d2;
  cursor: pointer;
}

.metric-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
}

.metric-card {
  padding: 14px 16px;
}

.metric-card span,
.metric-card em {
  color: var(--text-secondary);
  font-style: normal;
}

.metric-card strong {
  display: block;
  margin: 8px 0;
  font-size: 34px;
}

.workbench-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 10px;
}

.panel-card-main,
.event-panel {
  padding: 16px;
}

.panel-heading {
  display: flex;
  justify-content: space-between;
  margin-bottom: 16px;
}

.panel-heading strong {
  font-size: 18px;
}

.panel-heading span,
.state-card {
  color: var(--text-secondary);
}

.state-card {
  padding: 14px;
  border-radius: 6px;
  background: #f8fafc;
  border: 1px solid #e1e7ef;
}

.error-state {
  color: #b42318;
  border-color: #f0b5b1;
  background: #fff3f2;
}

.incident-list,
.timeline-list {
  display: grid;
  gap: 12px;
  list-style: none;
}

.incident-list li,
.timeline-list li {
  padding: 15px;
  border-radius: 6px;
  background: #fff;
  border: 1px solid #dce3ec;
}

.incident-list li {
  display: flex;
  justify-content: space-between;
  gap: 16px;
}

.incident-list li > div {
  min-width: 0;
  flex: 1;
}

.incident-list p,
.timeline-list p {
	margin-top: 6px;
	color: var(--text-secondary);
	line-height: 1.7;
}

.stage-evidence-groups {
	display: grid;
	gap: 6px;
	margin-top: 10px;
}

.stage-evidence-group {
	display: flex;
	align-items: center;
	gap: 12px;
	width: 100%;
	padding: 8px 10px;
	border-radius: 5px;
	border: 1px solid #cfe0f1;
	background: #edf6ff;
}

.stage-evidence-group h4 {
	width: 128px;
	flex: 0 0 128px;
	margin: 0;
	padding-right: 10px;
	border-right: 1px solid #c9dced;
	color: var(--text-primary);
	overflow-wrap: anywhere;
}

.stage-evidence-group p {
	display: grid;
	grid-template-columns: 150px minmax(0, 1fr);
	align-items: center;
	gap: 10px;
	min-width: 0;
	flex: 1;
	margin: 0;
}

.stage-evidence-group time {
	color: #1769ba;
	font-size: 12px;
}

.stage-evidence-group p span {
	overflow: hidden;
	text-overflow: ellipsis;
	white-space: nowrap;
}

.timeline-list time {
  display: block;
  margin-bottom: 6px;
  color: #1769ba;
  font-size: 12px;
}

.severity-pill {
  align-self: flex-start;
  padding: 5px 10px;
  border-radius: 4px;
  color: #1769ba;
  background: #edf6ff;
  border: 1px solid #b8d7f4;
}

.severity-pill.critical,
.severity-pill.high {
  color: #b42318;
  background: #fff0ef;
  border-color: #f5b7b1;
}

.event-table {
  width: 100%;
  border-collapse: collapse;
}

.event-table th,
.event-table td {
  padding: 13px 12px;
  text-align: left;
  border-bottom: 1px solid var(--border-light);
}

.event-table th {
  color: var(--text-muted);
  font-size: 12px;
}

@media (max-width: 1180px) {
  .metric-grid,
  .workbench-grid {
    grid-template-columns: 1fr;
  }
}
</style>
