<template>
  <section class="posture-page">
    <header class="posture-header">
      <h2>实时态势</h2>
      <div class="header-right">
        <span class="update-time">{{ formatTime(posture.updated_at) }}</span>
        <button class="ghost" @click="refreshAll" :disabled="refreshing">{{ refreshing ? '刷新中' : '刷新' }}</button>
      </div>
    </header>

    <section class="score-row">
      <div class="score-card" :class="riskClass(posture.risk_level)">
        <small>态势评分</small>
        <strong>{{ posture.risk_score ?? 0 }}</strong>
        <div class="score-meter"><u :style="{ width: (posture.risk_score || 0) + '%' }"></u></div>
        <em>{{ riskLabel(posture.risk_level) }}</em>
      </div>
      <div class="metric-cards">
        <div class="metric"><label>活跃攻击链</label><b>{{ hasLoaded ? chains.length : (posture.active_chains ?? 0) }}</b></div>
        <div class="metric"><label>总告警事件</label><b>{{ chainsTotalEvents }}</b></div>
        <div class="metric" v-for="[cat, label] in topComponents" :key="cat" :class="cat">
          <label>{{ label }}</label><b>{{ posture.component_counts?.[cat] ?? 0 }}</b>
        </div>
      </div>
    </section>

    <section class="panel attck-panel" v-if="stageDistribution.length">
      <div class="panel-title"><strong>ATT&CK 攻击阶段分布</strong><span>基于 {{ activeStageCount }} 个已观测阶段</span></div>
      <div class="kill-chain-row">
        <div v-for="stage in stageDistribution" :key="stage.key" :class="['kc-cell', stage.class, { active: stage.count > 0 }]">
          <span class="kc-label">{{ stage.label }}</span>
          <span class="kc-count" v-if="stage.count > 0">{{ stage.count }}</span>
          <span class="kc-bar" v-if="stage.count > 0" :style="{ height: stagePct(stage.count) + '%' }"></span>
          <span class="kc-status" v-if="stage.count > 0">●</span>
        </div>
      </div>
    </section>

    <div class="dual-panel">
      <article class="panel chains-panel">
        <div class="panel-title">
          <strong>攻击链</strong>
          <span>{{ chains.length }} 条</span>
        </div>
        <div v-if="loading && !hasLoaded" class="empty-card">正在读取 XDR 攻击链数据</div>
        <div v-else-if="!chains.length && posture.active_chains" class="empty-card">攻击链数据同步中，请稍候...</div>
        <div v-else-if="!chains.length" class="empty-card">暂无活跃攻击链</div>
        <div v-else class="chain-list">
          <article v-for="chain in chains" :key="chain.id" class="chain-card" :class="{ open: expanded === chain.id }">
            <div class="chain-top" @click="toggleChain(chain.id)">
              <div class="chain-score" :class="riskClass(chain.severity || severityFromScore(chain.score))">
                <strong>{{ chain.score ?? 0 }}</strong>
                <em>{{ riskLabel(chain.severity || severityFromScore(chain.score)) }}</em>
              </div>
              <div class="chain-core">
                <b>{{ chain.entity || chain.victim || '未知实体' }}<i v-if="chain.standalone_alert" class="solo-flag">独立告警</i><i v-if="chain.partial_chain" class="partial-flag">部分链</i></b>
                <div class="chain-stage-flow">
                  <span v-for="(stage, i) in v3StageFlow(chain)" :key="stage.key" :class="['flow-step', stageClass(stage.key), { missing: stage.missing }]">
                    {{ stageLabel(stage.key) }}
                    <i v-if="stage.hasArrow" class="flow-arrow">→</i>
                  </span>
                </div>
              </div>
              <div class="chain-meta-compact">
                <span>{{ chain.event_count }} 事件</span>
                <span>{{ chain.stage_count || chain.stages?.length }} 阶段</span>
                <span class="time-range">{{ shortTime(chain.first_seen) }} — {{ shortTime(chain.last_seen) }}</span>
              </div>
            </div>

            <div v-if="expanded === chain.id" class="chain-detail">
              <div class="detail-strip">
                <span v-if="chain.categories?.length" v-for="cat in chain.categories" :key="cat" class="cat-tag">{{ catLabel(cat) }}</span>
                <span v-if="chain.seed_stage" class="seed-tag">种子 → {{ stageLabel(chain.seed_stage) }}</span>
                <span v-if="chain.partial_chain" class="partial-warn">缺少 {{ (chain.missing_stages || []).length }} 阶段</span>
                <span v-if="chain.standalone_alert" class="standalone-warn">独立告警（无关联 IP）</span>
                <span v-if="chain.hypothesis_status" :class="['hs-badge', chain.hypothesis_status]">{{ hypothesisStatusLabel(chain.hypothesis_status) }}</span>
                <span v-if="chain.confidence !== undefined" class="v2-tag">置信度 {{ fmtNum(chain.confidence) }}</span>
                <span v-if="chain.impact !== undefined" class="v2-tag">影响 {{ fmtNum(chain.impact) }}</span>
                <span v-if="chain.continuity !== undefined" class="v2-tag">连续性 {{ fmtNum(chain.continuity) }}</span>
                <span v-if="chain.attack_mapping_version" class="v2-tag">{{ chain.attack_mapping_version }}</span>
              </div>

              <div v-if="chain.missing_stages?.length" class="missing-strip">
                后端标记的缺失阶段：<span v-for="ms in chain.missing_stages" :key="ms" class="missing-stage">{{ stageLabel(ms) }}</span>
              </div>

              <div v-if="chain.event_evidence?.length" class="evidence-section">
                <div class="evidence-title">组件告警证据 ({{ chain.event_evidence.length }} 条)</div>
                <div class="timeline">
                  <div v-for="(ev, i) in chain.event_evidence" :key="'alrt-'+i" class="tl-entry">
                    <div class="tl-marker" :class="severityClass(ev.severity)">{{ i + 1 }}</div>
                    <div class="tl-body">
                      <div class="tl-top">
                        <b>{{ ev.rule_name || '未命名' }}</b>
                        <span :class="['sev-sm', severityClass(ev.severity)]">{{ riskLabel(ev.severity) }}</span>
                        <span v-if="ev.stage" class="stage-sm">{{ stageLabel(ev.stage) }}</span>
                        <span v-if="ev.category" class="cat-tag">{{ catLabel(ev.category) }}</span>
                      </div>
                      <div class="tl-detail">
                        <span>{{ formatTime(ev.timestamp) }}</span>
                        <span v-if="ev.summary" class="tl-summary">{{ ev.summary }}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div v-if="trafficEvidence(chain).length" class="evidence-section traffic-section">
                <div class="evidence-title traffic-title">流量会话举证 ({{ trafficEvidence(chain).length }} 条)</div>
                <div class="timeline">
                  <div v-for="(ev, i) in trafficEvidence(chain)" :key="'flow-'+i" class="tl-entry traffic-entry">
                    <div class="tl-marker flow-marker">{{ i + 1 }}</div>
                    <div class="tl-body">
                      <div class="tl-top">
                        <b>{{ ev.rule_name || ev.summary || '流量会话' }}</b>
                        <span v-if="ev.stage" class="stage-sm">{{ stageLabel(ev.stage) }}</span>
                      </div>
                      <div class="tl-detail">
                        <span>{{ ev.src_ip || '-' }}:{{ ev.src_port || 0 }} → {{ ev.dst_ip || '-' }}:{{ ev.dst_port || 0 }}</span>
                        <span v-if="ev.protocol">协议 {{ ev.protocol }}</span>
                        <span>{{ formatTime(ev.timestamp) }}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </article>
        </div>
      </article>

      <section class="panel side-panel">
        <div class="panel-title"><strong>热点威胁</strong></div>
        <div class="side-content">
          <div v-if="topHosts.length" class="side-block">
            <strong>Top 受害主机</strong>
            <div class="hot-item" v-for="h in topHosts" :key="h.host || h.hostname">
              <span>{{ h.host || h.hostname || h.id }}</span>
              <em :class="riskClass(h.severity)">{{ h.score || h.event_count }}</em>
            </div>
          </div>

          <div v-if="topSources.length" class="side-block">
            <strong>Top 攻击来源 IP</strong>
            <div class="hot-item" v-for="s in topSources" :key="s.ip || s.source">
              <span>{{ s.ip || s.source }}</span>
              <em :class="riskClass(s.severity)">{{ s.score || s.event_count }}</em>
            </div>
          </div>

          <div v-if="topRules.length" class="side-block">
            <strong>高频检测规则</strong>
            <div class="hot-item" v-for="r in topRules" :key="r.name">
              <span>{{ r.name }}</span>
              <em>{{ r.count }}</em>
            </div>
          </div>
        </div>
      </section>
    </div>

    <div v-if="error" class="notice error">{{ error }}</div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { attackWorkbenchClient } from '../api/domain'
import { normalizeItems } from '../shared/api-normalize'
import { formatChinaDateTime } from '../shared/time'

const chains = ref([])
const posture = ref({})
const topHosts = ref([])
const topSources = ref([])
const loading = ref(false)
const hasLoaded = ref(false)
const refreshing = ref(false)
const error = ref('')
const expanded = ref(null)

const componentLabels = [
  ['traffic', '流量检测'],
  ['runtime', '运行时'],
  ['rasp', 'RASP'],
  ['log_audit', '日志审计'],
]

const topComponents = computed(() => {
  const counts = posture.value.component_counts || {}
  return componentLabels
    .filter(([cat]) => (counts[cat] || 0) > 0)
    .sort(([,], [,]) => 0)
})

const totalAlertEvents = computed(() => {
  const counts = posture.value.component_counts || {}
  return Object.values(counts).reduce((s, v) => s + v, 0)
})

const chainsTotalEvents = computed(() => {
  return chains.value.reduce((s, c) => s + (c.event_count || 0), 0)
})

const stageDistribution = computed(() => {
  const observed = new Set()
  chains.value.forEach(c => {
    (c.stages || []).forEach(s => observed.add(s))
  })
  const allStages = [
    { key: 'recon', label: '侦察', class: 's-recon' },
    { key: 'initial_access', label: '初始入侵', class: 's-access' },
    { key: 'execution', label: '执行', class: 's-exec' },
    { key: 'persistence', label: '持久化', class: 's-persist' },
    { key: 'privilege_escalation', label: '提权', class: 's-priv' },
    { key: 'credential_access', label: '凭证窃取', class: 's-cred' },
    { key: 'discovery', label: '发现', class: 's-disc' },
    { key: 'lateral_movement', label: '横向移动', class: 's-lateral' },
    { key: 'collection', label: '数据收集', class: 's-collect' },
    { key: 'command_and_control', label: 'C2', class: 's-c2' },
    { key: 'exfiltration', label: '数据外泄', class: 's-c2' },
    { key: 'impact', label: '影响', class: 's-impact' },
  ]
  return allStages.map(s => {
    let count = 0
    chains.value.forEach(c => {
      (c.stages || []).forEach(st => {
        if (st === s.key) count++
      })
    })
    return { ...s, count }
  })
})

const activeStageCount = computed(() => stageDistribution.value.filter(s => s.count > 0).length)

const topRules = computed(() => {
  const map = {}
  chains.value.forEach(c => {
    ;(c.evidence || []).forEach(ev => {
      const name = ev.rule_name
      if (!name) return
      map[name] = (map[name] || 0) + 1
    })
  })
  return Object.entries(map)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
})

function stagePct(count) {
  const max = Math.max(...stageDistribution.value.map(s => s.count), 1)
  return Math.round((count / max) * 100)
}

function riskClass(level) {
  const map = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' }
  return map[level] || ''
}

function riskLabel(level) {
  const map = { critical: '严重', high: '高', medium: '中', low: '低' }
  return map[level] || level || '-'
}

function severityFromScore(score) {
  const s = Number(score)
  if (s >= 80) return 'critical'
  if (s >= 60) return 'high'
  if (s >= 35) return 'medium'
  return 'low'
}

function severityClass(sev) {
  const map = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' }
  return map[sev] || ''
}

function stageLabel(stage) {
  const map = {
    recon: '侦察', initial_access: '初始入侵', execution: '执行', persistence: '持久化',
    privilege_escalation: '提权', lateral_movement: '横向移动', credential_access: '凭证窃取',
    c2_exfiltration: 'C2/回传', command_and_control: 'C2/回传', discovery: '发现',
    collection: '数据收集', exfiltration: '数据外泄', impact: '影响',
    defense_evasion: '防御规避', detection: '检测',
  }
  return map[stage] || stage || ''
}

function stageClass(stage) {
  const map = {
    recon: 's-recon', initial_access: 's-access', execution: 's-exec', persistence: 's-persist',
    privilege_escalation: 's-priv', lateral_movement: 's-lateral', credential_access: 's-cred',
    c2_exfiltration: 's-c2', command_and_control: 's-c2', discovery: 's-disc',
    collection: 's-collect', exfiltration: 's-c2', impact: 's-impact',
  }
  return map[stage] || ''
}

function catLabel(cat) {
  const map = { traffic: '流量', runtime: '运行时', rasp: 'RASP', log_audit: '日志审计' }
  return map[cat] || cat || ''
}

function hypothesisStatusLabel(status) {
  const map = { candidate: '候选', confirmed: '已确认', rejected: '已拒绝', archived: '已归档' }
  return map[status] || status || ''
}

function formatTime(value) {
  return value ? formatChinaDateTime(value) : '-'
}

function shortTime(value) {
  if (!value) return '-'
  const d = new Date(value)
  if (isNaN(d.getTime())) return '-'
  return formatChinaDateTime(value)
}

function fmtNum(v) { return Number(v).toFixed(1) }

const stageFlowOrder = ['recon', 'initial_access', 'execution', 'persistence', 'privilege_escalation', 'credential_access', 'lateral_movement', 'collection', 'c2_exfiltration', 'impact', 'detection']

function v3StageFlow(chain) {
  const present = new Set(chain.stages || [])
  const missing = new Set(chain.missing_stages || [])
  const seed = chain.seed_stage
  let seedIdx = stageFlowOrder.indexOf(seed)
  if (seedIdx < 0) seedIdx = 0
  const flow = stageFlowOrder.slice(seedIdx, stageFlowOrder.indexOf('collection') + 1)
  return flow.map((key, i, arr) => ({
    key,
    missing: missing.has(key),
    hasArrow: i < arr.length - 1,
  }))
}

function trafficEvidence(chain) {
  return (chain.evidence || []).filter(ev => ev.evidence_type === 'traffic_session')
}

function toggleChain(id) {
  expanded.value = expanded.value === id ? null : id
}

async function refreshAll() {
  refreshing.value = true
  await loadPosture()
  await loadChains()
  refreshing.value = false
}

async function loadPosture() {
  try {
    const res = await attackWorkbenchClient.xdrPosture()
    const data = res?.data?.data || res?.data || res || {}
    posture.value = data
    topHosts.value = Array.isArray(data.top_hosts) ? data.top_hosts : []
    topSources.value = Array.isArray(data.top_source_ips) ? data.top_source_ips : []
  } catch { /* keep last known */ }
}

async function loadChains() {
  loading.value = true
  error.value = ''
  try {
    const res = await attackWorkbenchClient.xdrChains({ limit: 20 })
    const data = res?.data?.data || res?.data || {}
    const normalized = normalizeItems(data)
    chains.value = normalized.items
    hasLoaded.value = true
  } catch (e) {
    error.value = e?.message || '无法读取 XDR 攻击链数据'
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await loadPosture()
  await loadChains()
})
</script>

<style scoped>
.posture-page{min-height:100%;display:grid;align-content:start;gap:14px;padding:18px;color:#172033;background:transparent}
.posture-header,.score-row,.panel{border:1px solid rgba(255,255,255,.58);background:rgba(255,255,255,.3);border-radius:24px;box-shadow:0 24px 80px rgba(49,65,88,.14),inset 0 1px 0 rgba(255,255,255,.55);backdrop-filter:blur(28px)}
.posture-header{padding:18px 22px;display:flex;align-items:end;justify-content:space-between;gap:16px}
.posture-header h2{margin:0;font-size:24px}
.header-right{display:flex;align-items:center;gap:12px}
.update-time{color:#64748b;font-size:13px}
button.ghost{background:none;border:1px solid rgba(148,163,184,.28);border-radius:10px;padding:6px 14px;font-size:12px;font-weight:700;color:#475569;cursor:pointer;white-space:nowrap}
button.ghost:hover{border-color:#64748b;color:#172033}
button.ghost:disabled{opacity:.4;cursor:default}

.score-row{display:flex;gap:14px;padding:18px;align-items:stretch}
.score-card{flex:0 0 180px;display:grid;justify-items:center;align-content:center;gap:6px;padding:18px;border-radius:18px;border:1px solid rgba(255,255,255,.44);background:rgba(255,255,255,.24)}
.score-card small{font-size:13px;color:#64748b}
.score-card strong{font-size:52px;font-weight:950;line-height:1;color:#172033}
.score-card.critical strong{color:#991b1b}
.score-card.high strong{color:#b45309}
.score-card.medium strong{color:#a16207}
.score-card.low strong{color:#15803d}
.score-card em{font-size:13px;font-weight:800}
.score-card.critical em{color:#991b1b}
.score-card.high em{color:#b45309}
.score-card.medium em{color:#a16207}
.score-card.low em{color:#15803d}
.score-meter{width:100%;height:4px;background:rgba(148,163,184,.15);border-radius:2px;overflow:hidden}
.score-meter u{display:block;height:100%;background:linear-gradient(90deg,#15803d,#b45309,#991b1b);border-radius:2px;transition:width .6s ease}
.metric-cards{flex:1;display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:10px}
.metric{display:grid;gap:4px;padding:14px 16px;border-radius:14px;border:1px solid rgba(255,255,255,.34);background:rgba(255,255,255,.16)}
.metric label{font-size:12px;color:#64748b}
.metric b{font-size:24px;font-weight:950}

.attck-panel{overflow:hidden}
.panel-title{height:44px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;border-bottom:1px solid rgba(255,255,255,.38);background:rgba(255,255,255,.2)}
.panel-title strong{font-size:14px}
.panel-title span{color:#687789;font-size:12px}
.kill-chain-row{display:flex;padding:16px 12px 12px;gap:6px;overflow-x:auto}
.kc-cell{flex:1;min-width:68px;display:grid;justify-items:center;gap:4px;padding:10px 6px;border-radius:12px;border:1px solid rgba(148,163,184,.15);background:rgba(148,163,184,.06);transition:all .2s;position:relative;overflow:hidden}
.kc-cell.active{border-color:rgba(59,130,246,.25);background:rgba(59,130,246,.08)}
.kc-cell.s-access.active{border-color:rgba(220,38,38,.25);background:rgba(220,38,38,.08)}
.kc-cell.s-exec.active{border-color:rgba(194,65,12,.25);background:rgba(194,65,12,.08)}
.kc-cell.s-lateral.active{border-color:rgba(79,70,229,.25);background:rgba(79,70,229,.08)}
.kc-cell.s-c2.active{border-color:rgba(67,56,202,.25);background:rgba(67,56,202,.08)}
.kc-label{font-size:10px;color:#64748b;text-align:center;line-height:1.3}
.kc-cell.active .kc-label{color:#334155;font-weight:700}
.kc-count{font-size:18px;font-weight:950;color:#172033}
.kc-bar{display:block;width:60%;background:linear-gradient(to top,#3b82f6,#60a5fa);border-radius:3px;min-height:2px;position:absolute;bottom:0;left:20%}
.kc-cell.s-access .kc-bar{background:linear-gradient(to top,#dc2626,#f87171)}
.kc-cell.s-exec .kc-bar{background:linear-gradient(to top,#c2410c,#fb923c)}
.kc-cell.s-lateral .kc-bar{background:linear-gradient(to top,#4f46e5,#818cf8)}
.kc-cell.s-c2 .kc-bar{background:linear-gradient(to top,#4338ca,#6366f1)}
.kc-status{font-size:8px;color:#3b82f6;line-height:1}
.kc-cell.s-access .kc-status{color:#dc2626}
.kc-cell.s-exec .kc-status{color:#c2410c}

.dual-panel{display:grid;grid-template-columns:1fr 320px;gap:14px;align-items:start}
.chains-panel{overflow:hidden;min-height:0}
.panel{overflow:hidden;border:1px solid rgba(255,255,255,.58);background:rgba(255,255,255,.3);border-radius:24px;box-shadow:0 24px 80px rgba(49,65,88,.14),inset 0 1px 0 rgba(255,255,255,.55);backdrop-filter:blur(28px)}
.chains-panel{display:grid;grid-template-rows:44px minmax(0,1fr)}
.empty-card{padding:42px;text-align:center;color:#64748b}
.chain-list{display:grid;gap:10px;padding:12px;max-height:calc(100vh - 420px);overflow:auto}
.chain-card{padding:14px;border-radius:16px;border:1px solid rgba(255,255,255,.4);background:rgba(255,255,255,.2);transition:all .15s;cursor:pointer}
.chain-card:hover{border-color:rgba(59,130,246,.25);background:rgba(255,255,255,.28)}
.chain-card.open{cursor:default}
.chain-top{display:flex;align-items:center;gap:14px}
.chain-score{min-width:68px;text-align:center;padding:8px 10px;border-radius:12px;background:rgba(148,163,184,.12);border:1px solid rgba(255,255,255,.24)}
.chain-score strong{display:block;font-size:24px;font-weight:950;line-height:1.1}
.chain-score em{display:block;font-size:10px;font-weight:800;margin-top:1px}
.chain-score.critical strong{color:#991b1b}.chain-score.critical em{color:#991b1b}
.chain-score.high strong{color:#b45309}.chain-score.high em{color:#b45309}
.chain-score.medium strong{color:#a16207}.chain-score.medium em{color:#a16207}
.chain-score.low strong{color:#15803d}.chain-score.low em{color:#15803d}
.chain-core{flex:1;display:grid;gap:4px;min-width:0}
.chain-core b{font-size:15px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chain-stage-flow{display:flex;flex-wrap:wrap;align-items:center;gap:0}
.flow-step{font-size:11px;font-weight:700;padding:2px 8px;border-radius:8px;display:flex;align-items:center;gap:4px}
.flow-step.s-recon{color:#475569;background:rgba(100,116,139,.1)}
.flow-step.s-access{color:#991b1b;background:rgba(220,38,38,.1)}
.flow-step.s-exec{color:#9a3412;background:rgba(194,65,12,.1)}
.flow-step.s-persist{color:#92400e;background:rgba(180,83,9,.1)}
.flow-step.s-priv{color:#a16207;background:rgba(202,138,4,.1)}
.flow-step.s-lateral{color:#4338ca;background:rgba(79,70,229,.1)}
.flow-step.s-cred{color:#be185d;background:rgba(219,39,119,.1)}
.flow-step.s-c2{color:#3730a3;background:rgba(67,56,202,.1)}
.flow-arrow{font-style:normal;color:#94a3b8;margin:0 2px}
.chain-meta-compact{display:flex;gap:12px;font-size:11px;color:#64748b;white-space:nowrap}
.chain-meta-compact .time-range{color:#94a3b8}

.chain-detail{margin-top:12px;padding-top:12px;border-top:1px solid rgba(255,255,255,.4)}
.detail-strip{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:10px}
.cat-tag{padding:2px 8px;border-radius:6px;font-size:10px;font-weight:700;background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.18);color:#1d4ed8}
.hs-badge{padding:2px 8px;border-radius:6px;font-size:10px;font-weight:700}
.hs-badge.candidate{background:rgba(59,130,246,.1);color:#1d4ed8}
.hs-badge.confirmed{background:rgba(22,163,74,.1);color:#15803d}
.hs-badge.rejected{background:rgba(148,163,184,.1);color:#64748b}
.v2-tag{font-size:10px;color:#64748b;padding:2px 6px;background:rgba(148,163,184,.08);border-radius:4px}

.evidence-section{margin-top:10px}
.evidence-title{font-size:12px;font-weight:700;margin-bottom:8px;color:#475569}
.timeline{display:grid;gap:6px;max-height:320px;overflow:auto;padding-right:4px}
.tl-entry{display:flex;gap:10px;padding:8px 10px;border-radius:10px;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.22)}
.tl-marker{min-width:22px;height:22px;display:flex;align-items:center;justify-content:center;border-radius:50%;font-size:10px;font-weight:800;background:rgba(148,163,184,.15);color:#64748b}
.tl-marker.critical{background:rgba(220,38,38,.15);color:#991b1b}
.tl-marker.high{background:rgba(194,65,12,.15);color:#9a3412}
.tl-body{flex:1;display:grid;gap:3px;min-width:0}
.tl-top{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.tl-top b{font-size:12px;font-weight:700}
.sev-sm{padding:1px 6px;border-radius:4px;font-size:9px;font-weight:800}
.sev-sm.critical{background:rgba(220,38,38,.12);color:#991b1b}
.sev-sm.high{background:rgba(194,65,12,.12);color:#9a3412}
.sev-sm.medium{background:rgba(202,138,4,.12);color:#a16207}
.sev-sm.low{background:rgba(22,163,74,.1);color:#15803d}
.stage-sm{padding:1px 6px;border-radius:4px;font-size:9px;background:rgba(79,70,229,.08);color:#4338ca}
.tl-detail{display:flex;flex-wrap:wrap;gap:8px;font-size:10px;color:#64748b}
.tl-summary{flex-basis:100%;color:#94a3b8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:9px}

.flow-step.missing{opacity:.35;text-decoration:line-through}
.solo-flag,.partial-flag{font-style:normal;font-size:9px;padding:1px 6px;border-radius:6px;margin-left:6px;font-weight:700;vertical-align:middle;display:inline-block;line-height:1.4}
.solo-flag{background:rgba(245,158,11,.15);color:#b45309}
.partial-flag{background:rgba(59,130,246,.12);color:#2563eb}
.seed-tag{padding:2px 8px;border-radius:6px;font-size:10px;font-weight:700;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.18);color:#15803d}
.partial-warn{font-size:10px;color:#b45309;font-weight:700}
.standalone-warn{font-size:10px;color:#d97706;font-weight:700}
.missing-strip{font-size:11px;color:#94a3b8;margin-top:8px;padding:6px 10px;border-radius:8px;background:rgba(245,158,11,.06);border:1px dashed rgba(245,158,11,.2)}
.missing-stage{padding:1px 6px;border-radius:4px;font-size:10px;background:rgba(245,158,11,.1);color:#b45309;margin-left:4px}
.traffic-section{border-top:1px dashed rgba(59,130,246,.18);padding-top:10px}
.traffic-title{color:#2563eb}
.traffic-entry{border-color:rgba(59,130,246,.12)}
.flow-marker{background:rgba(59,130,246,.12);color:#2563eb}

.side-panel{display:grid;grid-template-rows:44px minmax(0,1fr);min-height:0}
.side-content{display:grid;gap:14px;padding:14px;overflow:auto;max-height:calc(100vh - 300px)}
.side-block strong{display:block;font-size:12px;margin-bottom:8px;color:#334155}
.hot-item{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(148,163,184,.1);font-size:12px;gap:8px}
.hot-item:last-child{border-bottom:none}
.hot-item span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hot-item em{font-size:12px;font-weight:700;color:#64748b}
.hot-item em.critical{color:#991b1b}
.hot-item em.high{color:#b45309}

.notice.error{margin:8px 0;padding:12px 18px;border-radius:14px;border:1px solid rgba(220,38,38,.3);background:rgba(220,38,38,.12);color:#991b1b;font-size:13px}

@media(max-width:900px){.dual-panel{grid-template-columns:1fr}.score-row{flex-direction:column}.score-card{flex:auto}}
</style>
