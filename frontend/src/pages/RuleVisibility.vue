<template>
  <section class="rules-page">
    <section class="query-panel">
      <label><span>规则类型</span><select v-model="filters.category" @change="resetAndLoad"><option value="">全部</option><option value="traffic">流量</option><option value="runtime">运行时</option><option value="rasp">RASP</option><option value="log_audit">日志审计</option></select></label>
      <label><span>状态</span><select v-model="filters.status" @change="resetAndLoad"><option value="">全部</option><option value="enabled">开启</option><option value="candidate">候选</option></select></label>
      <label><span>攻击阶段</span><select v-model="filters.stage" @change="resetAndLoad"><option value="">全部</option><option v-for="stage in stages" :key="stage" :value="stage">{{ stageLabel(stage) }}</option></select></label>
      <label><span>关键字</span><input v-model.trim="filters.source" placeholder="规则名称 / ID / 字段" @keydown.enter="resetAndLoad"></label>
      <button class="primary" @click="resetAndLoad" :disabled="loading">查询</button>
    </section>

    <div v-if="error" class="notice error">{{ error }}</div>

    <article class="panel events-panel">
      <div class="panel-title"><strong>规则清单</strong><span>{{ `${inventory.total} 条 / 当前页可显示 ${pageSize} 条` }}</span></div>
      <div ref="tableWrap" :class="['table-wrap', { updating: loading && hasLoaded }]">
        <table>
          <thead><tr><th>规则</th><th>匹配字段</th><th>类型</th><th>阶段</th><th class="center">严重性</th><th class="center">状态</th></tr></thead>
          <tbody>
            <tr v-if="loading && !hasLoaded"><td colspan="6" class="empty-cell">正在读取生效规则</td></tr>
            <tr v-else-if="!pagedItems.length"><td colspan="6" class="empty-cell">暂无匹配规则</td></tr>
            <tr v-for="item in pagedItems" :key="item.id">
              <td><b>{{ item.name }}</b><small>{{ item.id }}</small></td>
              <td>{{ item.field || '-' }}<small>{{ item.operator || 'contains' }}</small></td>
              <td>{{ item.category?.toUpperCase() }}</td>
              <td>{{ stageLabel(item.stage) }}</td>
              <td class="center"><button :class="['score-chip', severityChipClass(item.severity)]" :disabled="savingRule === item.id" @click="openSeverityDialog(item)">{{ severityLabel(item.severity) }}</button></td>
              <td class="center"><button :class="['status-button', item.enabled ? 'on' : 'off']" :disabled="savingRule === item.id" @click="toggleRule(item)">{{ item.enabled ? '开启' : '关闭' }}</button></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="pager">
        <button @click="prevPage" :disabled="loading || page === 1">上一页</button>
        <span>第 {{ page }} 页</span>
        <button @click="nextPage" :disabled="loading || pagedItems.length < pageSize">下一页</button>
      </div>
    </article>

    <div v-if="severityDialog" class="modal-mask" @click.self="closeSeverityDialog">
      <section class="score-modal">
        <div class="modal-head"><strong>修改严重性</strong><button @click="closeSeverityDialog">×</button></div>
        <div class="modal-body">
          <p>{{ severityDialog.name }}</p>
          <label><span>当前严重性</span><input :value="severityLabel(severityDialog.severity)" disabled></label>
          <label><span>修改为</span><select v-model="severityDialog.next_severity"><option value="critical">严重</option><option value="high">高</option><option value="medium">中</option><option value="low">低</option><option value="info">信息</option></select></label>
        </div>
        <div class="modal-actions"><button @click="closeSeverityDialog">取消</button><button class="primary" :disabled="savingRule === severityDialog.id" @click="confirmSeverityDialog">确认</button></div>
      </section>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ruleClient } from '../api/domain'

const stages = ['recon', 'initial_access', 'execution', 'persistence', 'privilege_escalation', 'lateral_movement', 'c2_exfiltration']
const filters = reactive({ category: '', stage: '', source: '', status: '' })
const inventory = reactive({ items: [], total: 0 })
const loading = ref(false)
const savingRule = ref('')
const hasLoaded = ref(false)
const error = ref('')
const page = ref(1)
const pageSize = 12
const severityDialog = ref(null)

const totalPages = computed(() => Math.max(1, Math.ceil(inventory.items.length / pageSize)))
const pagedItems = computed(() => inventory.items.slice((page.value - 1) * pageSize, page.value * pageSize))

function normalizeRule(rule) {
  const field = rule.field || rule.match_field || rule.conditions?.[0]?.field || '-'
  const operator = rule.operator || rule.match_operator || rule.conditions?.[0]?.operator || (rule.regex ? 'regex' : 'contains')
  return {
    id: rule.id,
    name: rule.name || rule.id,
    category: rule.category || '-',
    stage: rule.stage_hint || rule.stage || rule.attack_stage || '',
    field,
    operator,
    severity: String(rule.severity || 'medium').toLowerCase(),
    score: rule.score_hint ?? rule.score ?? rule.adjusted_score ?? '-',
    original_score: rule.original_score ?? rule.score_hint ?? rule.score,
    enabled: rule.enabled !== false,
    candidate: rule.candidate !== false,
  }
}

function localFilter(list) {
  return list.filter((item) => {
    if (filters.category && item.category !== filters.category) return false
    if (filters.stage && item.stage !== filters.stage) return false
    if (filters.status === 'enabled' && !item.enabled) return false
    if (filters.status === 'candidate' && !item.candidate) return false
    if (filters.source) {
      const q = filters.source.toLowerCase()
      const haystack = [item.name, item.id, item.field, item.operator].join(' ').toLowerCase()
      if (!haystack.includes(q)) return false
    }
    return true
  })
}

function resetAndLoad() { page.value = 1; loadData() }
async function loadData() {
  loading.value = true
  error.value = ''
  try {
    const rules = await ruleClient.inventory({ status: 'enabled' })
    inventory.items = localFilter((rules?.items || []).map(normalizeRule))
    inventory.total = inventory.items.length
    if (page.value > totalPages.value) page.value = totalPages.value
    hasLoaded.value = true
  } catch (err) {
    error.value = err?.message || '规则管理数据读取失败'
  } finally {
    loading.value = false
  }
}
function openSeverityDialog(item) { severityDialog.value = { ...item, next_severity: item.severity || 'medium' } }
function closeSeverityDialog() { severityDialog.value = null }
async function confirmSeverityDialog() {
  if (!severityDialog.value) return
  const item = inventory.items.find((row) => row.id === severityDialog.value.id)
  if (!item) return
  savingRule.value = item.id
  error.value = ''
  try {
    const saved = await ruleClient.updateRuleItem(item.id, { severity: severityDialog.value.next_severity })
    item.severity = saved?.severity || severityDialog.value.next_severity
    closeSeverityDialog()
  } catch (err) {
    error.value = err?.message || '规则严重性保存失败'
  } finally {
    savingRule.value = ''
  }
}
async function toggleRule(item) {
  savingRule.value = item.id
  error.value = ''
  try {
    const nextEnabled = !item.enabled
    const saved = await ruleClient.updateRuleItem(item.id, { enabled: nextEnabled })
    item.enabled = saved?.enabled ?? !item.enabled
    item.live_rules = saved?.live_rules
    item.hot_reloaded = saved?.hot_reloaded
    if (filters.status) await loadData()
  } catch (err) {
    error.value = err?.message || '规则状态保存失败'
  } finally {
    savingRule.value = ''
  }
}
function prevPage() { if (page.value > 1) page.value -= 1 }
function nextPage() { if (pagedItems.value.length >= pageSize && page.value < totalPages.value) page.value += 1 }
function stageLabel(stage) { return ({ recon: '信息收集', initial_access: '初始入侵', execution: '执行载荷', persistence: '持久化', privilege_escalation: '提权', lateral_movement: '横向移动', c2_exfiltration: '控制与外联' })[stage] || stage || '-' }
function severityLabel(value) { return { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' }[value] || '中' }
function severityChipClass(value) { return value === 'critical' ? 'sev-high' : value === 'high' ? 'sev-high' : value === 'medium' ? 'sev-medium' : 'sev-low' }
onMounted(loadData)
</script>

<style scoped>
.rules-page{height:100%;min-height:0;display:grid;grid-template-rows:auto auto minmax(0,1fr);gap:10px;padding:12px;color:#172033;box-sizing:border-box}.query-panel,.panel{border:1px solid rgba(255,255,255,.58);background:rgba(255,255,255,.3);border-radius:22px;box-shadow:0 22px 70px rgba(49,65,88,.12),inset 0 1px 0 rgba(255,255,255,.55);backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px)}.query-panel{display:grid;grid-template-columns:1fr 1fr 1fr 1fr 1fr 1.2fr auto;gap:8px;align-items:end;padding:10px}.query-panel label{display:grid;gap:4px;color:#536170;font-size:12px}input,select{height:30px;border:1px solid rgba(255,255,255,.66);border-radius:11px;background:rgba(255,255,255,.46);color:#16202c;padding:0 10px;font-size:12px;outline:0}.primary,button{height:30px;padding:0 11px;border:1px solid rgba(255,255,255,.6);border-radius:11px;background:rgba(255,255,255,.36);color:#17202c;cursor:pointer;font-size:12px;backdrop-filter:blur(16px)}button:disabled{opacity:.45;cursor:not-allowed}.primary{border:0;background:linear-gradient(135deg,rgba(14,165,233,.88),rgba(52,211,153,.86));color:white;font-weight:900}.events-panel{min-height:0;display:grid;grid-template-rows:40px minmax(0,1fr) 38px;overflow:hidden}.panel-title{height:40px;display:flex;align-items:center;justify-content:space-between;padding:0 14px;border-bottom:1px solid rgba(255,255,255,.38);background:rgba(255,255,255,.2)}.panel-title strong{font-size:14px}.panel-title span{color:#687789;font-size:12px}.table-wrap{min-height:0;overflow:auto}table{width:100%;border-collapse:separate;border-spacing:0 5px;padding:6px 8px;min-width:980px}th{height:26px;color:#607084;font-size:12px;font-weight:700;text-align:left;padding:0 9px;position:sticky;top:0;background:rgba(245,248,252,.94);z-index:1}th.center,td.center{text-align:center}td{height:37px;padding:0 9px;background:rgba(255,255,255,.42);border-top:1px solid rgba(255,255,255,.42);border-bottom:1px solid rgba(218,226,238,.45);font-size:12px;vertical-align:middle}td:first-child{border-radius:13px 0 0 13px}td:last-child{border-radius:0 13px 13px 0}small{display:block;color:#6a7889;font-size:11px;margin-top:1px}.empty-cell{text-align:center;color:#718096;padding:28px}.pill,.origin,.status-button,.score-chip{border-radius:999px;padding:4px 9px;font-size:12px;display:inline-flex;align-items:center;justify-content:center;width:fit-content;border:1px solid rgba(255,255,255,.55);margin:auto}.ok,.status-button.on,.origin.internal{background:rgba(34,197,94,.16);color:#15803d}.warn{background:rgba(245,158,11,.18);color:#92400e}.bad,.status-button.off{background:rgba(239,68,68,.16);color:#b91c1c}.origin.external{background:rgba(59,130,246,.16);color:#1d4ed8}.score-chip{min-width:58px;font-weight:800}.score-chip i{width:8px;height:8px;border-radius:50%;margin-right:6px}.score-chip.sev-high{background:rgba(239,68,68,.16);color:#b91c1c}.score-chip.sev-high i{background:#ef4444}.score-chip.sev-medium{background:rgba(245,158,11,.18);color:#92400e}.score-chip.sev-medium i{background:#f59e0b}.score-chip.sev-low{background:rgba(59,130,246,.16);color:#1d4ed8}.score-chip.sev-low i{background:#3b82f6}.pager{display:flex;justify-content:center;align-items:center;gap:12px;color:#687789;font-size:12px}.notice.error{padding:9px 12px;border-radius:13px;background:rgba(239,68,68,.16);color:#991b1b}.modal-mask{position:fixed;inset:0;z-index:20;display:grid;place-items:center;background:rgba(15,23,42,.28);backdrop-filter:blur(10px)}.score-modal{width:min(400px,92vw);border:1px solid rgba(255,255,255,.62);border-radius:20px;background:rgba(248,250,252,.9);box-shadow:0 30px 90px rgba(15,23,42,.24);overflow:hidden}.modal-head{height:44px;display:flex;align-items:center;justify-content:space-between;padding:0 15px;border-bottom:1px solid rgba(203,213,225,.6)}.modal-head button{border:0;background:transparent;font-size:18px}.modal-body{display:grid;gap:9px;padding:14px}.modal-body p{margin:0 0 4px;font-size:13px;color:#475569}.modal-actions{display:flex;justify-content:flex-end;gap:10px;padding:11px 15px;border-top:1px solid rgba(203,213,225,.6)}@media(max-width:1280px){.query-panel{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:720px){.query-panel{grid-template-columns:1fr}}
</style>
