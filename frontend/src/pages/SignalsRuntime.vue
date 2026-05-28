<template>
  <section class="ops-page">
    <header class="page-head"><div><p>{{ isTrace ? 'TRACE 分析' : 'RASP 与 Runtime' }}</p><h2>{{ isTrace ? '调用链路与追踪' : '运行时防护态势' }}</h2><span>所有卡片从 XDR、RASP、Trace 后端接口读取，用于呈现运行时信号与链路调查。</span></div><button @click="loadAll" :disabled="loading">刷新信号</button></header>
    <div v-if="error" class="state-card error-state">{{ error }}</div>
    <section class="metric-grid">
      <article v-for="metric in metrics" :key="metric.label" class="surface-card metric-card"><span>{{ metric.label }}</span><strong>{{ metric.value }}</strong><em>{{ metric.hint }}</em></article>
    </section>
    <section class="content-grid">
      <article class="surface-card list-card"><div class="panel-heading"><strong>{{ isTrace ? '追踪会话' : '运行时事件' }}</strong><span>{{ primaryRows.length }} 条</span></div><div v-if="!primaryRows.length" class="empty-state">当前没有运行时或追踪事件。</div><div v-for="item in primaryRows" :key="item.id || item.trace_id || item.event_id || JSON.stringify(item).slice(0,30)" class="row"><strong>{{ pickText(item.title || item.name || item.event_type || item.trace_id, '未命名记录') }}</strong><span>{{ pickText(item.summary || item.service || item.source || item.rule_name, '该记录没有摘要字段') }}</span></div></article>
      <article class="surface-card list-card"><div class="panel-heading"><strong>{{ isTrace ? '追踪事件' : '信号来源' }}</strong><span>{{ secondaryRows.length }} 条</span></div><div v-if="!secondaryRows.length" class="empty-state">当前没有信号来源统计。</div><div v-for="item in secondaryRows" :key="item.id || item.source || item.event_id || JSON.stringify(item).slice(0,30)" class="row"><strong>{{ pickText(item.source || item.title || item.name || item.event_type, '未命名来源') }}</strong><span>{{ pickText(item.count ?? item.summary ?? item.status ?? item.severity, '该记录没有详情字段') }}</span></div></article>
    </section>
  </section>
</template>
<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { signalClient } from '../api/domain'
import { normalizeItems, pickText } from '../shared/api-normalize'
const props = defineProps({ mode: { type: String, default: 'runtime' } })
const loading = ref(false); const error = ref(''); const xdrStats = ref({}); const raspStats = ref({}); const traceStats = ref({}); const primaryRows = ref([]); const secondaryRows = ref([])
const isTrace = computed(() => props.mode === 'trace')
const metrics = computed(() => isTrace.value ? [
  { label:'追踪会话', value: traceStats.value.total_sessions ?? traceStats.value.sessions ?? primaryRows.value.length, hint:'Trace 统计接口' },
  { label:'追踪事件', value: traceStats.value.total_events ?? secondaryRows.value.length, hint:'Trace 事件接口' },
  { label:'异常链路', value: traceStats.value.error_count ?? traceStats.value.errors ?? 0, hint:'链路异常' },
  { label:'平均耗时', value: traceStats.value.avg_duration_ms ?? traceStats.value.average_latency ?? 0, hint:'毫秒' },
] : [
  { label:'XDR 事件', value: xdrStats.value.total_events ?? xdrStats.value.total ?? 0, hint:'XDR 统计接口' },
  { label:'RASP 事件', value: raspStats.value.total_events ?? raspStats.value.total ?? primaryRows.value.length, hint:'RASP 统计接口' },
  { label:'受保护服务', value: raspStats.value.protected_services ?? raspStats.value.services ?? 0, hint:'运行时覆盖' },
  { label:'信号来源', value: secondaryRows.value.length, hint:'来源接口' },
])
async function loadAll(){ loading.value=true; error.value=''; try{ if(isTrace.value){ const [s,a,b]=await Promise.all([signalClient.traceStats(), signalClient.traceSessions(), signalClient.traceEvents()]); traceStats.value=s||{}; primaryRows.value=normalizeItems(a).items; secondaryRows.value=normalizeItems(b).items } else { const [xs,rs,re,src]=await Promise.all([signalClient.xdrStats(), signalClient.raspStats(), signalClient.raspEvents(), signalClient.xdrSources()]); xdrStats.value=xs||{}; raspStats.value=rs||{}; primaryRows.value=normalizeItems(re).items; secondaryRows.value=normalizeItems(src).items } }catch(e){ error.value=e?.message||'无法读取运行时信号' }finally{ loading.value=false } }
watch(() => props.mode, loadAll); onMounted(loadAll)
</script>
<style scoped>
.ops-page{display:grid;gap:22px;padding:28px}.page-head{display:flex;justify-content:space-between;gap:24px;padding:30px;border-radius:26px;border:1px solid var(--border-light);background:linear-gradient(135deg,rgba(17,31,52,.94),rgba(8,18,32,.78))}.page-head p{margin:0 0 8px;color:var(--primary-light);font-size:12px;font-weight:900;letter-spacing:.16em}.page-head h2{margin:0;font-size:clamp(32px,4vw,54px);letter-spacing:-.055em}.page-head span{display:block;max-width:760px;margin-top:12px;color:var(--text-secondary);line-height:1.8}button{height:44px;padding:0 18px;border:0;border-radius:14px;color:#06101d;font-weight:900;background:linear-gradient(135deg,#7dd3fc,#34d399);cursor:pointer}.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}.content-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.metric-card,.list-card{padding:22px}.metric-card span,.metric-card em,.row span{color:var(--text-secondary);font-style:normal}.metric-card strong{display:block;margin:8px 0;font-size:30px}.panel-heading{display:flex;justify-content:space-between;margin-bottom:16px}.row{display:grid;gap:8px;padding:14px 0;border-top:1px solid var(--border-light)}.state-card,.empty-state{padding:18px;color:var(--text-secondary);border-radius:16px;border:1px solid var(--border-light);background:rgba(255,255,255,.04)}.error-state{color:#fecaca;border-color:rgba(248,113,113,.34);background:rgba(248,113,113,.12)}@media(max-width:1080px){.metric-grid,.content-grid{grid-template-columns:1fr}.page-head{flex-direction:column;align-items:flex-start}}
</style>
