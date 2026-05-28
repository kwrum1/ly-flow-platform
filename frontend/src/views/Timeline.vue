<template>
  <div class="page-shell timeline-page">
    <section class="timeline-hero">
      <div>
        <span class="page-kicker">Evidence Timeline</span>
        <h1 class="page-title" data-testid="timeline-title">Timeline 时间线</h1>
        <p class="page-subtitle">按事件真实时间排序，复盘 Incident、Session 或 Agent 的跨源证据链。</p>
      </div>
      <div class="timeline-summary">
        <span>{{ timelineItems.length }} 条证据</span>
        <span>{{ Object.keys(groupedBySource).length }} 个来源</span>
      </div>
    </section>

    <section class="surface-card filter-card">
      <div class="filter-row">
        <el-input v-model="filters.incidentId" clearable placeholder="Incident / Session / Agent ID" style="max-width: 320px" />
        <el-select v-model="filters.sourceModule" clearable placeholder="source_module" style="width: 160px">
          <el-option label="DPI" value="dpi" />
          <el-option label="Runtime" value="runtime" />
          <el-option label="RASP" value="rasp" />
          <el-option label="XDR" value="xdr" />
        </el-select>
        <el-button type="primary" @click="loadTimeline">加载时间线</el-button>
      </div>
    </section>

    <div v-if="error" class="page-state error" data-testid="timeline-error-state">
      <span>{{ error }}</span>
      <el-button type="primary" plain @click="loadTimeline">重试加载</el-button>
    </div>

    <section class="surface-card timeline-card">
      <div class="card-header">
        <div>
          <h2 class="card-title">Chronological Chain</h2>
          <p class="card-caption">禁止按 Redis ID 替代业务时间；所有记录按 timestamp 升序排列</p>
        </div>
      </div>
      <div v-if="loading" class="table-state">加载时间线中...</div>
      <div v-else-if="timelineItems.length === 0" class="table-state" data-testid="timeline-empty-state">未找到时间线数据，请检查 ID 或返回 Incidents。</div>
      <div v-else class="timeline-list" data-testid="timeline-list">
        <article v-for="item in timelineItems" :key="item.id || `${item.timestamp}-${item.source}`" class="timeline-item" :data-timestamp="item.timestamp">
          <div class="timeline-dot" />
          <div class="timeline-body">
            <div class="timeline-meta">
              <span class="time-cell">{{ formatTime(item.timestamp) }}</span>
              <span class="status-badge source">{{ sourceLabel(item.source) }}</span>
              <span class="risk-badge" :class="item.severity">{{ severityText(item.severity) }}</span>
            </div>
            <strong>{{ item.title || item.ruleName || item.eventType || '安全事件' }}</strong>
            <p>{{ item.detail || item.ruleName || '-' }}</p>
            <div class="timeline-context mono">
              <span><em>Entity</em>{{ item.entityId || '-' }}</span>
              <span><em>Raw</em>{{ item.rawReference || '-' }}</span>
              <span><em>Path</em>{{ item.srcIp || '-' }} → {{ item.dstIp || item.domain || '-' }}</span>
            </div>
          </div>
        </article>
      </div>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { isRequestCanceled } from '../api'
import { timelineAPI } from '../api/events'
import { groupTimelineBySource, normalizeTimelineItems } from '../domain/timeline'

const route = useRoute()
const timelineItems = ref([])
const loading = ref(false)
const error = ref('')
const filters = ref({ incidentId: route.params.id || '', sourceModule: '' })

const severityMap = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
const sourceMap = { events: 'DPI', unified: 'Runtime', xdr: 'XDR', rasp: 'RASP' }

const groupedBySource = computed(() => groupTimelineBySource(timelineItems.value))
const severityText = (severity) => severityMap[severity] || severity || '未知'
const sourceLabel = (source) => sourceMap[source] || String(source || 'events').toUpperCase()
const formatTime = (value) => {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  return date.toLocaleString('zh-CN')
}

const loadTimeline = async () => {
  loading.value = true
  error.value = ''
  try {
    const id = filters.value.incidentId || route.params.id || ''
    const response = id
      ? await timelineAPI.detail(id, { source_module: filters.value.sourceModule || undefined })
      : await timelineAPI.list({ source_module: filters.value.sourceModule || undefined })
    timelineItems.value = normalizeTimelineItems(response.items || [])
  } catch (err) {
    if (!isRequestCanceled(err)) {
      error.value = err?.message || 'Timeline 加载失败'
      timelineItems.value = []
    }
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await loadTimeline()
})
</script>

<style scoped>
.timeline-page { display: flex; flex-direction: column; gap: 18px; }
.timeline-hero { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; }
.timeline-summary, .filter-row, .timeline-meta, .timeline-context { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.timeline-summary span { padding: 9px 12px; border: 1px solid var(--border-color); border-radius: 999px; background: rgba(15, 23, 42, 0.58); color: var(--text-secondary); font-weight: 850; }
.filter-card { padding: 16px; }
.timeline-list { position: relative; display: flex; flex-direction: column; gap: 14px; padding: 8px 4px 4px; }
.timeline-item { display: grid; grid-template-columns: 28px minmax(0, 1fr); gap: 12px; }
.timeline-dot { width: 14px; height: 14px; margin: 8px auto 0; border: 2px solid var(--border-glow); border-radius: 999px; background: rgba(56, 189, 248, 0.32); box-shadow: 0 0 18px rgba(56, 189, 248, 0.28); }
.timeline-body { padding: 14px; border: 1px solid var(--border-light); border-radius: 16px; background: rgba(8, 18, 32, 0.58); }
.timeline-body strong { display: block; margin-top: 8px; color: var(--text-primary); }
.timeline-body p { color: var(--text-secondary); margin: 6px 0 10px; }
.timeline-context span { color: var(--text-secondary); font-size: 12px; }
.timeline-context em { margin-right: 6px; color: var(--text-muted); font-style: normal; text-transform: uppercase; }
@media (max-width: 1120px) { .timeline-hero { align-items: flex-start; flex-direction: column; } }
</style>
