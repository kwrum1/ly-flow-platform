<template>
  <div class="page-shell topology-page">
    <section class="topology-hero">
      <div>
        <span class="page-kicker">Topology Graph</span>
        <h1 class="page-title" data-testid="topology-title">Topology 拓扑</h1>
        <p class="page-subtitle">聚合资产、服务、远端域名与 Incident 关系，避免渲染无界原始流量。</p>
      </div>
      <div class="topology-summary">
        <span>{{ graph.nodes.length }} 节点</span>
        <span>{{ graph.edges.length }} 聚合边</span>
      </div>
    </section>

    <div v-if="error" class="page-state error" data-testid="topology-error-state">
      <span>{{ error }}</span>
      <el-button type="primary" plain @click="loadTopology">重试加载</el-button>
    </div>

    <section class="topology-grid">
      <article class="surface-card graph-card" data-testid="topology-graph">
        <div class="card-header">
          <div>
            <h2 class="card-title">关系图</h2>
            <p class="card-caption">节点按风险着色，边显示聚合次数</p>
          </div>
          <el-button type="primary" @click="loadTopology">刷新拓扑</el-button>
        </div>
        <div v-if="loading" class="table-state">加载拓扑中...</div>
        <div v-else-if="graph.nodes.length === 0" class="table-state" data-testid="topology-empty-state">暂无拓扑数据。</div>
        <div v-else class="graph-board">
          <button
            v-for="node in graph.nodes"
            :key="node.id"
            type="button"
            class="graph-node"
            :class="[`risk-${node.risk}`, { active: selectedNode?.id === node.id }]"
            :data-node-type="node.type"
            @click="selectedNode = node"
          >
            <strong>{{ node.label }}</strong>
            <em>{{ node.type }}</em>
          </button>
        </div>
      </article>

      <aside class="surface-card detail-card" data-testid="topology-detail">
        <div class="card-header">
          <div>
            <h2 class="card-title">详情</h2>
            <p class="card-caption">点击节点查看风险、能力与关联边</p>
          </div>
        </div>
        <div v-if="!selectedNode" class="table-state">请选择节点。</div>
        <template v-else>
          <div class="node-detail">
            <span class="risk-badge" :class="selectedNode.risk">{{ selectedNode.risk }}</span>
            <h3>{{ selectedNode.label }}</h3>
            <p>{{ selectedNode.id }}</p>
          </div>
          <div class="edge-list">
            <div v-for="edge in selectedEdges" :key="edge.id" class="edge-item">
              <strong>{{ edge.relation }}</strong>
              <span class="mono">{{ edge.source }} → {{ edge.target }}</span>
              <em>{{ edge.count }} 次 · {{ edge.risk }}</em>
            </div>
          </div>
        </template>
      </aside>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { isRequestCanceled } from '../api'
import api from '../api'
import { normalizeList } from '../api/adapters'
import { incidentsAPI } from '../api/events'
import { buildTopology } from '../domain/topology'

const graph = ref({ nodes: [], edges: [] })
const selectedNode = ref(null)
const loading = ref(false)
const error = ref('')

const selectedEdges = computed(() => {
  if (!selectedNode.value) return []
  return graph.value.edges.filter((edge) => edge.source === selectedNode.value.id || edge.target === selectedNode.value.id)
})

const loadTopology = async () => {
  loading.value = true
  error.value = ''
  try {
    const [assetPayload, incidentPayload, topologyPayload] = await Promise.all([
      api.get('/assets', { params: { limit: 100 } }),
      incidentsAPI.list({ limit: 100 }),
      api.get('/topology', { params: { limit: 1000 } }).catch(() => ({ items: [] })),
    ])
    const assets = normalizeList(assetPayload, ['items', 'hosts', 'list']).items
    const flows = normalizeList(topologyPayload, ['edges', 'flows', 'items', 'list']).items
    graph.value = buildTopology({ assets, flows, incidents: incidentPayload.items || [] })
    selectedNode.value = graph.value.nodes[0] || null
  } catch (err) {
    if (!isRequestCanceled(err)) {
      error.value = err?.message || 'Topology 加载失败'
      graph.value = { nodes: [], edges: [] }
      selectedNode.value = null
    }
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  await loadTopology()
})
</script>

<style scoped>
.topology-page { display: flex; flex-direction: column; gap: 18px; }
.topology-hero { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; }
.topology-summary { display: flex; flex-wrap: wrap; gap: 10px; }
.topology-summary span { padding: 9px 12px; border: 1px solid var(--border-color); border-radius: 999px; background: rgba(15, 23, 42, 0.58); color: var(--text-secondary); font-weight: 850; }
.topology-grid { display: grid; grid-template-columns: minmax(0, 1.4fr) 340px; gap: 18px; }
.graph-board { min-height: 420px; display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); align-content: start; gap: 16px; padding: 12px; border: 1px dashed var(--border-light); border-radius: 18px; background: radial-gradient(circle at 20% 10%, rgba(56, 189, 248, 0.12), transparent 34%), rgba(8, 18, 32, 0.42); }
.graph-node { min-height: 96px; padding: 14px; border: 1px solid var(--border-light); border-radius: 18px; background: rgba(15, 23, 42, 0.78); color: var(--text-primary); cursor: pointer; transition: all var(--transition-fast); }
.graph-node:hover, .graph-node.active { transform: translateY(-3px); border-color: var(--border-glow); box-shadow: 0 18px 40px rgba(8, 18, 32, 0.35); }
.graph-node strong, .graph-node em { display: block; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
.graph-node em { margin-top: 8px; color: var(--text-muted); font-style: normal; text-transform: uppercase; }
.risk-critical { border-color: var(--risk-critical-border); }
.risk-high { border-color: var(--risk-high-border); }
.risk-medium { border-color: var(--risk-medium-border); }
.node-detail h3 { margin: 10px 0 4px; color: var(--text-primary); }
.node-detail p { color: var(--text-muted); }
.edge-list { display: flex; flex-direction: column; gap: 10px; margin-top: 16px; }
.edge-item { display: flex; flex-direction: column; gap: 4px; padding: 12px; border: 1px solid var(--border-light); border-radius: 14px; background: rgba(8, 18, 32, 0.5); }
.edge-item em { color: var(--text-muted); font-style: normal; }
@media (max-width: 1120px) { .topology-hero { align-items: flex-start; flex-direction: column; } .topology-grid { grid-template-columns: 1fr; } }
</style>
