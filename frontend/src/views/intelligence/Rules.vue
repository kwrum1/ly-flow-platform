<template>
  <div class="rules-page">
    <div class="page-header">
      <h2>规则管理</h2>
      <div class="header-actions">
        <el-button>
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            width="16"
            height="16"
          ><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line
            x1="12"
            y1="3"
            x2="12"
            y2="15"
          /></svg>
          导入规则
        </el-button>
        <el-button>
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            width="16"
            height="16"
          ><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line
            x1="12"
            y1="15"
            x2="12"
            y2="3"
          /></svg>
          导出规则
        </el-button>
        <el-button type="primary">
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            width="16"
            height="16"
          ><line
            x1="12"
            y1="5"
            x2="12"
            y2="19"
          /><line
            x1="5"
            y1="12"
            x2="19"
            y2="12"
          /></svg>
          新增规则
        </el-button>
      </div>
    </div>

    <!-- 统计 -->
    <div class="stats-grid">
      <div
        v-for="stat in stats"
        :key="stat.key"
        class="stat-card"
      >
        <span class="stat-value">{{ stat.value }}</span>
        <span class="stat-label">{{ stat.label }}</span>
      </div>
    </div>

    <!-- 筛选 -->
    <div class="sync-section">
      <div class="sync-card">
        <div>
          <strong>Wazuh XDR 规则同步</strong>
          <p>支持 dry-run 预览后同步开源规则。</p>
        </div>
        <el-button
          type="primary"
          :disabled="syncLoading || !isAdmin"
          @click="dryRunRuleSync('wazuh')"
        >Dry-run</el-button>
      </div>
      <div class="sync-card static">
        <div>
          <strong>RASP 规则</strong>
          <p>静态内置规则，不参与在线更新。</p>
        </div>
        <span class="static-badge">静态</span>
      </div>
      <div
        v-if="syncResult"
        class="sync-result"
      >
        {{ syncResult.source }}: 新增 {{ syncResult.added }} / 变更 {{ syncResult.changed }} / 未变 {{ syncResult.unchanged }} / 失败 {{ syncResult.failed }}
      </div>
    </div>

    <div class="filter-section">
      <div class="filter-tabs">
        <button
          v-for="f in filters"
          :key="f.key"
          :class="{ active: activeFilter === f.key }"
          @click="activeFilter = f.key"
        >
          {{ f.label }}
        </button>
      </div>
      <el-input
        v-model="searchQuery"
        placeholder="搜索规则名称..."
        prefix-icon="Search"
        clearable
        style="width: 200px"
      />
    </div>

    <!-- 规则列表 -->
    <div class="rules-section">
      <div class="rules-table">
        <div class="table-header">
          <div class="th">
            规则名称
          </div>
          <div class="th">
            类别
          </div>
          <div class="th">
            严重度
          </div>
          <div class="th">
            状态
          </div>
          <div class="th">
            来源
          </div>
          <div class="th">
            操作
          </div>
        </div>
        <div class="table-body">
          <div
            v-if="loading"
            class="table-state"
          >
            加载中...
          </div>
          <div
            v-else-if="error"
            class="table-state error"
          >
            {{ error }}
          </div>
          <div
            v-else-if="rules.length === 0"
            class="table-state"
          >
            暂无规则数据
          </div>
          <div
            v-for="rule in rules"
            :key="rule.id"
            class="table-row"
          >
            <div class="td name">
              {{ rule.name }}
            </div>
            <div class="td category">
              {{ rule.category }}
            </div>
            <div class="td">
              <span
                class="risk-badge"
                :class="rule.level"
              >{{ rule.levelText }}</span>
            </div>
            <div class="td">
              <el-switch
                v-model="rule.enabled"
                :disabled="!isAdmin"
                @change="toggleRule(rule)"
              />
            </div>
            <div class="td source">
              {{ rule.source }}
            </div>
            <div class="td actions">
              <el-button
                link
                type="primary"
                size="small"
              >
                编辑
              </el-button>
              <el-button
                link
                type="primary"
                size="small"
              >
                详情
              </el-button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import api from '../../api'
const searchQuery = ref('')
const activeFilter = ref('all')
const loading = ref(false)
const error = ref('')
const currentUserRole = ref(localStorage.getItem('role') || '')
const isAdmin = computed(() => currentUserRole.value === 'admin')

const stats = ref([
  { key: 'total', label: '规则总数', value: 0 },
  { key: 'enabled', label: '已启用', value: 0 },
  { key: 'critical', label: '严重', value: 0 },
  { key: 'high', label: '高危', value: 0 },
  { key: 'custom', label: '自定义', value: 0 }
])
const filters = [
  { key: 'all', label: '全部' },
  { key: 'enabled', label: '已启用' },
  { key: 'critical', label: '严重' },
  { key: 'high', label: '高危' },
  { key: 'medium', label: '中危' }
]
const allRules = ref([])
const syncLoading = ref(false)
const syncResult = ref(null)

const unwrap = (payload) => payload?.data ?? payload ?? {}
const requestJSON = async (path, options = {}) => {
  const method = String(options.method || 'GET').toUpperCase()
  const body = typeof options.body === 'string' ? JSON.parse(options.body) : options.body

  if (method === 'GET') return api.get(path)
  if (method === 'POST') return api.post(path, body || {})
  if (method === 'PUT') return api.put(path, body || {})
  if (method === 'DELETE') return api.delete(path, body ? { data: body } : undefined)

  throw new Error(`Unsupported method: ${method}`)
}

const severityText = (level) => {
  const map = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
  return map[level] || '低危'
}

const normalizeRule = (rule, index) => {
  const level = String(rule.severity || rule.level || 'low').toLowerCase()
  return {
    id: rule.id || index,
    name: rule.name || rule.rule_name || '-',
    category: rule.category || rule.language || rule.action || '-',
    level,
    levelText: severityText(level),
    enabled: Boolean(rule.enabled),
    source: rule.source || rule.module || 'RASP'
  }
}

const rules = computed(() => {
  let list = allRules.value
  if (activeFilter.value === 'enabled') list = list.filter(rule => rule.enabled)
  if (['critical', 'high', 'medium'].includes(activeFilter.value)) list = list.filter(rule => rule.level === activeFilter.value)
  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase()
    list = list.filter(rule => rule.name.toLowerCase().includes(q) || rule.category.toLowerCase().includes(q))
  }
  return list
})

const refreshStats = (rulesList, apiStats = {}) => {
  const enabled = rulesList.filter(rule => rule.enabled).length
  stats.value = [
    { key: 'total', label: '规则总数', value: apiStats.totalRules ?? rulesList.length },
    { key: 'enabled', label: '已启用', value: apiStats.enabledRules ?? enabled },
    { key: 'critical', label: '严重', value: rulesList.filter(rule => rule.level === 'critical').length },
    { key: 'high', label: '高危', value: rulesList.filter(rule => rule.level === 'high').length },
    { key: 'custom', label: '自定义', value: apiStats.customRules ?? rulesList.length }
  ]
}

const loadRules = async () => {
  loading.value = true
  error.value = ''
  try {
    const [rulesBody, statsBody] = await Promise.all([
      requestJSON('/rasp/rules'),
      requestJSON('/rules/stats')
    ])
    const listBody = unwrap(rulesBody)
    const items = Array.isArray(listBody) ? listBody : (listBody.items || listBody.rules || [])
    allRules.value = items.map(normalizeRule)
    refreshStats(allRules.value, unwrap(statsBody))
  } catch (err) {
    error.value = err.message || '规则加载失败'
    allRules.value = []
    refreshStats([])
  } finally {
    loading.value = false
  }
}

const toggleRule = async (rule) => {
  const previous = !rule.enabled
  error.value = ''

  if (!isAdmin.value) {
    rule.enabled = previous
    error.value = 'Permission denied: 仅管理员可修改规则状态。'
    return
  }

  try {
    await requestJSON('/rasp/rules', {
      method: 'PUT',
      body: JSON.stringify({ id: rule.id, enabled: rule.enabled })
    })
    refreshStats(allRules.value)
  } catch (err) {
    rule.enabled = previous
    error.value = err.message || 'Operation failed: 规则状态更新失败'
  }
}

const dryRunRuleSync = async (source) => {
  syncLoading.value = true
  error.value = ''
  try {
    const body = unwrap(await requestJSON(`/rules/sync/${source}/dry-run`, { method: 'POST' }))
    syncResult.value = body
  } catch (err) {
    error.value = err.message || '规则同步预览失败'
  } finally {
    syncLoading.value = false
  }
}

onMounted(loadRules)
</script>

<style scoped>
.rules-page { min-height: 100%; }
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.page-header h2 { font-size: 18px; font-weight: 600; color: var(--text-primary); }
.header-actions { display: flex; gap: 12px; }

.stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 20px; }
.stat-card { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; text-align: center; }
.stat-card .stat-value { display: block; font-size: 24px; font-weight: 700; color: var(--text-primary); }
.stat-card .stat-label { font-size: 12px; color: var(--text-secondary); }

.sync-section { display: grid; gap: 10px; margin-bottom: 16px; }
.sync-card { display: flex; justify-content: space-between; align-items: center; padding: 14px 16px; border: 1px solid var(--border-color); border-radius: 8px; background: var(--bg-card); }
.sync-card p { margin: 4px 0 0; color: var(--text-secondary); font-size: 12px; }
.static-badge { color: var(--text-secondary); border: 1px solid var(--border-color); border-radius: 999px; padding: 4px 10px; }
.sync-result { color: var(--text-secondary); font-size: 13px; }

.filter-section { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.filter-tabs { display: flex; gap: 8px; }
.filter-tabs button { padding: 6px 12px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-secondary); font-size: 12px; cursor: pointer; transition: all 0.15s; }
.filter-tabs button.active { background: var(--primary-color); border-color: var(--primary-color); color: white; }

.rules-section { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; }

.table-header { display: flex; background: var(--bg-secondary); border-bottom: 1px solid var(--border-color); }
.th { padding: 12px 16px; font-size: 12px; font-weight: 600; color: var(--text-secondary); text-align: left; }
.th:nth-child(1) { flex: 2; }
.th:nth-child(2) { width: 100px; }
.th:nth-child(3) { width: 80px; }
.th:nth-child(4) { width: 80px; }
.th:nth-child(5) { width: 80px; }
.th:nth-child(6) { width: 120px; }

.table-body { max-height: 450px; overflow-y: auto; }
.table-state { padding: 32px; text-align: center; color: var(--text-muted); }
.table-state.error { color: var(--risk-critical); }
.table-row { display: flex; align-items: center; border-bottom: 1px solid var(--border-color); }
.table-row:hover { background: var(--bg-hover); }
.td { padding: 14px 16px; font-size: 13px; color: var(--text-primary); display: flex; align-items: center; }
.td.name { flex: 2; font-weight: 500; }
.td.category { width: 100px; }
.td.source { width: 80px; color: var(--text-secondary); }
.td.actions { width: 120px; gap: 8px; }
</style>
