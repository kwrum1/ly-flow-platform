<template>
  <div class="global-situation">
    <!-- 顶部标题栏 -->
    <header class="situation-header">
      <div class="header-title">
        <svg
          viewBox="0 0 24 24"
          fill="none"
        >
          <circle
            cx="12"
            cy="12"
            r="10"
          />
          <line
            x1="2"
            y1="12"
            x2="22"
            y2="12"
          />
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
        <h1>全球网络攻击态势</h1>
      </div>
      <div class="header-info">
        <span
          v-if="loading"
          class="sync-state"
        >同步中...</span>
        <span
          v-if="error"
          class="sync-state error"
        >{{ error }}</span>
        <span class="polling-meta" :class="{ stale: situationPolling.stale }">
          上次更新：{{ situationPolling.lastUpdatedText }} / {{ situationPolling.stale ? '数据陈旧' : '数据新鲜' }}
        </span>
        <span class="sync-state">{{ refreshing ? '刷新中...' : `通道:${realtimeStatus}` }}</span>
        <span class="time">{{ currentTime }}</span>
        <span
          class="refresh"
          @click="refreshByAction"
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
          >
            <polyline points="23 4 23 10 17 10" />
            <polyline points="1 20 1 14 7 14" />
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
          </svg>
          刷新
        </span>
      </div>
    </header>

    <div
      v-if="situationPolling.stale"
      class="stale-hint"
    >
      <span>数据可能已过期，请手动刷新或等待通道恢复后自动同步。</span>
      <button
        type="button"
        class="hint-action"
        @click="refreshByAction"
      >立即刷新</button>
    </div>

    <!-- 主内容 -->
    <div class="situation-content">
      <!-- 全球攻击地图 -->
      <div class="map-section">
        <div
          ref="mapContainer"
          class="map-container"
        >
          <div class="map-background" />
          <!-- 攻击动画线条 -->
          <svg
            v-if="attacks.length > 0"
            class="attack-lines"
          >
            <defs>
              <linearGradient
                id="attackGradient"
                x1="0%"
                y1="0%"
                x2="100%"
                y2="0%"
              >
                <stop
                  offset="0%"
                  style="stop-color:#ff4d4f;stop-opacity:0"
                />
                <stop
                  offset="50%"
                  style="stop-color:#ff4d4f;stop-opacity:1"
                >
                  <animate
                    attributeName="offset"
                    values="0;1;0"
                    dur="2s"
                    repeatCount="indefinite"
                  />
                </stop>
                <stop
                  offset="100%"
                  style="stop-color:#1890ff;stop-opacity:0"
                />
              </linearGradient>
            </defs>
            <path
              v-for="(attack, i) in attacks"
              :key="i"
              :d="attack.path"
              class="attack-path"
              :style="{ animationDelay: attack.delay + 's' }"
            />
          </svg>
          <!-- 攻击点 -->
          <div
            v-for="(attack, i) in attacks"
            :key="'point-' + i"
            class="attack-point source"
            :style="{ left: attack.sourceX + '%', top: attack.sourceY + '%' }"
          >
            <span class="point-pulse" />
          </div>
          <!-- 目标点 -->
          <div class="target-area">
            <div class="target-inner">
              <span class="target-label">目标区域</span>
              <span class="target-value">中国</span>
            </div>
          </div>
          <!-- 地图网格 -->
          <div class="map-grid" />
        </div>

        <!-- 攻击统计 -->
        <div class="map-stats">
          <div class="stat-item">
            <span class="stat-value danger">{{ stats.totalAttacks.toLocaleString() }}</span>
            <span class="stat-label">攻击总数</span>
          </div>
          <div class="stat-item">
            <span class="stat-value">{{ stats.activeSources }}</span>
            <span class="stat-label">活跃攻击源</span>
          </div>
          <div class="stat-item">
            <span class="stat-value warning">{{ stats.attackedTargets }}</span>
            <span class="stat-label">被攻击目标</span>
          </div>
          <div class="stat-item">
            <span class="stat-value success">{{ stats.blockRate }}%</span>
            <span class="stat-label">阻断率</span>
          </div>
        </div>
      </div>

      <!-- 攻击链阶段 -->
      <div class="killchain-section">
        <div class="section-header">
          <h2>攻击链阶段 (ATT&CK Kill Chain)</h2>
        </div>
        <div class="killchain-stages">
          <div
            v-for="(stage, i) in killchain"
            :key="i"
            class="stage-item"
            :class="{ active: stage.active, hover: stage.hover }"
            @mouseenter="stage.hover = true"
            @mouseleave="stage.hover = false"
          >
            <div
              class="stage-icon"
              :style="{ background: stage.color }"
            >
              <span class="stage-number">{{ i + 1 }}</span>
            </div>
            <div class="stage-info">
              <span class="stage-name">{{ stage.name }}</span>
              <span class="stage-en">{{ stage.en }}</span>
            </div>
            <div
              v-if="stage.count > 0"
              class="stage-count"
            >
              {{ stage.count }}
            </div>
            <div
              v-if="i < killchain.length - 1"
              class="stage-arrow"
            >
              <svg
                viewBox="0 0 24 24"
                fill="none"
              >
                <line
                  x1="5"
                  y1="12"
                  x2="19"
                  y2="12"
                />
                <polyline points="12 5 19 12 12 19" />
              </svg>
            </div>
          </div>
        </div>

        <div class="active-attacks">
          <h3>当前活跃攻击</h3>
          <div class="attack-tags">
            <span
              v-for="tag in activeTags"
              :key="tag"
              class="attack-tag"
            >{{ tag }}</span>
          </div>
        </div>
      </div>

      <!-- 左侧面板 -->
      <div class="panel panel-left">
        <div class="panel-section">
          <h3>攻击类型分布</h3>
          <div
            ref="pieChart"
            class="pie-chart"
          >
            <div class="pie-inner">
              <svg viewBox="0 0 100 100">
                <circle
                  v-for="(item, i) in attackTypes"
                  :key="i"
                  cx="50"
                  cy="50"
                  r="40"
                  fill="none"
                  :stroke="item.color"
                  stroke-width="20"
                  :stroke-dasharray="item.dash"
                  :stroke-dashoffset="item.offset"
                  :style="{ transform: 'rotate(-90deg)', transformOrigin: '50% 50%' }"
                />
              </svg>
              <div class="pie-center">
                <span class="pie-total">{{ totalAttackCount }}</span>
                <span class="pie-label">总攻击</span>
              </div>
            </div>
            <div class="pie-legend">
              <div
                v-for="item in attackTypes"
                :key="item.name"
                class="legend-item"
              >
                <span
                  class="legend-dot"
                  :style="{ background: item.color }"
                />
                <span class="legend-name">{{ item.name }}</span>
                <span class="legend-value">{{ item.value }}</span>
              </div>
            </div>
          </div>
        </div>

        <div class="panel-section">
          <h3>攻击来源 TOP5</h3>
          <div class="source-list">
            <div
              v-for="(src, i) in topSources"
              :key="i"
              class="source-item"
            >
              <span class="source-rank">{{ i + 1 }}</span>
              <span class="source-country">{{ src.country }}</span>
              <span class="source-count">{{ src.count.toLocaleString() }}</span>
              <div class="source-bar">
                <div
                  class="source-fill"
                  :style="{ width: (src.count / topSources[0].count * 100) + '%' }"
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 右侧面板 -->
      <div class="panel panel-right">
        <div class="panel-section">
          <h3>高危情报 <span class="实时-badge">实时</span></h3>
          <div class="alert-timeline">
            <div
              v-if="criticalAlerts.length === 0"
              class="alert-empty"
            >
              <span>当前暂无关键告警，可进入攻击队列查看全部事件或手动刷新。</span>
              <div class="alert-empty-actions">
                <button
                  type="button"
                  class="hint-action"
                  @click="goToEventsWorkbench()"
                >进入攻击队列</button>
                <button
                  type="button"
                  class="hint-action secondary"
                  @click="refreshByAction"
                >立即刷新</button>
              </div>
            </div>
            <div
              v-for="alert in criticalAlerts"
              :key="alert.id"
              class="alert-item"
              :class="alert.level"
            >
              <div class="alert-time">
                {{ alert.time }}
              </div>
              <div class="alert-content">
                <span class="alert-type">{{ alert.type }}</span>
                <span class="alert-detail">{{ alert.detail }}</span>
              </div>
              <div class="alert-action">
                <span
                  class="risk-badge"
                  :class="alert.level"
                >{{ alert.levelText }}</span>
                <button
                  type="button"
                  class="alert-link"
                  @click="goToEventsWorkbench(alert)"
                >进入队列</button>
              </div>
            </div>
          </div>
        </div>

        <div class="panel-section">
          <h3>攻击趋势 (24小时)</h3>
          <div
            ref="trendChart"
            class="trend-chart"
          >
            <svg
              viewBox="0 0 400 100"
              preserveAspectRatio="none"
            >
              <defs>
                <linearGradient
                  id="trendGradient"
                  x1="0%"
                  y1="0%"
                  x2="0%"
                  y2="100%"
                >
                  <stop
                    offset="0%"
                    style="stop-color:#1890ff;stop-opacity:0.4"
                  />
                  <stop
                    offset="100%"
                    style="stop-color:#1890ff;stop-opacity:0"
                  />
                </linearGradient>
              </defs>
              <path
                :d="trendAreaPath"
                fill="url(#trendGradient)"
              />
              <path
                :d="trendLinePath"
                fill="none"
                stroke="#1890ff"
                stroke-width="2"
              />
              <circle
                v-for="(point, i) in trendPoints"
                :key="i"
                :cx="point.x"
                :cy="point.y"
                r="3"
                class="trend-point"
              />
            </svg>
            <div class="trend-labels">
              <span
                v-for="(label, i) in trendLabels"
                :key="i"
              >{{ label }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 底部状态栏 -->
    <footer class="situation-footer">
      <div class="footer-item">
        <span class="footer-label">紧急告警</span>
        <span class="footer-value danger">{{ footerStats.emergencyAlerts }}</span>
      </div>
      <div class="footer-item">
        <span class="footer-label">今日新增攻击</span>
        <span class="footer-value">{{ footerStats.todayAttacks.toLocaleString() }}</span>
      </div>
      <div class="footer-item">
        <span class="footer-label">资产健康度</span>
        <span class="footer-value success">{{ footerStats.assetHealth }}%</span>
      </div>
      <div class="footer-item">
        <span class="footer-label">系统状态</span>
        <span class="footer-value">
          <span class="status-dot online" />
          正常
        </span>
      </div>
    </footer>
  </div>
</template>

<script setup>
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import api, { createRequestController, isRequestCanceled } from '../../api'
import { createPollingFreshnessTracker } from '../../data/polling/freshness'
import { CONNECTION_STATUS, createRealtimeGateway } from '../../realtime'
import { formatChinaDateTime, formatChinaTime, platformNow } from '../../shared/time'

const router = useRouter()
const currentTime = ref('')
const mapContainer = ref(null)
const loading = ref(false)
const error = ref('')
const refreshing = ref(false)
const realtimeStatus = ref(CONNECTION_STATUS.IDLE)

const situationPolling = ref({ stale: false, lastUpdatedText: '-' })
const situationFreshness = createPollingFreshnessTracker({ staleAfterMs: 90000, staleFailureThreshold: 2 })
let refreshController = null
let freshnessTimer = null
let realtimeGateway = null

const stats = ref({
  totalAttacks: 0,
  activeSources: 0,
  attackedTargets: 0,
  blockRate: 0
})

const attackTypes = ref([])
const totalAttackCount = computed(() => attackTypes.value.reduce((sum, t) => sum + t.value, 0))

const killchain = ref([
  { name: '侦察', en: 'Recon', count: 0, active: false, color: 'var(--stage-recon)' },
  { name: '武器化', en: 'Weaponization', count: 0, active: false, color: 'var(--stage-weapon)' },
  { name: '投递', en: 'Delivery', count: 0, active: false, color: 'var(--stage-delivery)' },
  { name: '利用', en: 'Exploitation', count: 0, active: false, color: 'var(--stage-exploit)' },
  { name: '安装', en: 'Installation', count: 0, active: false, color: 'var(--stage-install)' },
  { name: '控制', en: 'C2', count: 0, active: false, color: 'var(--stage-c2)' },
  { name: '行动', en: 'Actions', count: 0, active: false, color: 'var(--stage-action)' }
])
const activeTags = ref([])
const attacks = ref([])
const topSources = ref([])
const criticalAlerts = ref([])
const trendData = ref(Array.from({ length: 24 }, () => 0))
const trendLabels = ref([])

const trendPoints = computed(() => {
  if (trendData.value.length === 0) return []
  const max = Math.max(...trendData.value, 1)
  const min = Math.min(...trendData.value, 0)
  const range = Math.max(max - min, 1)
  const divisor = Math.max(trendData.value.length - 1, 1)
  return trendData.value.map((val, i) => ({
    x: (i / divisor) * 400,
    y: 100 - ((val - min) / range) * 90
  }))
})

const trendLinePath = computed(() => {
  const points = trendPoints.value
  return points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ')
})

const trendAreaPath = computed(() => {
  const points = trendPoints.value
  if (points.length === 0) return ''
  return trendLinePath.value + ` L ${points[points.length - 1].x} 100 L 0 100 Z`
})

const footerStats = ref({
  emergencyAlerts: 0,
  todayAttacks: 0,
  assetHealth: 0
})

const updateTime = () => {
  currentTime.value = formatChinaDateTime(platformNow()).replace(/\//g, '-')
}

const unwrap = (payload) => payload?.data ?? payload ?? {}

const formatPollingTime = (value) => {
  if (!value) return '-'
  const text = formatChinaTime(value)
  return text === '时间格式异常' ? '-' : text
}

const updateSituationPolling = (snapshot = situationFreshness.getSnapshot()) => {
  situationPolling.value = {
    stale: snapshot.stale,
    lastUpdatedText: formatPollingTime(snapshot.lastUpdatedAt),
  }
}

const requestJSON = async (path, signal) => api.get(path, { signal })
const countBy = (items, key) => items.reduce((acc, item) => {
  const value = item[key]
  if (value) acc[value] = (acc[value] || 0) + 1
  return acc
}, {})
const severityText = (level) => ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[level] || '低危')
const hashValue = (value, mod) => String(value || '').split('').reduce((sum, ch) => sum + ch.charCodeAt(0), 0) % mod

const updateAttackTypes = (byModule) => {
  const colors = ['#1890ff', '#ff4d4f', '#ffc53d', '#52c41a', '#8b5cf6']
  const entries = Object.entries(byModule || {}).filter(([, count]) => Number(count) > 0)
  const total = entries.reduce((sum, [, count]) => sum + (Number(count) || 0), 0)
  let offset = 0
  attackTypes.value = entries.map(([name, count], index) => {
    const value = Number(count) || 0
    const percent = total > 0 ? (value / total) * 251 : 0
    const item = { name: name.toUpperCase(), value, color: colors[index % colors.length], dash: `${percent} 251`, offset: -offset }
    offset += percent
    return item
  })
}

const updateTrend = (items) => {
  const buckets = Array.from({ length: 24 }, () => 0)
  items.forEach(item => {
    const time = new Date(item.timestamp || item.created_at || item.time || Date.now())
    if (!Number.isNaN(time.getTime())) buckets[time.getHours()] += 1
  })
  trendData.value = buckets
  trendLabels.value = Array.from({ length: 6 }, (_, index) => `${String(index * 4).padStart(2, '0')}:00`)
}

const refreshData = async ({ signal, isManual = false } = {}) => {
  if (refreshController) refreshController.abort()
  refreshController = createRequestController()
  const activeSignal = signal || refreshController.signal

  loading.value = true
  if (isManual) refreshing.value = true
  error.value = ''
  let didSucceed = false

  try {
    const publicPayload = await requestJSON('/public/situation/global', activeSignal)
    const publicBody = unwrap(publicPayload)
    const items = Array.isArray(publicBody?.attacks) ? publicBody.attacks : []

    const sourceCounts = countBy(items, 'source_country')
    const targetCounts = countBy(items, 'target_country')

    stats.value = {
      totalAttacks: items.reduce((sum, item) => sum + (Number(item.count) || 1), 0),
      activeSources: Object.keys(sourceCounts).length,
      attackedTargets: Object.keys(targetCounts).length,
      blockRate: 0
    }
    footerStats.value = {
      emergencyAlerts: 0,
      todayAttacks: stats.value.totalAttacks,
      assetHealth: 0
    }

    updateAttackTypes({ country: stats.value.totalAttacks })
    topSources.value = Object.entries(sourceCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([country, count]) => ({ country, count }))
    criticalAlerts.value = []
    activeTags.value = [...new Set(items.flatMap(item => [item.source_country, item.target_country]).filter(Boolean))].slice(0, 6)
    attacks.value = items.slice(0, 5).map((item, index) => ({
      path: `M ${40 + index * 20} ${30 + index * 12} Q 200 40 ${300 - index * 15} ${80 + index * 8}`,
      delay: index * 0.2,
      sourceX: 10 + hashValue(item.source_country || item.source_ip || index, 70),
      sourceY: 15 + hashValue(item.target_country || item.target_ip || index, 60)
    }))
    killchain.value = killchain.value.map((stage, index) => {
      const count = index === 0 ? stats.value.totalAttacks : 0
      return { ...stage, count, active: count > 0 }
    })
    updateTrend(items)
    didSucceed = true
  } catch (err) {
    if (!isRequestCanceled(err)) {
      error.value = err.message || '态势数据加载失败'
      updateSituationPolling(situationFreshness.markFailure())
    }
  } finally {
    if (didSucceed) updateSituationPolling(situationFreshness.markSuccess())
    loading.value = false
    refreshing.value = false
  }
}

const refreshByAction = () => {
  refreshData({ isManual: true })
}

const goToEventsWorkbench = (alert = null) => {
  const query = {}
  if (alert?.querySeverity) query.severity = alert.querySeverity
  if (alert?.type && alert.type !== '-') query.event_type = alert.type
  if (alert?.detail && alert.detail !== '-') query.q = alert.detail
  router.push({ path: '/events', query })
}

const setupRealtime = () => {
  const realtimePath = import.meta.env.VITE_EVENTS_REALTIME_PATH || '/ws/events'
  const realtimeBase = import.meta.env.VITE_REALTIME_BASE_URL || window.location.origin
  const wsUrl = realtimePath.startsWith('ws')
    ? realtimePath
    : `${realtimeBase.replace(/^http/, 'ws').replace(/\/$/, '')}${realtimePath.startsWith('/') ? '' : '/'}${realtimePath}`

  realtimeGateway = createRealtimeGateway({
    wsUrl,
    pollingIntervalMs: 30000,
    onPoll: async () => {
      await refreshData()
    }
  })

  realtimeStatus.value = realtimeGateway.getStatus()
  realtimeGateway.onStatusChange((status) => {
    realtimeStatus.value = status
  })

  realtimeGateway.onMessage(async () => {
    await refreshData()
  })

  realtimeGateway.connect()
}

let timer = null
onMounted(async () => {
  updateTime()
  updateSituationPolling(situationFreshness.refresh())
  freshnessTimer = setInterval(() => {
    updateSituationPolling(situationFreshness.refresh())
  }, 1000)
  timer = setInterval(updateTime, 1000)

  await refreshData()
  setupRealtime()
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
  if (freshnessTimer) clearInterval(freshnessTimer)
  if (refreshController) refreshController.abort()
  realtimeGateway?.close('view_unmounted')
  realtimeGateway = null
})
</script>

<style scoped>
.global-situation {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: linear-gradient(135deg, #0a0e14 0%, #0d1117 50%, #0a0e14 100%);
  display: flex;
  flex-direction: column;
  z-index: 1000;
  overflow: hidden;
}

.situation-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 32px;
  background: rgba(13, 17, 23, 0.8);
  border-bottom: 1px solid var(--border-color);
}

.header-title {
  display: flex;
  align-items: center;
  gap: 12px;
}

.header-title svg {
  width: 32px;
  height: 32px;
  stroke: var(--primary-color);
}

.header-title h1 {
  font-size: 24px;
  font-weight: 700;
  background: linear-gradient(135deg, #fff 0%, #8b949e 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.header-info {
  display: flex;
  align-items: center;
  gap: 16px;
}

.stale-hint {
  margin: 12px 24px 0;
  padding: 10px 14px;
  border: 1px solid var(--risk-critical-border);
  border-radius: 8px;
  background: rgba(255, 77, 79, 0.12);
  color: var(--risk-critical);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.hint-action {
  border: 1px solid var(--risk-critical-border);
  border-radius: 6px;
  background: rgba(255, 77, 79, 0.18);
  color: #ffd8d8;
  padding: 4px 10px;
  cursor: pointer;
}

.hint-action.secondary {
  border-color: var(--border-color);
  background: rgba(255, 255, 255, 0.08);
  color: var(--text-secondary);
}

.time {
  font-size: 14px;
  color: var(--text-secondary);
  font-family: 'Roboto Mono', monospace;
}

.sync-state {
  font-size: 12px;
  color: #52c41a;
}

.polling-meta {
  font-size: 12px;
  color: var(--text-secondary);
}

.polling-meta.stale {
  color: var(--risk-critical);
}


.sync-state.error {
  color: var(--risk-critical);
}

.refresh {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--text-secondary);
  cursor: pointer;
  padding: 6px 12px;
  background: var(--bg-secondary);
  border-radius: 6px;
  transition: all var(--transition-fast);
}

.refresh:hover {
  color: var(--primary-color);
  background: var(--bg-hover);
}

.refresh svg {
  width: 14px;
  height: 14px;
}

.situation-content {
  flex: 1;
  display: grid;
  grid-template-columns: 1fr 280px 280px;
  grid-template-rows: 1fr auto;
  gap: 16px;
  padding: 16px 24px;
  overflow: hidden;
}

/* 地图区域 */
.map-section {
  grid-column: 1;
  grid-row: 1;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.map-container {
  flex: 1;
  position: relative;
  background: rgba(22, 27, 34, 0.5);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  overflow: hidden;
}

.map-background {
  position: absolute;
  inset: 0;
  background:
    radial-gradient(ellipse at 50% 50%, rgba(24, 144, 255, 0.1) 0%, transparent 70%),
    url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%231891ff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
}

.attack-lines {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
}

.attack-path {
  fill: none;
  stroke: url(#attackGradient);
  stroke-width: 2;
  stroke-dasharray: 1000;
  stroke-dashoffset: 1000;
  animation: attackFlow 3s linear infinite;
}

@keyframes attackFlow {
  to {
    stroke-dashoffset: 0;
  }
}

.attack-point {
  position: absolute;
  width: 8px;
  height: 8px;
  transform: translate(-50%, -50%);
}

.attack-point.source::before {
  content: '';
  position: absolute;
  width: 8px;
  height: 8px;
  background: var(--risk-critical);
  border-radius: 50%;
  box-shadow: 0 0 10px var(--risk-critical);
}

.point-pulse {
  position: absolute;
  width: 20px;
  height: 20px;
  background: rgba(255, 77, 79, 0.3);
  border-radius: 50%;
  animation: breathe 1.5s ease-out infinite;
  transform: translate(-50%, -50%);
}

.target-area {
  position: absolute;
  left: 65%;
  top: 45%;
  transform: translate(-50%, -50%);
}

.target-inner {
  width: 120px;
  height: 120px;
  background: radial-gradient(circle, rgba(24, 144, 255, 0.2) 0%, transparent 70%);
  border: 2px solid var(--primary-color);
  border-radius: 50%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  animation: glow 3s ease-in-out infinite;
}

.target-label {
  font-size: 11px;
  color: var(--text-secondary);
}

.target-value {
  font-size: 18px;
  font-weight: 700;
  color: var(--primary-color);
}

.map-stats {
  display: flex;
  gap: 16px;
}

.stat-item {
  flex: 1;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 12px 16px;
  text-align: center;
}

.stat-item .stat-value {
  font-size: 24px;
  font-weight: 700;
  color: var(--text-primary);
}

.stat-item .stat-value.danger {
  color: var(--risk-critical);
}

.stat-item .stat-value.warning {
  color: var(--risk-medium);
}

.stat-item .stat-value.success {
  color: var(--risk-low);
}

.stat-item .stat-label {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 4px;
}

/* 攻击链 */
.killchain-section {
  grid-column: 1;
  grid-row: 2;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
}

.section-header h2 {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 12px;
}

.killchain-stages {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 16px;
}

.stage-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: var(--bg-secondary);
  border-radius: 6px;
  position: relative;
  transition: all var(--transition-fast);
}

.stage-item:hover,
.stage-item.active {
  background: var(--bg-hover);
  transform: translateY(-2px);
}

.stage-icon {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.stage-number {
  font-size: 12px;
  font-weight: 700;
  color: white;
}

.stage-info {
  display: flex;
  flex-direction: column;
}

.stage-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}

.stage-en {
  font-size: 10px;
  color: var(--text-muted);
}

.stage-count {
  background: var(--risk-critical-bg);
  color: var(--risk-critical);
  font-size: 11px;
  padding: 2px 6px;
  border-radius: 10px;
}

.stage-arrow {
  color: var(--text-muted);
  margin-left: auto;
}

.stage-arrow svg {
  width: 16px;
  height: 16px;
}

.active-attacks h3 {
  font-size: 13px;
  color: var(--text-secondary);
  margin-bottom: 8px;
}

.attack-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.attack-tag {
  padding: 4px 10px;
  background: rgba(255, 77, 79, 0.15);
  color: var(--risk-critical);
  font-size: 12px;
  border-radius: 12px;
  border: 1px solid rgba(255, 77, 79, 0.3);
  animation: pulse 2s infinite;
}

/* 面板 */
.panel {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.panel-section {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
  flex: 1;
}

.panel-section h3 {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.实时-badge {
  font-size: 10px;
  padding: 2px 6px;
  background: var(--risk-critical);
  color: white;
  border-radius: 4px;
  animation: pulse 1s infinite;
}

/* 饼图 */
.pie-chart {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.pie-inner {
  position: relative;
  width: 120px;
  height: 120px;
  margin: 0 auto;
}

.pie-inner svg {
  width: 100%;
  height: 100%;
  transform: rotate(-90deg);
}

.pie-center {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
}

.pie-total {
  display: block;
  font-size: 20px;
  font-weight: 700;
  color: var(--text-primary);
}

.pie-label {
  font-size: 10px;
  color: var(--text-secondary);
}

.pie-legend {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
}

.legend-dot {
  width: 8px;
  height: 8px;
  border-radius: 2px;
}

.legend-name {
  flex: 1;
  color: var(--text-secondary);
}

.legend-value {
  color: var(--text-primary);
  font-weight: 600;
}

/* 来源列表 */
.source-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.source-item {
  display: grid;
  grid-template-columns: 20px 60px 1fr;
  gap: 8px;
  align-items: center;
}

.source-rank {
  width: 18px;
  height: 18px;
  background: var(--bg-secondary);
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  color: var(--text-muted);
}

.source-country {
  font-size: 12px;
  color: var(--text-primary);
}

.source-count {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-primary);
  text-align: right;
}

.source-bar {
  grid-column: 1 / -1;
  height: 4px;
  background: var(--bg-secondary);
  border-radius: 2px;
  overflow: hidden;
}

.source-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--primary-color), var(--primary-light));
  border-radius: 2px;
}

/* 告警时间线 */
.alert-timeline {
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-height: 200px;
  overflow-y: auto;
}

.alert-item {
  display: grid;
  grid-template-columns: 70px 1fr auto;
  gap: 8px;
  padding: 8px;
  background: var(--bg-secondary);
  border-radius: 6px;
  align-items: center;
}

.alert-empty {
  border: 1px dashed var(--border-color);
  border-radius: 8px;
  padding: 12px;
  color: var(--text-secondary);
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.alert-empty-actions {
  display: flex;
  gap: 8px;
}

.alert-action {
  display: flex;
  align-items: center;
  gap: 8px;
}

.alert-link {
  border: none;
  background: transparent;
  color: var(--primary-color);
  cursor: pointer;
  font-size: 12px;
}

.alert-link:hover {
  text-decoration: underline;
}

.alert-time {
  font-size: 11px;
  color: var(--text-muted);
  font-family: 'Roboto Mono', monospace;
}

.alert-type {
  font-size: 12px;
  font-weight: 500;
  color: var(--text-primary);
}

.alert-detail {
  font-size: 11px;
  color: var(--text-secondary);
}

.alert-item.critical {
  border-left: 3px solid var(--risk-critical);
}

.alert-item.high {
  border-left: 3px solid var(--risk-high);
}

.alert-item.medium {
  border-left: 3px solid var(--risk-medium);
}

/* 趋势图 */
.trend-chart {
  height: 100px;
  position: relative;
}

.trend-chart svg {
  width: 100%;
  height: 80px;
}

.trend-point {
  fill: var(--primary-color);
  stroke: var(--bg-card);
  stroke-width: 2;
}

.trend-labels {
  display: flex;
  justify-content: space-between;
  margin-top: 8px;
  font-size: 10px;
  color: var(--text-muted);
}

/* 底部状态栏 */
.situation-footer {
  display: flex;
  justify-content: center;
  gap: 48px;
  padding: 12px 32px;
  background: rgba(13, 17, 23, 0.8);
  border-top: 1px solid var(--border-color);
}

.footer-item {
  display: flex;
  align-items: center;
  gap: 8px;
}

.footer-label {
  font-size: 12px;
  color: var(--text-secondary);
}

.footer-value {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-primary);
  display: flex;
  align-items: center;
  gap: 4px;
}

.footer-value.danger {
  color: var(--risk-critical);
}

.footer-value.success {
  color: var(--risk-low);
}
</style>
