<template>
  <section class="situation-page">
    <header class="situation-header">
      <div>
        <p>GLOBAL THREAT SITUATION</p>
        <h2>全球网络攻击态势</h2>
      </div>
      <div class="header-tools">
        <span>{{ currentTime }}</span>
        <button type="button" title="刷新态势" aria-label="刷新态势" :disabled="loading" @click="refreshData">↻</button>
      </div>
    </header>

    <div v-if="error" class="state-message">{{ error }}</div>

    <div class="metric-strip">
      <div><span>攻击链</span><strong>{{ metrics.chains }}</strong></div>
      <div><span>公网攻击 IP</span><strong>{{ metrics.sourceIPs }}</strong></div>
      <div><span>攻击城市</span><strong>{{ metrics.cities }}</strong></div>
      <div><span>目标资产</span><strong>{{ metrics.targets }}</strong></div>
    </div>

    <div class="situation-grid">
      <aside class="side-panel source-panel">
        <div class="panel-title"><strong>攻击来源</strong><span>TOP 6</span></div>
        <div v-if="topSources.length" class="source-list">
          <div v-for="(source, index) in topSources" :key="source.country" class="source-row">
            <span class="rank">{{ index + 1 }}</span>
            <div><b>{{ source.country }}</b><small>{{ source.city }}</small></div>
            <strong>{{ source.count }}</strong>
            <i :style="{ width: `${source.percent}%` }" />
          </div>
        </div>
        <div v-else class="empty">暂无公网攻击来源</div>
      </aside>

      <main class="map-panel">
        <div class="map-title">
          <div><strong>实时攻击方向</strong><span>{{ targetLabel }}</span></div>
          <span class="live"><i />LIVE</span>
        </div>
        <div ref="mapElement" class="world-map" />
        <div v-if="!geoRoutes.length && !loading" class="map-empty">暂无公网攻击 IP 态势数据</div>
      </main>

      <aside class="side-panel chain-panel">
        <div class="panel-title"><strong>未闭环 Incident</strong><span>{{ attackChains.length }} 条</span></div>
        <div v-if="attackChains.length" class="chain-list">
          <button v-for="chain in attackChains.slice(0, 6)" :key="chain.id" type="button" @click="goToIncident(chain)">
            <div><span :class="['severity-dot', chain.severity]" /><strong>{{ chain.title }}</strong></div>
            <p><b>{{ chain.sourceIP }}</b><span>→</span><b>{{ chain.targetIP }}</b></p>
            <small>{{ chain.stage }} · {{ chain.time }}</small>
          </button>
        </div>
        <div v-else class="empty">暂无活跃攻击链</div>
      </aside>

      <section class="killchain-panel">
        <div v-for="stage in killchain" :key="stage.key" :class="['stage', { active: stage.count > 0 }]">
          <span>{{ stage.code }}</span><div><b>{{ stage.name }}</b><small>{{ stage.count }} 条</small></div>
        </div>
      </section>
    </div>
  </section>
</template>

<script setup>
import * as echarts from 'echarts'
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import api from '../../api'
import { attackWorkbenchClient } from '../../api/domain'
import worldMap from '../../assets/maps/world-110m.json'
import { formatChinaDateTime, platformNow } from '../../shared/time'

echarts.registerMap('ly-world', worldMap)

const router = useRouter()
const mapElement = ref(null)
const loading = ref(false)
const error = ref('')
const currentTime = ref('')
const attackChains = ref([])
const geoRoutes = ref([])
const target = ref({ country: '中国', province: '', city: '', district: '', lat: 39.9042, lon: 116.4074 })
let chart = null
let pollTimer = null
let clockTimer = null

const list = (value) => Array.isArray(value) ? value : []
const text = (...values) => values.find((value) => value !== undefined && value !== null && String(value).trim()) || ''
const stageKey = (value) => String(value || '').toLowerCase().replace(/[\s-]+/g, '_')
const stageDefinitions = [
  ['recon', '侦察', 'TA0043'], ['initial_access', '初始访问', 'TA0001'], ['execution', '执行', 'TA0002'],
  ['persistence', '持久化', 'TA0003'], ['privilege_escalation', '权限提升', 'TA0004'],
  ['lateral_movement', '横向移动', 'TA0008'], ['c2_exfiltration', '控制与外传', 'TA0011'],
]

function validIP(value) {
  const text = String(value || '').trim()
  return text !== '' && text !== '-' && text !== 'unknown' && text !== '未知'
}

const metrics = computed(() => ({
  chains: attackChains.value.length,
  sourceIPs: new Set([...geoRoutes.value.map((item) => item.source_ip), ...attackChains.value.map((item) => item.sourceIP)].filter(validIP)).size,
  cities: new Set(geoRoutes.value.map((item) => `${item.source_country}/${item.source_city}`).filter((item) => !item.endsWith('/') && !item.startsWith('/'))).size,
  targets: new Set([...geoRoutes.value.map((item) => item.target_ip || item.target_city), ...attackChains.value.map((item) => item.targetIP)].filter(validIP)).size,
}))

const targetLabel = computed(() => [target.value.country, target.value.province, target.value.city, target.value.district].filter(Boolean).join(' · '))

const topSources = computed(() => {
  const grouped = new Map()
  geoRoutes.value.forEach((route) => {
    const country = text(route.source_country, '未知')
    const row = grouped.get(country) || { country, city: text(route.source_city, route.source_region, '-'), count: 0 }
    row.count += Number(route.count || 1)
    grouped.set(country, row)
  })
  const rows = [...grouped.values()].sort((a, b) => b.count - a.count).slice(0, 6)
  const max = rows[0]?.count || 1
  return rows.map((row) => ({ ...row, percent: Math.max(8, Math.round(row.count / max * 100)) }))
})

const killchain = computed(() => {
  const counts = Object.fromEntries(stageDefinitions.map(([key]) => [key, 0]))
  attackChains.value.forEach((chain) => {
    const stages = list(chain.stages).length ? list(chain.stages) : [chain.stage || 'detection']
    stages.forEach((stage) => {
      const key = stageKey(text(stage?.stage, stage?.stage_id, stage?.name, stage))
      const matched = stageDefinitions.find(([candidate]) => key.includes(candidate) || candidate.includes(key))
      counts[matched?.[0] || 'recon'] = (counts[matched?.[0] || 'recon'] || 0) + 1
    })
  })
  return stageDefinitions.map(([key, name, code]) => ({ key, name, code, count: counts[key] || 0 }))
})

function normalizeChain(chain, index) {
  const route = list(chain.geo_routes)[0] || {}
  const stages = list(chain.stages)
  return {
    ...chain,
    id: text(chain.id, chain.chain_id, `chain-${index}`),
    title: text(chain.title, chain.name, chain.attack_type, '关联攻击事件'),
    severity: String(text(chain.severity, 'medium')).toLowerCase(),
    sourceIP: text(route.source_ip, list(chain.source_ips)[0], '-'),
    targetIP: text(route.target_ip, list(chain.victim_ips)[0], chain.entity_id, '-'),
    stage: text(stages.at(-1)?.stage_label, stages.at(-1)?.name, chain.stage, '风险确认'),
    time: formatChinaDateTime(text(chain.last_seen, chain.updated_at, chain.created_at, platformNow())),
  }
}

async function refreshData() {
  loading.value = true
  error.value = ''
  try {
    const [situationResult, incidentResult] = await Promise.allSettled([
      api.get('/public/situation/global'),
      attackWorkbenchClient.incidents({ limit: 20, live: 0, status: 'active' }),
    ])
    const body = situationResult.status === 'fulfilled' ? (situationResult.value?.data ?? situationResult.value ?? {}) : {}
    let chains = list(body.attacks)
    if (incidentResult.status === 'fulfilled') {
      const incidentBody = incidentResult.value?.data ?? incidentResult.value ?? {}
      const activeIncidents = list(incidentBody.items)
      if (activeIncidents.length) chains = activeIncidents
    }
    attackChains.value = chains.map(normalizeChain)
    geoRoutes.value = list(body.geo_routes).length ? list(body.geo_routes) : chains.flatMap((chain) => list(chain.geo_routes))
    target.value = { ...target.value, ...(body.target || {}) }
    await nextTick()
    renderMap()
  } catch (requestError) {
    error.value = requestError?.message || '态势数据加载失败'
  } finally {
    loading.value = false
  }
}

function renderMap() {
  if (!mapElement.value) return
  if (!chart) chart = echarts.init(mapElement.value)
  const routes = geoRoutes.value
  const lineData = routes.map((route) => ({
    coords: [[Number(route.source_lon), Number(route.source_lat)], [Number(route.target_lon), Number(route.target_lat)]],
    value: Number(route.count || 1),
    source: `${text(route.source_country, '未知')} · ${text(route.source_city, route.source_ip)}`,
    target: `${text(route.target_country, '中国')} · ${text(route.target_city, route.target_ip)}`,
  })).filter((item) => item.coords.flat().every(Number.isFinite))
  const sourceData = routes.map((route) => ({
    name: `${text(route.source_country, '未知')} · ${text(route.source_city, route.source_ip)}`,
    value: [Number(route.source_lon), Number(route.source_lat), Number(route.count || 1)],
  })).filter((item) => item.value.slice(0, 2).every(Number.isFinite))
  const targetData = [{ name: targetLabel.value, value: [Number(target.value.lon), Number(target.value.lat), routes.length] }]
  chart.setOption({
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item', backgroundColor: '#fff', borderColor: '#cfd9e7', textStyle: { color: '#243044', fontSize: 12 }, formatter: (p) => p.data?.source ? `${p.data.source}<br/>攻击目标：${p.data.target}<br/>关联事件：${p.data.value}` : `${p.name}<br/>事件：${p.value?.[2] ?? 0}` },
    geo: { map: 'ly-world', roam: true, zoom: 1.12, center: [18, 22], itemStyle: { areaColor: '#eaf2fb', borderColor: '#9eb9d8', borderWidth: 0.7 }, emphasis: { itemStyle: { areaColor: '#d5e8fa' }, label: { show: false } } },
    series: [
      { type: 'lines', coordinateSystem: 'geo', zlevel: 2, data: lineData, effect: { show: true, period: 4, trailLength: 0.25, symbol: 'circle', symbolSize: 5, color: '#e5484d' }, lineStyle: { color: '#2782e8', width: 1.4, opacity: 0.65, curveness: 0.25 } },
      { type: 'effectScatter', coordinateSystem: 'geo', zlevel: 3, data: sourceData, symbolSize: (v) => Math.min(13, 6 + Number(v[2] || 0)), rippleEffect: { scale: 3 }, itemStyle: { color: '#e5484d' } },
      { type: 'effectScatter', coordinateSystem: 'geo', zlevel: 4, data: targetData, symbolSize: 14, rippleEffect: { scale: 4 }, itemStyle: { color: '#1769d2' }, label: { show: true, position: 'bottom', color: '#1769d2', fontWeight: 700, formatter: (p) => p.name } },
    ],
  }, true)
}

function goToIncident(chain) {
  router.push({ path: '/incidents', query: { id: chain.id } })
}

function updateClock() { currentTime.value = formatChinaDateTime(platformNow()) }
function resizeChart() { chart?.resize() }

onMounted(async () => {
  updateClock()
  await refreshData()
  clockTimer = setInterval(updateClock, 1000)
  pollTimer = setInterval(refreshData, 60000)
  window.addEventListener('resize', resizeChart)
})

onUnmounted(() => {
  clearInterval(clockTimer)
  clearInterval(pollTimer)
  window.removeEventListener('resize', resizeChart)
  chart?.dispose()
  chart = null
})
</script>

<style scoped>
.situation-page { display: grid; gap: 14px; min-width: 0; }
.situation-header { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; padding-bottom: 14px; border-bottom: 1px solid var(--lyf-line); background-image: linear-gradient(90deg, var(--lyf-accent-line), transparent 46%); background-repeat: no-repeat; background-position: left bottom; background-size: 100% 1px; }
.situation-header h2 { margin: 0; color: var(--lyf-ink); font-size: clamp(21px, 2vw, 27px); font-weight: 650; letter-spacing: -0.02em; }
.situation-header p { margin: 6px 0 0; color: var(--lyf-ink-3); font-size: 12px; }
.header-tools { display: flex; align-items: center; gap: 10px; }
.live { display: inline-flex; align-items: center; gap: 6px; color: var(--lyf-success); font-family: var(--lyf-font-data); font-size: 10px; font-weight: 700; letter-spacing: 0.1em; }
.live i { width: 5px; height: 5px; border-radius: 50%; background: var(--lyf-success); box-shadow: 0 0 8px var(--lyf-success); }

.metric-strip { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.metric-strip > div { padding: 13px 15px; border: 1px solid var(--lyf-line); border-radius: var(--lyf-radius); background: linear-gradient(180deg, rgb(34 211 238 / 5%), transparent 40%), var(--lyf-surface); }
.metric-strip span { display: block; color: var(--lyf-ink-3); font-size: 10.5px; }
.metric-strip b { display: block; margin-top: 6px; color: var(--lyf-ink); font-family: var(--lyf-font-data); font-size: 22px; font-weight: 600; }

.situation-grid { display: grid; grid-template-columns: minmax(0, 7fr) minmax(0, 4fr); gap: 12px; }
.map-panel, .killchain-panel, .chain-panel, .source-panel, .side-panel { border: 1px solid var(--lyf-line); border-radius: var(--lyf-radius); background: linear-gradient(180deg, rgb(34 211 238 / 4%), transparent 34%), var(--lyf-surface); overflow: hidden; }
.panel-title, .map-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 16px; border-bottom: 1px solid var(--lyf-line); background: var(--lyf-surface-2); color: var(--lyf-ink); font-size: 13px; font-weight: 650; }
.world-map { position: relative; min-height: 340px; background: radial-gradient(circle at 50% 45%, rgb(34 211 238 / 8%), transparent 60%), var(--lyf-paper); }
.map-empty, .empty { display: grid; min-height: 140px; place-items: center; color: var(--lyf-ink-3); font-size: 11.5px; text-align: center; }
.state-message { padding: 12px 16px; color: var(--lyf-ink-3); font-size: 11.5px; }

.killchain-panel { display: grid; gap: 0; }
.killchain-panel .stage { display: grid; grid-template-columns: 90px minmax(0, 1fr) 40px; align-items: center; gap: 10px; padding: 8px 14px; border-bottom: 1px solid var(--lyf-line); color: var(--lyf-ink-2); font-size: 11.5px; }
.killchain-panel .stage:last-child { border-bottom: 0; }
.killchain-panel .stage.active { background: rgb(34 211 238 / 6%); color: var(--lyf-ink); }
.killchain-panel .stage b { color: var(--lyf-ink); font-family: var(--lyf-font-data); font-weight: 600; text-align: right; }

.chain-list, .source-list { display: grid; }
.chain-list > *, .source-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 10px; padding: 9px 14px; border-bottom: 1px solid var(--lyf-line); color: var(--lyf-ink-2); font-size: 11.5px; }
.chain-list > *:last-child, .source-row:last-child { border-bottom: 0; }
.chain-list > *:hover, .source-row:hover { background: rgb(34 211 238 / 4%); }
.severity-dot { display: inline-block; width: 6px; height: 6px; margin-right: 6px; border-radius: 50%; background: var(--lyf-low); }
.rank b { color: var(--lyf-ink); font-family: var(--lyf-font-data); font-weight: 600; }

@media (max-width: 1180px) {
  .situation-grid { grid-template-columns: minmax(0, 1fr); }
  .metric-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 640px) { .metric-strip { grid-template-columns: minmax(0, 1fr); } }
</style>
