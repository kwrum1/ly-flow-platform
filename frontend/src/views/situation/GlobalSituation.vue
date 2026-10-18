<template>
  <OverviewV2 v-if="features.attackV2" />
  <section v-else class="situation-page">
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
        <div class="panel-title"><strong>活跃攻击链</strong><span>{{ attackChains.length }} 条</span></div>
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
import worldMap from '../../assets/maps/world-110m.json'
import { features } from '../../config/features'
import { formatChinaDateTime, platformNow } from '../../shared/time'
import OverviewV2 from './OverviewV2.vue'

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

const metrics = computed(() => ({
  chains: attackChains.value.length,
  sourceIPs: new Set(geoRoutes.value.map((item) => item.source_ip).filter(Boolean)).size,
  cities: new Set(geoRoutes.value.map((item) => `${item.source_country}/${item.source_city}`).filter((item) => !item.endsWith('/'))).size,
  targets: new Set(geoRoutes.value.map((item) => item.target_ip || item.target_city).filter(Boolean)).size,
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
    const response = await api.get('/public/situation/global')
    const body = response?.data ?? response ?? {}
    const chains = list(body.attacks)
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
  pollTimer = setInterval(refreshData, 30000)
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
*{box-sizing:border-box}.situation-page{height:calc(100vh - 64px);min-height:680px;display:grid;grid-template-rows:52px auto minmax(0,1fr);gap:8px;padding:10px;background:#f3f6fa;color:#1f2a3d;overflow:hidden}.situation-header{display:flex;align-items:center;justify-content:space-between;padding:0 14px;border:1px solid #dce4ef;border-radius:6px;background:#fff}.situation-header p{margin:0 0 2px;color:#2782e8;font-size:10px;font-weight:800}.situation-header h2{margin:0;font-size:18px}.header-tools{display:flex;align-items:center;gap:12px;color:#68758a;font-size:12px}.header-tools button{display:grid;place-items:center;width:30px;height:30px;border:1px solid #d7e0ec;border-radius:4px;background:#f7f9fc;color:#1769d2;font-size:19px;cursor:pointer}.state-message{padding:7px 10px;border:1px solid #f1b8b5;border-radius:4px;background:#fff3f2;color:#a52a21;font-size:12px}.metric-strip{min-height:38px;display:grid;grid-template-columns:repeat(4,1fr);border:1px solid #dce4ef;border-radius:6px;background:#fff;overflow:hidden}.metric-strip>div{display:flex;align-items:center;justify-content:center;gap:12px;border-right:1px solid #e5ebf3}.metric-strip>div:last-child{border:0}.metric-strip span{color:#738096;font-size:12px}.metric-strip strong{color:#1769d2;font-size:24px}.situation-grid{min-height:0;display:grid;grid-template-columns:210px minmax(430px,1fr) 260px;grid-template-rows:minmax(0,1fr) 90px;gap:8px}.side-panel,.map-panel,.killchain-panel{min-height:0;border:1px solid #dce4ef;border-radius:6px;background:#fff;overflow:hidden}.panel-title,.map-title{height:40px;display:flex;align-items:center;justify-content:space-between;padding:0 12px;border-bottom:1px solid #e5ebf3}.panel-title strong,.map-title strong{font-size:13px}.panel-title>span,.map-title span{color:#7c899d;font-size:11px}.source-list{padding:7px}.source-row{position:relative;display:grid;grid-template-columns:22px minmax(0,1fr) auto;align-items:center;gap:7px;padding:9px 5px 11px;border-bottom:1px solid #edf1f6}.source-row .rank{display:grid;place-items:center;width:19px;height:19px;border-radius:3px;background:#edf4fc;color:#1769d2;font-size:10px}.source-row div{min-width:0}.source-row b,.source-row small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.source-row b{font-size:12px}.source-row small{margin-top:2px;color:#8a96a8;font-size:10px}.source-row>strong{color:#334155;font-size:12px}.source-row i{position:absolute;left:34px;right:auto;bottom:5px;height:2px;border-radius:2px;background:#65a9ef}.map-panel{position:relative;display:grid;grid-template-rows:40px minmax(0,1fr)}.map-title>div{display:flex;align-items:baseline;gap:10px}.live{display:flex;align-items:center;gap:5px;color:#1c8c55!important;font-weight:800}.live i{width:7px;height:7px;border-radius:50%;background:#28b66f}.world-map{width:100%;height:100%;min-height:270px}.map-empty{position:absolute;left:50%;bottom:18px;transform:translateX(-50%);padding:7px 12px;border:1px solid #d8e2ee;border-radius:4px;background:rgba(255,255,255,.92);color:#778499;font-size:11px}.chain-list{height:calc(100% - 40px);padding:6px;overflow:auto}.chain-list button{width:100%;padding:9px;border:0;border-bottom:1px solid #e7edf4;background:#fff;text-align:left;cursor:pointer}.chain-list button:hover{background:#f4f8fd}.chain-list button>div{display:flex;align-items:center;gap:7px}.chain-list strong{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#263247;font-size:12px}.severity-dot{width:7px;height:7px;border-radius:50%;background:#f1a43c;flex:0 0 auto}.severity-dot.high,.severity-dot.critical{background:#e5484d}.chain-list p{display:flex;align-items:center;gap:6px;margin:7px 0 4px;color:#516079;font-size:11px}.chain-list p b{max-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.chain-list p span{color:#2782e8}.chain-list small{color:#8a96a8;font-size:10px}.empty{display:grid;place-items:center;height:calc(100% - 40px);padding:20px;color:#8b97a8;font-size:12px}.killchain-panel{grid-column:1/-1;display:grid;grid-template-columns:repeat(7,1fr);padding:8px}.stage{position:relative;display:flex;align-items:center;justify-content:center;gap:7px;border-right:1px solid #e5ebf3;color:#8b96a7}.stage:last-child{border:0}.stage>span{display:grid;place-items:center;width:32px;height:32px;border-radius:50%;background:#edf1f6;color:#738096;font-size:9px;font-weight:800}.stage.active>span{background:#e4f1ff;color:#1769d2;box-shadow:inset 0 0 0 1px #a7cdf5}.stage b,.stage small{display:block}.stage b{color:#40506a;font-size:11px}.stage small{margin-top:3px;font-size:10px}.stage.active b{color:#1769d2}@media(max-width:1100px){.situation-page{height:auto;min-height:calc(100vh - 64px);overflow:auto}.situation-grid{grid-template-columns:180px minmax(420px,1fr);grid-template-rows:430px 220px 100px}.chain-panel{grid-column:1/-1}.chain-list{display:grid;grid-template-columns:repeat(2,1fr)}.killchain-panel{grid-row:3}}@media(max-width:760px){.metric-strip{grid-template-columns:repeat(2,1fr)}.situation-grid{display:flex;flex-direction:column}.map-panel{min-height:420px}.source-panel,.chain-panel{min-height:220px}.killchain-panel{grid-template-columns:repeat(2,1fr);min-height:220px}.situation-header p{display:none}}
</style>
