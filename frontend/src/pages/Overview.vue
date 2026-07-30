<template>
  <section class="ops-page">
    <header class="screen-head">
      <div class="head-line"></div>
      <div><p>LYFLOW SITUATION CENTER</p><h2>全球威胁态势感知</h2><span>基于攻击源 IP 城市归属与 XDR 关联评分展示实时攻击方向</span></div>
      <em v-if="loading" class="auto-refresh">同步中</em>
    </header>
    <div v-if="error" class="state-card error-state">{{ error }}</div>
    <section class="metric-grid">
      <article class="metric-card" :class="securityLevel.key"><span>安全等级</span><strong>{{ securityLevel.label }}</strong><em>XDR 关联评分 {{ securityScore }} / 100</em></article>
      <article class="metric-card"><span>威胁攻击链数量</span><strong>{{ threatChainCount }}</strong><em>来自态势接口</em></article>
      <article class="metric-card"><span>告警总量</span><strong>{{ stats.total_alerts ?? 0 }}</strong><em>统计接口</em></article>
      <article class="metric-card"><span>更新时间</span><strong>{{ shortTime }}</strong><em>中国时间</em></article>
    </section>
    <article class="soc-screen">
      <div class="screen-title"><span></span><b>全球态势</b><em>{{ situationText }}</em><span></span></div>
      <div class="soc-layout">
        <aside class="side-panel left-panel">
          <div class="panel-cap">攻击源 TOP</div>
          <div v-for="item in topCities" :key="item.label" class="rank-row"><b>{{ item.label }}</b><span>{{ item.count }} 次</span></div>
        </aside>
        <div class="world-map" aria-label="全球攻击态势地图">
          <div class="map-grid"></div><div class="scan-line"></div><div class="earth-glow"></div>
          <div ref="mapChart" class="map-chart"></div>
          <div v-for="route in mapRoutes" :key="`${route.key}-label`" class="attack-label"><b>{{ route.city }}</b><span>{{ route.ip }}</span></div>
        </div>
        <aside class="side-panel right-panel">
          <div class="panel-cap">受害源 TOP</div>
          <div v-for="item in victimTop" :key="item.label" class="rank-row"><b>{{ item.label }}</b><span>{{ item.count }} 次</span></div>
        </aside>
      </div>
    </article>
  </section>
</template>
<script setup>
import * as echarts from 'echarts'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { attackWorkbenchClient, overviewClient } from '../api/domain'
import { formatChinaTime } from '../shared/time'
import worldMap from '../assets/maps/world-110m.json'

const loading = ref(false); const error = ref(''); const health = ref({}); const stats = ref({}); const situation = ref({}); const posture = ref({}); const loadedAt = ref('')
const mapChart = ref(null)
let chart = null
let refreshTimer = null
const shortTime = computed(() => loadedAt.value ? formatChinaTime(loadedAt.value) : '未加载')
const securityScore = computed(() => Number(posture.value?.risk_score ?? stats.value?.posture_score ?? 0))
const threatChainCount = computed(() => situation.value?.attacks?.length || posture.value?.active_chains || 0)
const securityLevel = computed(() => {
  const score = securityScore.value
  if (score <= 0) return { key: 'safe', label: '安全' }
  if (score >= 80) return { key: 'critical', label: '严重' }
  if (score >= 60) return { key: 'high', label: '高危' }
  if (score >= 35) return { key: 'medium', label: '中危' }
  return { key: 'low', label: '低危' }
})
const geoRoutes = computed(() => Array.isArray(situation.value?.geo_routes) ? situation.value.geo_routes : [])
const situationText = computed(() => {
  const data = situation.value || {}
  const attacks = data.attacks?.length || 0
  const cities = geoRoutes.value.length
  const message = data.empty_state?.message || '态势接口正常'
  return `攻击链 ${attacks} 条 · 城市归属 ${cities} 个 · ${message}`
})
const targetLabel = computed(() => situation.value?.target?.label || [situation.value?.target?.country, situation.value?.target?.province, situation.value?.target?.city, situation.value?.target?.district].filter(Boolean).join('·') || '中国·北京')
const targetCoord = computed(() => [Number(situation.value?.target?.lon ?? 116.4074), Number(situation.value?.target?.lat ?? 39.9042)])
const mapRoutes = computed(() => geoRoutes.value.map((route, index) => {
  const sourceCoord = [Number(route.source_lon), Number(route.source_lat)]
  const sourceLabel = provinceLabel(route.source_country, route.source_region, route.source_city)
  return {
    key: `${route.source_ip || route.source_city || index}-${index}`,
    ip: route.source_ip || 'unknown',
    label: sourceLabel,
    city: [route.source_country, route.source_region, route.source_city].filter(Boolean).join(' · '),
    count: route.count || 1,
    severity: route.severity || 'medium',
    sourceCoord,
    coords: [sourceCoord, targetCoord.value],
  }
}))
const topCities = computed(() => aggregateTop(geoRoutes.value, (route) => provinceLabel(route.source_country, route.source_region, route.source_city)))
const victimTop = computed(() => aggregateTop(geoRoutes.value, victimIPLabel))

function provinceLabel(country, region, city) {
  const normalizedRegion = String(region || '').trim()
  if (normalizedRegion) return normalizedRegion
  return String(country || city || '未知').trim()
}

function victimIPLabel(route) {
  return String(route.target_ip || route.victim_ip || route.dst_ip || route.destination_ip || '').trim()
}

function aggregateTop(routes, labelOf) {
  const buckets = new Map()
  for (const route of routes) {
    const label = labelOf(route)
    if (!label) continue
    buckets.set(label, (buckets.get(label) || 0) + Number(route.count || 1))
  }
  return [...buckets.entries()].map(([label, count]) => ({ label, count })).sort((a, b) => b.count - a.count).slice(0, 5)
}

function ensureChart() {
  if (!mapChart.value) return
  if (!chart) {
    echarts.registerMap('ly-world', worldMap)
    chart = echarts.init(mapChart.value, null, { renderer: 'canvas' })
    window.addEventListener('resize', resizeChart)
  }
  renderMap()
}
function renderMap() {
  if (!chart) return
  chart.setOption({
    backgroundColor: 'transparent',
    tooltip: { trigger: 'item', backgroundColor: 'rgba(3,10,25,.92)', borderColor: '#38bdf8', textStyle: { color: '#e0f2fe' } },
    geo: {
      map: 'ly-world', roam: false, zoom: 1.18, center: [18, 18], silent: true,
      itemStyle: { areaColor: 'rgba(14, 116, 144, .38)', borderColor: '#38bdf8', borderWidth: .75, shadowColor: 'rgba(56,189,248,.42)', shadowBlur: 12 },
      emphasis: { disabled: true },
    },
    series: [
      { type: 'map', map: 'ly-world', geoIndex: 0, roam: false, silent: true, itemStyle: { areaColor: 'rgba(14, 116, 144, .26)', borderColor: 'rgba(125,211,252,.55)', borderWidth: .55 }, emphasis: { disabled: true }, data: [] },
      { name: '城市节点', type: 'effectScatter', coordinateSystem: 'geo', zlevel: 3, symbolSize: 5, rippleEffect: { brushType: 'stroke', scale: 3.2 }, itemStyle: { color: '#67e8f9', shadowColor: '#67e8f9', shadowBlur: 12 }, label: { show: true, formatter: '{b}', position: 'right', color: '#93c5fd', fontSize: 10 }, data: [] },
      { name: '攻击路径', type: 'lines', coordinateSystem: 'geo', zlevel: 4, effect: { show: true, period: 3, trailLength: .26, symbol: 'arrow', symbolSize: 7, color: '#f97316' }, lineStyle: { color: '#f97316', width: 1.8, opacity: .78, curveness: .26 }, data: mapRoutes.value.map((route) => ({ name: route.label, coords: route.coords, value: route.count })) },
      { name: '攻击源', type: 'effectScatter', coordinateSystem: 'geo', zlevel: 5, symbolSize: 10, rippleEffect: { brushType: 'stroke', scale: 4 }, itemStyle: { color: '#fb7185', shadowColor: '#fb7185', shadowBlur: 18 }, label: { show: true, formatter: (p) => p.data.label, position: 'top', color: '#fecdd3', fontSize: 11, lineHeight: 15 }, data: mapRoutes.value.map((route) => ({ name: route.label, value: [...route.sourceCoord, route.count], label: route.label, city: route.city, ip: route.ip })) },
      { name: '目标', type: 'effectScatter', coordinateSystem: 'geo', zlevel: 6, symbolSize: 13, rippleEffect: { brushType: 'stroke', scale: 5 }, itemStyle: { color: '#38bdf8', shadowColor: '#38bdf8', shadowBlur: 22 }, label: { show: true, formatter: () => targetLabel.value.replace(/·/g, '\n'), position: 'right', color: '#e0f2fe', fontWeight: 900, fontSize: 12, lineHeight: 16 }, data: mapRoutes.value.length ? [{ name: targetLabel.value, value: [...targetCoord.value, 1] }] : [] },
    ],
  }, true)
}
function resizeChart() { chart?.resize() }
async function loadAll(){ if (loading.value) return; loading.value=true; error.value=''; try{ const [h,s,g,p]=await Promise.all([overviewClient.health(), overviewClient.stats(), overviewClient.globalSituation(), attackWorkbenchClient.xdrPosture()]); health.value=h||{}; stats.value=s||{}; situation.value=g||{}; posture.value=p||{}; loadedAt.value=new Date().toISOString(); await nextTick(); ensureChart() }catch(e){ error.value=e?.message||'无法读取态势数据' }finally{ loading.value=false } }
onMounted(async () => { await nextTick(); ensureChart(); loadAll(); refreshTimer = window.setInterval(loadAll, 30000) })
watch([mapRoutes, targetCoord, targetLabel], () => nextTick(renderMap), { deep: true })
onBeforeUnmount(() => { if (refreshTimer) window.clearInterval(refreshTimer); window.removeEventListener('resize', resizeChart); chart?.dispose(); chart = null })
</script>
<style scoped>
.ops-page{height:100%;min-height:0;display:grid;grid-template-rows:auto auto minmax(0,1fr);gap:12px;padding:14px;color:#dbeafe;box-sizing:border-box;background:radial-gradient(circle at 50% 0,rgba(14,165,233,.12),transparent 32%)}.screen-head{position:relative;display:flex;justify-content:space-between;align-items:center;gap:24px;padding:18px 24px 16px;border:1px solid rgba(56,189,248,.26);background:linear-gradient(180deg,rgba(6,20,42,.96),rgba(3,10,25,.88));box-shadow:inset 0 -1px 0 rgba(125,211,252,.22),0 18px 44px rgba(0,0,0,.24);clip-path:polygon(0 0,100% 0,100% calc(100% - 14px),calc(100% - 18px) 100%,18px 100%,0 calc(100% - 14px))}.head-line{position:absolute;left:22%;right:22%;top:0;height:2px;background:linear-gradient(90deg,transparent,#38bdf8,#22d3ee,transparent);box-shadow:0 0 22px #38bdf8}.screen-head p{margin:0 0 5px;color:#67e8f9;font-size:11px;font-weight:900;letter-spacing:.22em}.screen-head h2{margin:0;font-size:clamp(28px,3vw,44px);letter-spacing:.08em;text-shadow:0 0 18px rgba(56,189,248,.34)}.screen-head span{display:block;margin-top:7px;color:#93c5fd;font-size:13px}.screen-head button{height:40px;padding:0 18px;border:1px solid rgba(125,211,252,.35);border-radius:4px;background:linear-gradient(180deg,#0ea5e9,#0369a1);color:#ecfeff;font-weight:900;box-shadow:0 0 18px rgba(14,165,233,.25)}.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.metric-card{position:relative;padding:14px 16px;border:1px solid rgba(56,189,248,.2);background:linear-gradient(180deg,rgba(8,28,58,.88),rgba(4,12,30,.88));box-shadow:inset 0 0 24px rgba(14,165,233,.08);overflow:hidden}.metric-card::before{content:'';position:absolute;left:0;top:0;width:3px;height:100%;background:#38bdf8}.metric-card span,.metric-card em{color:#93c5fd;font-style:normal;font-size:12px}.metric-card strong{display:block;margin:4px 0;font-size:27px;color:#f8fafc}.metric-card.high::before,.metric-card.critical::before{background:#f97316}.metric-card.medium::before{background:#facc15}.metric-card.low::before{background:#22c55e}.state-card{padding:12px;color:#bfdbfe;border:1px solid rgba(125,211,252,.24);background:rgba(8,28,58,.72)}.error-state{color:#fecaca;border-color:rgba(248,113,113,.34);background:rgba(127,29,29,.24)}.soc-screen{min-height:0;display:grid;grid-template-rows:auto minmax(0,1fr);border:1px solid rgba(56,189,248,.25);background:linear-gradient(180deg,rgba(2,12,30,.96),rgba(1,6,18,.98));box-shadow:0 24px 70px rgba(0,0,0,.32),inset 0 0 80px rgba(8,47,73,.25);padding:12px}.screen-title{height:42px;display:grid;grid-template-columns:1fr auto auto 1fr;align-items:center;gap:14px;color:#e0f2fe}.screen-title span{height:1px;background:linear-gradient(90deg,transparent,#38bdf8)}.screen-title span:last-child{background:linear-gradient(90deg,#38bdf8,transparent)}.screen-title b{font-size:18px;letter-spacing:.18em}.screen-title em{font-style:normal;color:#93c5fd;font-size:12px}.soc-layout{min-height:0;display:grid;grid-template-columns:190px minmax(0,1.35fr) 190px;gap:10px}.side-panel{align-self:stretch;border:1px solid rgba(56,189,248,.18);background:linear-gradient(180deg,rgba(7,24,52,.86),rgba(3,10,25,.8));box-shadow:inset 0 0 34px rgba(14,165,233,.08);padding:12px}.panel-cap{height:30px;line-height:30px;margin-bottom:10px;padding-left:10px;border-left:3px solid #38bdf8;color:#e0f2fe;font-weight:900;letter-spacing:.12em;background:linear-gradient(90deg,rgba(14,165,233,.16),transparent)}.rank-row,.stat-line{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-top:9px;padding:10px;border:1px solid rgba(148,163,184,.12);background:rgba(15,23,42,.48)}.rank-row b,.stat-line b{font-size:13px;color:#f8fafc}.rank-row span,.stat-line span{font-size:12px;color:#93c5fd}.rank-row.muted b{color:#94a3b8}.world-map{position:relative;min-height:500px;overflow:hidden;border:1px solid rgba(56,189,248,.24);background:radial-gradient(circle at 73% 42%,rgba(14,165,233,.18),transparent 20%),radial-gradient(circle at 50% 55%,rgba(6,182,212,.12),transparent 46%),linear-gradient(180deg,#041225,#010713);box-shadow:inset 0 0 70px rgba(14,165,233,.15)}.world-map::before{content:'';position:absolute;inset:0;background-image:linear-gradient(rgba(59,130,246,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(59,130,246,.08) 1px,transparent 1px);background-size:34px 34px;mask-image:radial-gradient(ellipse at center,#000 40%,transparent 88%)}.earth-glow{position:absolute;left:50%;top:52%;width:78%;height:78%;transform:translate(-50%,-50%);border-radius:50%;border:1px solid rgba(56,189,248,.18);box-shadow:0 0 90px rgba(14,165,233,.12),inset 0 0 60px rgba(14,165,233,.06)}.scan-line{position:absolute;left:0;right:0;top:0;height:2px;background:linear-gradient(90deg,transparent,#67e8f9,transparent);box-shadow:0 0 18px #38bdf8;animation:scan 4.6s linear infinite;z-index:2}.world-layer{position:absolute;inset:0;width:100%;height:100%;z-index:3}.land{fill:url(#landGlow);fill-opacity:.34;stroke:#45c7ff;stroke-width:1.15;stroke-opacity:.82;filter:drop-shadow(0 0 8px rgba(56,189,248,.42))}.border-line{fill:none;stroke:#60a5fa;stroke-width:.7;stroke-opacity:.2;stroke-dasharray:7 12}.world-silhouette{transform-origin:center;transform:translateY(4px) scale(1.02)}.land.island{fill-opacity:.26;stroke-opacity:.58}.attack-route{fill:none;stroke:url(#attackLine);stroke-width:2.2;stroke-linecap:round;stroke-dasharray:5 10;filter:url(#lineGlow);animation:routeFlow 2.1s linear infinite}.city-dot{position:absolute;z-index:4;transform:translate(-50%,-50%);color:#93c5fd;font-size:10px;white-space:nowrap}.city-dot i{display:block;width:5px;height:5px;border-radius:50%;background:#67e8f9;box-shadow:0 0 12px #67e8f9}.city-dot span{display:block;margin-top:5px;transform:translateX(-40%);opacity:.72}.china-target{position:absolute;z-index:6;transform:translate(-50%,-50%);display:grid;place-items:center;width:76px;height:76px;border-radius:50%;background:radial-gradient(circle,#e0f2fe 0 10%,#38bdf8 11% 28%,rgba(14,165,233,.22) 30%);box-shadow:0 0 36px rgba(56,189,248,.65),0 0 90px rgba(14,165,233,.32);color:#fff;font-weight:950}.china-target i{position:absolute;inset:-16px;border:1px solid rgba(125,211,252,.5);border-radius:50%;animation:pulse 2.6s ease-out infinite}.china-target span{font-size:11px;color:#bae6fd}.attack-pin{position:absolute;z-index:7;transform:translate(-50%,-120%);min-width:132px;padding:7px 10px;border:1px solid rgba(249,115,22,.46);background:rgba(7,24,52,.88);box-shadow:0 0 22px rgba(249,115,22,.18)}.attack-pin b{display:block;color:#fed7aa;font-size:12px;white-space:nowrap}.attack-pin span{display:block;color:#93c5fd;font-size:11px;margin-top:2px}.map-empty{position:absolute;left:24px;bottom:24px;z-index:7;padding:12px 14px;border:1px solid rgba(148,163,184,.18);background:rgba(15,23,42,.78);color:#bfdbfe}.map-footer{display:none}@keyframes scan{0%{transform:translateY(0);opacity:.15}50%{opacity:.9}100%{transform:translateY(500px);opacity:.08}}@keyframes routeFlow{to{stroke-dashoffset:-34}}@keyframes pulse{0%{opacity:.85;transform:scale(.85)}100%{opacity:.05;transform:scale(1.3)}}@media(max-width:1180px){.soc-layout{grid-template-columns:1fr}.side-panel{display:block}.world-map{min-height:420px}.metric-grid{grid-template-columns:1fr 1fr}}@media(max-width:720px){.metric-grid{grid-template-columns:1fr}.screen-head{flex-direction:column;align-items:flex-start}.world-map{min-height:340px}.attack-pin{display:none}}

.map-chart{position:absolute;inset:0;z-index:4}.attack-label{position:absolute;left:9%;top:22%;z-index:7;min-width:150px;padding:8px 10px;border:1px solid rgba(249,115,22,.42);background:rgba(7,24,52,.86);box-shadow:0 0 20px rgba(249,115,22,.16);color:#fed7aa}.attack-label b{display:block;font-size:12px;white-space:nowrap}.attack-label span{display:block;margin-top:3px;color:#93c5fd;font-size:11px}.world-layer,.city-dot,.china-target,.attack-pin{display:none!important}.world-map{min-height:540px}.soc-layout{grid-template-columns:190px minmax(0,1.6fr) 190px}.map-empty{z-index:8}
.auto-refresh{align-self:flex-start;padding:8px 12px;border:1px solid rgba(56,189,248,.24);background:rgba(14,165,233,.1);color:#93c5fd;font-size:12px;font-style:normal}.ops-page{gap:8px;padding:10px;overflow:hidden}.screen-head{padding:12px 18px 11px}.screen-head h2{font-size:clamp(24px,2.4vw,36px)}.screen-head span{margin-top:4px;font-size:12px}.metric-grid{gap:8px}.metric-card{padding:10px 13px}.metric-card strong{font-size:23px}.soc-screen{min-height:0;padding:9px}.screen-title{height:32px}.soc-layout{min-height:0;height:100%;grid-template-columns:180px minmax(0,1fr) 180px;gap:8px}.side-panel{min-height:0;padding:9px}.rank-row,.stat-line{margin-top:7px;padding:8px}.world-map{min-height:0;height:100%}.map-chart{inset:0}.attack-label{top:18%}@media(max-height:900px){.screen-head{padding:9px 16px}.metric-card{padding:8px 12px}.metric-card strong{font-size:20px}.screen-title{height:28px}.panel-cap{height:25px;line-height:25px;margin-bottom:6px}.rank-row,.stat-line{padding:6px 8px;margin-top:6px}.soc-screen{padding:7px}.world-map{min-height:330px}}
@media(max-width:1180px){.ops-page{height:auto;min-height:100%;overflow:visible}.soc-screen{min-height:auto}.soc-layout{height:auto;grid-template-columns:minmax(0,1fr)}.world-map{width:100%;height:420px;min-height:420px}.side-panel{min-height:88px}.metric-grid{grid-template-columns:1fr 1fr}}
@media(max-width:720px){.metric-grid{grid-template-columns:1fr}.screen-head{flex-direction:column;align-items:flex-start}.screen-title{height:auto;min-height:42px;grid-template-columns:1fr auto;gap:8px}.screen-title span{display:none}.screen-title em{text-align:right}.world-map{height:340px;min-height:340px}.attack-label{display:none}}
</style>
