<template>
  <section class="control-page">
    <header class="control-header">
      <div class="control-heading">
        <span class="control-kicker">SYSTEM SETTINGS</span>
        <h2>平台设置</h2>
        <p>管理采集接口、设备地点和时间基准，保存后即时应用到平台。</p>
      </div>
      <span class="control-live"><i />设置实时生效</span>
    </header>

    <section class="settings-grid">
      <article class="panel mirror-panel">
        <div class="panel-title">
          <span class="panel-icon">IF</span>
          <div class="panel-heading"><strong>抓包接口</strong><small>选择旁路镜像网卡，保存后立即生效</small></div>
        </div>
        <form class="mirror-form" @submit.prevent="saveMirrorConfig">
          <label>
            <span>镜像接口</span>
            <select v-model="mirrorInterface" :disabled="!mirrorInterfaces.length">
              <option value="" disabled>{{ mirrorInterfaces.length ? '请选择镜像网卡' : '未读取到可选网卡' }}</option>
              <option v-for="iface in mirrorInterfaces" :key="iface.name" :value="iface.name">{{ mirrorInterfaceLabel(iface) }}</option>
            </select>
          </label>
          <button type="submit" class="primary" :disabled="savingMirror || !mirrorInterface.trim()">{{ savingMirror ? '保存中' : '保存设置' }}</button>
        </form>
        <div v-if="mirrorMessage" class="notice success">{{ mirrorMessage }}</div>
      </article>

      <article class="panel mirror-panel location-panel">
        <div class="panel-title location-title">
          <span class="panel-icon">LOC</span>
          <div class="panel-heading"><strong>设备地点</strong><small>用于态势地图与区域归属</small></div>
        </div>
        <form class="location-form" @submit.prevent="saveTargetLocation">
          <label><span>省份</span><select v-model="targetProvince" @change="selectProvince"><option v-for="province in provinceOptions" :key="province" :value="province">{{ province }}</option></select></label>
          <label><span>城市</span><select v-model="targetCity" @change="selectCity"><option v-for="city in cityOptions" :key="city" :value="city">{{ city }}</option></select></label>
          <label><span>区县</span><select v-model="targetDistrict"><option v-for="district in districtOptions" :key="district" :value="district">{{ district }}</option></select></label>
          <button type="submit" class="primary" :disabled="savingTargetLocation || !targetCity.trim()">{{ savingTargetLocation ? '保存中' : '保存地点' }}</button>
        </form>
        <div v-if="targetLocationMessage" class="notice success">{{ targetLocationMessage }}</div>
      </article>

      <article class="panel mirror-panel time-panel">
        <div class="panel-title">
          <span class="panel-icon">TIME</span>
          <div class="panel-heading"><strong>时间设置</strong><small>统一平台时间与 NTP 基准</small></div>
        </div>
        <form class="time-form" @submit.prevent="saveSystemTime">
          <label class="time-readonly"><span>服务器当前时间</span><input :value="serverTimeText" disabled></label>
          <label class="time-readonly"><span>平台基准时间</span><input :value="platformTimeText" disabled></label>
          <label><span>修改时间</span><input v-model="systemTimeInput" type="datetime-local"></label>
          <label><span>NTP 服务器</span><input v-model.trim="ntpServer" placeholder="ntp.aliyun.com"></label>
          <div class="time-actions">
            <button type="button" @click="syncBrowserTime" :disabled="savingSystemTime">同步本机最新时间</button>
            <button type="submit" class="primary" :disabled="savingSystemTime || !systemTimeInput">{{ savingSystemTime ? '同步中' : '保存时间' }}</button>
          </div>
        </form>
        <div v-if="systemTimeMessage" class="notice success">{{ systemTimeMessage }}</div>
      </article>
    </section>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { assetAgentClient, overviewClient, trafficClient } from '../api/domain'
import { normalizeItems } from '../shared/api-normalize'
import { formatChinaDateTime, refreshPlatformTimeOffset, setPlatformTimeOffset } from '../shared/time'

const agents = ref([])
const agentPage = ref(1)
const agentPageSize = 8
const total = ref(0)
const loading = ref(false)
const hasLoaded = ref(false)
const error = ref('')
const toggling = ref('')
const deleting = ref('')
const renaming = ref(null)
const renameValue = ref('')
const savingRename = ref(false)
const raspApproval = ref(null)
const approvingRasp = ref(false)
const mirrorInterface = ref('')
const mirrorInterfaces = ref([])
const mirrorEnabled = ref(true)
const savingMirror = ref(false)
const mirrorMessage = ref('')
const targetProvince = ref('')
const targetCity = ref('')
const targetDistrict = ref('')
const savingTargetLocation = ref(false)
const targetLocationMessage = ref('')
const serverTime = ref('')
const platformTime = ref('')
const systemTimeInput = ref('')
const ntpServer = ref('')
const savingSystemTime = ref(false)
const systemTimeMessage = ref('')

const onlineCount = computed(() => agents.value.filter((a) => isOnline(a)).length)
const offlineCount = computed(() => Math.max(agents.value.length - onlineCount.value, 0))
const agentTotalPages = computed(() => Math.max(1, Math.ceil(agents.value.length / agentPageSize)))
const pagedAgents = computed(() => agents.value.slice((agentPage.value - 1) * agentPageSize, agentPage.value * agentPageSize))
const serverTimeText = computed(() => serverTime.value ? formatChinaDateTime(serverTime.value) : '-')
const platformTimeText = computed(() => platformTime.value ? formatChinaDateTime(platformTime.value) : '-')

const locationCatalog = {
  北京: { 北京: ['东城区','西城区','朝阳区','海淀区','丰台区','石景山区','通州区','大兴区'] },
  上海: { 上海: ['黄浦区','徐汇区','静安区','杨浦区','浦东新区','闵行区','宝山区'] },
  天津: { 天津: ['和平区','河西区','南开区','滨海新区'] },
  重庆: { 重庆: ['渝中区','江北区','南岸区','渝北区','九龙坡区'] },
  广东: { 广州: ['越秀区','海珠区','天河区','番禺区'], 深圳: ['福田区','罗湖区','南山区','宝安区','龙岗区'], 东莞: ['市辖区'], 佛山: ['禅城区'] },
  江西: { 南昌: ['东湖区','西湖区','红谷滩区'], 上饶: ['信州区','广信区','广丰区'], 九江: ['浔阳区'], 赣州: ['章贡区'], 景德镇: ['珠山区'], 宜春: ['袁州区'] },
  浙江: { 杭州: ['上城区','拱墅区','西湖区','滨江区'], 宁波: ['海曙区'], 温州: ['鹿城区'] },
  江苏: { 南京: ['玄武区','鼓楼区','建邺区'], 苏州: ['姑苏区','工业园区'], 无锡: ['梁溪区'] },
  四川: { 成都: ['锦江区','青羊区','武侯区','高新区'] }, 湖北: { 武汉: ['江岸区','武昌区','洪山区'] },
  陕西: { 西安: ['新城区','碑林区','雁塔区'] }, 山东: { 济南: ['历下区'], 青岛: ['市南区','崂山区'] },
  河南: { 郑州: ['中原区','金水区'] }, 湖南: { 长沙: ['芙蓉区','岳麓区'] }, 福建: { 福州: ['鼓楼区'], 厦门: ['思明区'] },
  安徽: { 合肥: ['庐阳区','蜀山区'] }, 云南: { 昆明: ['五华区','盘龙区'] }, 贵州: { 贵阳: ['南明区','观山湖区'] },
  辽宁: { 沈阳: ['和平区','沈河区'], 大连: ['中山区','沙河口区'] }, 吉林: { 长春: ['南关区','朝阳区'] }, 黑龙江: { 哈尔滨: ['道里区','南岗区'] },
  广西: { 南宁: ['青秀区','兴宁区'] }, 甘肃: { 兰州: ['城关区','七里河区'] }, 新疆: { 乌鲁木齐: ['天山区','沙依巴克区'] },
  西藏: { 拉萨: ['城关区'] }, 河北: { 石家庄: ['长安区','桥西区'] }, 山西: { 太原: ['小店区','迎泽区'] },
  内蒙古: { 呼和浩特: ['新城区','赛罕区'] }, 海南: { 海口: ['龙华区','美兰区'] }, 青海: { 西宁: ['城中区','城西区'] },
  宁夏: { 银川: ['兴庆区','金凤区'] }, 香港: { 香港: ['中西区','九龙城区'] }, 澳门: { 澳门: ['澳门半岛'] }, 台湾: { 台北: ['中正区','信义区'] },
}
const provinceOptions = Object.keys(locationCatalog)
const cityOptions = computed(() => Object.keys(locationCatalog[targetProvince.value] || {}))
const districtOptions = computed(() => locationCatalog[targetProvince.value]?.[targetCity.value] || ['市辖区'])

function selectProvince() {
  targetCity.value = cityOptions.value[0] || ''
  targetDistrict.value = districtOptions.value[0] || ''
}

function selectCity() {
  targetDistrict.value = districtOptions.value[0] || ''
}

function cleanIP(ip) { return (ip || '').replace(/\/\d+$/, '') || '-' }

function isOnline(agent) {
  if (!agent.last_heartbeat) return false
  const d = new Date(agent.last_heartbeat)
  if (isNaN(d.getTime())) return agent.status === 'online'
  return (Date.now() - d.getTime()) < 120000
}

function agentStatus(agent) { return isOnline(agent) ? 'online' : 'offline' }

function uptimeText(agent) {
  const heartbeat = agent.last_heartbeat
  const connected = agent.connection_since || heartbeat
  const raw = isOnline(agent) ? connected : heartbeat
  if (!raw) return '-'
  const d = new Date(raw)
  if (isNaN(d.getTime())) return String(raw).slice(0, 16)
  const diff = Date.now() - d.getTime()
  if (!isOnline(agent)) {
    const mins = Math.floor(diff / 60000)
    if (mins < 3) return '刚刚离线'
    if (mins < 60) return `${mins} 分钟前离线`
    const hours = Math.floor(mins / 60)
    if (hours < 24) return `${hours} 小时前离线`
    return `${Math.floor(hours / 24)} 天前离线`
  }
  const elapsed = Math.floor(diff / 1000)
  if (elapsed < 60) return '刚刚上线'
  return '在线 ' + durationText(elapsed)
}

function durationText(sec) {
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const parts = []
  if (d > 0) parts.push(`${d} 天`)
  if (h > 0) parts.push(`${h} 小时`)
  if (m > 0 && d === 0) parts.push(`${m} 分钟`)
  return parts.join(' ') || '1 分钟内'
}

async function loadAgents() {
  loading.value = true
  error.value = ''
  try {
    const data = normalizeItems(await assetAgentClient.agents({ limit: 200 }))
    agents.value = data.items.filter((agent) => agent.agent_id !== 'test-agent' && agent.id !== 'test-agent')
    if (agentPage.value > agentTotalPages.value) agentPage.value = agentTotalPages.value
    total.value = agents.value.length
    hasLoaded.value = true
  } catch (e) {
    error.value = e?.message || '无法读取 Agent 列表'
  } finally {
    loading.value = false
  }
}

async function loadMirrorConfig() {
  try {
    const data = await trafficClient.mirrorInterface()
    mirrorInterface.value = data?.interface || ''
    mirrorInterfaces.value = Array.isArray(data?.interfaces) ? data.interfaces.filter((item) => item?.name) : []
    mirrorEnabled.value = true
  } catch { /* control center remains usable without mirror config */ }
}

async function loadTargetLocation() {
  try {
    const data = await overviewClient.targetLocation()
    targetProvince.value = data?.province || ''
    targetCity.value = data?.city || ''
    targetDistrict.value = data?.district || ''
  } catch { /* location setting keeps defaults until server is updated */ }
}

async function loadSystemTime() {
  try {
    const data = await refreshPlatformTimeOffset(overviewClient.systemTime)
    applySystemTimePayload(data)
  } catch { /* time panel remains editable */ }
}

function applySystemTimePayload(data = {}) {
  setPlatformTimeOffset(data?.offset_ms || 0)
  serverTime.value = data?.server_time || ''
  platformTime.value = data?.platform_time || serverTime.value || ''
  ntpServer.value = data?.ntp_server || ntpServer.value || ''
  systemTimeInput.value = toDateTimeLocal(platformTime.value || new Date().toISOString())
}

function toDateTimeLocal(value) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  const pad = (n) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

async function syncBrowserTime() {
  systemTimeInput.value = toDateTimeLocal(new Date().toISOString())
  await saveSystemTime()
}

async function saveSystemTime() {
  if (!systemTimeInput.value) return
  savingSystemTime.value = true
  systemTimeMessage.value = ''
  error.value = ''
  try {
    const date = new Date(systemTimeInput.value)
    const data = await overviewClient.updateSystemTime({ time: date.toISOString(), ntp_server: ntpServer.value.trim() })
    applySystemTimePayload(data)
    systemTimeMessage.value = `平台时间基准已同步${ntpServer.value ? `，NTP：${ntpServer.value}` : ''}`
  } catch (e) {
    error.value = e?.message || '系统时间同步失败'
  } finally {
    savingSystemTime.value = false
  }
}

function mirrorInterfaceLabel(iface) {
  const parts = [iface.name]
  if (iface.ips?.length) parts.push(iface.ips.join(', '))
  if (iface.source?.includes('host')) parts.push('宿主机网卡')
  if (iface.source === 'server') parts.push('容器网卡')
  return parts.join(' · ')
}

async function saveMirrorConfig() {
  if (!mirrorInterface.value.trim()) return
  savingMirror.value = true
  mirrorMessage.value = ''
  error.value = ''
  try {
    const data = await trafficClient.updateMirrorInterface({ interface: mirrorInterface.value.trim(), enabled: true })
    mirrorInterface.value = data?.interface || mirrorInterface.value.trim()
    mirrorInterfaces.value = Array.isArray(data?.interfaces) ? data.interfaces.filter((item) => item?.name) : mirrorInterfaces.value
    mirrorEnabled.value = Boolean(data?.enabled)
    mirrorMessage.value = '抓包接口设置已保存'
  } catch (e) {
    error.value = e?.message || '抓包接口设置保存失败'
  } finally {
    savingMirror.value = false
  }
}

async function saveTargetLocation() {
  if (!targetCity.value.trim()) return
  savingTargetLocation.value = true
  targetLocationMessage.value = ''
  error.value = ''
  try {
    const data = await overviewClient.updateTargetLocation({
      country: '中国',
      province: targetProvince.value.trim(),
      city: targetCity.value.trim(),
      district: targetDistrict.value.trim(),
    })
    targetProvince.value = data?.province || targetProvince.value.trim()
    targetCity.value = data?.city || targetCity.value.trim()
    targetDistrict.value = data?.district || targetDistrict.value.trim()
    targetLocationMessage.value = `已保存：态势地图目标区域 = ${data?.label || [targetProvince.value, targetCity.value, targetDistrict.value].filter(Boolean).join('·')}`
  } catch (e) {
    error.value = e?.message || '地点设置保存失败'
  } finally {
    savingTargetLocation.value = false
  }
}

async function toggleCap(agent, field) {
  const key = agent.agent_id + '_' + field
  const next = !agent[field + '_enabled']
  if (field === 'rasp' && next) {
    raspApproval.value = agent
    return
  }
  await doToggleCap(agent, field, next, key)
}

async function doToggleCap(agent, field, next, key) {
  toggling.value = key
  error.value = ''
  try {
    await assetAgentClient.toggleAgentCapability(agent.agent_id, field, next)
    agent[field + '_enabled'] = next
  } catch (e) {
    error.value = e?.message || '功能切换失败'
  } finally {
    toggling.value = ''
  }
}

async function confirmRaspProtection() {
  if (!raspApproval.value) return
  approvingRasp.value = true
  const agent = raspApproval.value
  const key = agent.agent_id + '_rasp'
  try {
    await assetAgentClient.toggleAgentCapability(agent.agent_id, 'rasp', true)
    agent.rasp_enabled = true
    raspApproval.value = null
  } catch (e) {
    error.value = e?.message || 'RASP 防护开启失败'
  } finally {
    approvingRasp.value = false
  }
}

async function deleteAgent(agent) {
  deleting.value = agent.agent_id
  error.value = ''
  try {
    await assetAgentClient.deleteAgent(agent.agent_id)
    agents.value = agents.value.filter((a) => a.agent_id !== agent.agent_id)
    total.value -= 1
  } catch (e) {
    error.value = e?.message || '删除失败，只能删除离线 Agent'
  } finally {
    deleting.value = ''
  }
}

function startRename(agent) {
  renaming.value = agent
  renameValue.value = agent.display_name || agent.hostname || agent.agent_id
}

async function confirmRename() {
  if (!renaming.value || !renameValue.value.trim()) return
  savingRename.value = true
  error.value = ''
  try {
    const result = await assetAgentClient.renameAgent(renaming.value.agent_id, renameValue.value.trim())
    renaming.value.display_name = result?.display_name || renameValue.value.trim()
    renaming.value = null
  } catch (e) {
    error.value = e?.message || '改名失败'
  } finally {
    savingRename.value = false
  }
}

onMounted(() => {
  loadMirrorConfig()
  loadTargetLocation()
  loadSystemTime()
})
</script>

<style scoped>
.control-page {
  position: relative;
  height: auto;
  min-height: 100%;
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 14px;
  color: var(--text-primary);
  box-sizing: border-box;
  overflow: visible;
}

.control-header,
.stats-bar,
.settings-grid,
.panel {
  border: 1px solid var(--border-color);
  border-radius: var(--card-radius);
  background: var(--bg-card);
  box-shadow: var(--shadow-card);
}

.control-header {
  height: 44px;
  display: flex;
  align-items: center;
  padding: 0 16px;
}

.control-header h2 {
  margin: 0;
  color: var(--text-primary);
  font-size: 16px;
}

.stats-bar {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  padding: 12px;
}

.stat-card {
  display: grid;
  gap: 4px;
  padding: 12px 14px;
  border: 1px solid var(--border-light);
  border-radius: var(--card-radius-sm);
  background: rgba(2, 8, 23, 0.24);
}

.stat-card span {
  color: var(--text-muted);
  font-size: 12px;
}

.stat-card strong {
  color: var(--text-primary);
  font-size: 24px;
  font-weight: 950;
}

.stat-card.online strong {
  color: var(--risk-low);
}

.stat-card.offline strong {
  color: var(--risk-critical);
}

.panel {
  min-width: 0;
  overflow: visible;
}

.settings-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  align-items: start;
  gap: 12px;
  background: transparent;
  border: 0;
  box-shadow: none;
}

.agent-panel {
  min-height: 0;
  display: grid;
  grid-template-rows: 44px minmax(0, 1fr) auto;
}

.mirror-panel {
  display: grid;
  grid-template-rows: 44px auto auto;
}

.mirror-form,
.location-form,
.time-form {
  display: grid;
  grid-template-columns: minmax(180px, 1fr) auto;
  gap: 10px;
  align-items: end;
  padding: 12px 16px;
}

.mirror-form label,
.location-form label,
.time-form label {
  display: grid;
  gap: 6px;
  color: var(--text-secondary);
  font-size: 12px;
}

.mirror-form small,
.location-form small,
.time-form small {
  grid-column: 1 / -1;
}

.mirror-form small,
.location-form small {
  align-self: center;
  color: var(--text-muted);
  font-size: 12px;
}

.location-form {
  grid-template-columns: repeat(3, minmax(96px, 1fr)) auto;
  align-items: end;
}

.location-panel .notice.success {
  margin: 0 16px 14px;
}

.location-title span {
  max-width: 160px;
  text-align: right;
  line-height: 1.35;
}

.mirror-switch {
  grid-template-columns: auto auto;
  align-items: center;
  gap: 8px !important;
  height: 32px;
}

.mirror-switch input {
  width: 16px;
  height: 16px;
  padding: 0;
}

.panel-title {
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
  border-bottom: 1px solid var(--border-light);
  background: rgba(4, 12, 24, 0.38);
}

.panel-title strong {
  color: var(--text-primary);
  font-size: 14px;
}

.panel-title span {
  color: var(--text-muted);
  font-size: 12px;
}

.table-wrap {
  min-height: 0;
  overflow: auto;
}

table {
  width: 100%;
  min-width: 980px;
  border-collapse: separate;
  border-spacing: 0;
  table-layout: fixed;
}

.col-agent { width: 25%; }
.col-ip { width: 14%; }
.col-uptime { width: 16%; }
.col-caps { width: 29%; }
.col-status { width: 9%; }
.col-action { width: 7%; }

th,
td {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border-light);
  text-align: left;
  vertical-align: middle;
}

th {
  position: sticky;
  top: 0;
  z-index: 1;
  height: 36px;
  color: var(--text-muted);
  background: var(--bg-card);
  font-size: 11px;
  font-weight: 900;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

td {
  height: 38px;
  color: var(--text-primary);
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.empty-cell {
  height: 96px;
  text-align: center;
  color: var(--text-secondary);
}

.agent-row.offline {
  opacity: 0.62;
}

.agent-row.editing td {
  background: rgba(125, 211, 252, 0.05);
}

.probe-name {
  max-width: 100%;
  height: auto;
  display: inline-grid;
  grid-template-columns: minmax(0, auto) auto;
  align-items: center;
  gap: 6px;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--text-primary);
  font-size: 12px;
  font-weight: 800;
  text-align: left;
  cursor: pointer;
}

.probe-name span,
.agent-id {
  overflow: hidden;
  text-overflow: ellipsis;
}

.rename-hint {
  display: inline-flex;
  margin: 0;
  padding: 2px 7px;
  border: 1px solid rgba(125, 211, 252, 0.24);
  border-radius: 999px;
  color: var(--primary-light);
  background: rgba(125, 211, 252, 0.09);
  font-size: 12px;
  font-weight: 800;
}

.probe-name:hover .rename-hint,
.probe-name:focus-visible .rename-hint {
  border-color: var(--border-glow);
  background: var(--bg-hover);
}

.agent-id {
  display: block;
  margin-top: 3px;
  color: var(--text-muted);
}

.caps-col {
  white-space: nowrap;
  overflow: visible;
}

.caps-group {
  display: grid;
  grid-template-columns: repeat(3, minmax(76px, 1fr));
  align-items: center;
  gap: 6px;
  max-width: 100%;
}

.cap-tag,
.cap-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 26px;
  padding: 0 8px;
  border: 1px solid var(--border-color);
  border-radius: 999px;
  background: var(--bg-elevated);
  color: var(--text-secondary);
  font-size: 11px;
  line-height: 1;
}

.cap-btn {
  cursor: pointer;
}

.cap-btn.on,
.cap-btn.protect {
  color: var(--risk-low);
  background: var(--risk-low-bg);
  border-color: var(--risk-low-border);
}

.cap-btn.off,
.cap-btn.detect {
  color: var(--primary-light);
  background: rgba(125, 211, 252, 0.09);
  border-color: rgba(125, 211, 252, 0.24);
}

.del-text {
  color: var(--risk-critical);
  background: var(--risk-critical-bg);
  border-color: var(--risk-critical-border);
}

.status-col {
  overflow: visible;
}

.status-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  min-width: 58px;
  height: 24px;
  padding: 0 9px;
  border: 1px solid var(--risk-critical-border);
  border-radius: 999px;
  color: var(--risk-critical);
  background: var(--risk-critical-bg);
  font-size: 11px;
  font-weight: 900;
}

.status-pill.online {
  border-color: var(--risk-low-border);
  color: var(--risk-low);
  background: var(--risk-low-bg);
}

.status-dot {
  width: 7px;
  height: 7px;
  flex: 0 0 auto;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 12px currentColor;
}

.ops-col {
  text-align: right;
}

.rename-row td {
  height: auto;
  padding: 0;
  background: linear-gradient(90deg, rgba(125, 211, 252, 0.08), rgba(2, 8, 23, 0.18));
  overflow: visible;
}

.rename-editor {
  display: grid;
  grid-template-columns: minmax(150px, 0.7fr) minmax(240px, 1fr) auto;
  gap: 10px;
  align-items: end;
  padding: 10px 12px 12px;
  border-top: 1px solid var(--border-light);
}

.rename-context,
.rename-editor label {
  display: grid;
  gap: 5px;
  min-width: 0;
  color: var(--text-secondary);
  font-size: 12px;
}

.rename-context strong {
  color: var(--text-primary);
  overflow: hidden;
  text-overflow: ellipsis;
}

.rename-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
}

.notice {
  padding: 10px 12px;
  color: var(--risk-critical);
  background: var(--risk-critical-bg);
  border-top: 1px solid var(--risk-critical-border);
  font-size: 12px;
}

.notice.success {
  color: var(--risk-low);
  background: var(--risk-low-bg);
  border-top-color: var(--risk-low-border);
}

input,
select {
  height: 32px;
  min-width: 0;
  border: 1px solid var(--border-color);
  border-radius: var(--card-radius-sm);
  background: var(--bg-secondary);
  color: var(--text-primary);
  padding: 0 11px;
  font-size: 12px;
  outline: 0;
}

select {
  cursor: pointer;
}

select:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

input:focus,
select:focus {
  border-color: var(--border-glow);
  box-shadow: 0 0 0 3px var(--primary-glow);
}

.modal-mask {
  position: fixed;
  inset: 0;
  z-index: 40;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: rgba(2, 8, 23, 0.58);
}

.modal-card,
.score-modal {
  width: min(520px, 92vw);
  display: grid;
  gap: 14px;
  padding: 18px;
  border: 1px solid var(--border-color);
  border-radius: var(--card-radius);
  background: var(--bg-card);
  box-shadow: var(--shadow-card);
}

.modal-card h3,
.modal-head strong {
  margin: 0;
  color: var(--text-primary);
  font-size: 16px;
}

.modal-card p,
.modal-body {
  margin: 0;
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.7;
}

.modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.modal-body {
  display: grid;
  gap: 12px;
}

.modal-body label {
  display: grid;
  gap: 5px;
}

.rasp-warn {
  padding: 12px;
  border: 1px solid var(--risk-critical-border);
  border-radius: var(--card-radius-sm);
  background: var(--risk-critical-bg);
}

.rasp-agent-name {
  margin: 0 0 12px;
  color: var(--text-primary);
  font-size: 14px;
  font-weight: 700;
}

.rasp-mode-audit {
  color: var(--primary-light);
}

.rasp-mode-protect {
  color: var(--risk-low);
}

.rasp-warn p {
  margin: 0 0 8px;
}

.rasp-warn ul {
  margin: 0;
  padding-left: 18px;
}

.approval-text {
  color: var(--primary-light);
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

button {
  height: 32px;
  padding: 0 12px;
  border: 1px solid var(--border-color);
  border-radius: var(--card-radius-sm);
  background: var(--bg-elevated);
  color: var(--text-secondary);
  cursor: pointer;
  font-size: 12px;
  transition: border-color var(--transition-fast), color var(--transition-fast), background var(--transition-fast);
}

button:hover:not(:disabled) {
  border-color: var(--border-glow);
  color: var(--text-primary);
  background: var(--bg-hover);
}

button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.primary {
  border: 0;
  background: linear-gradient(135deg, var(--primary-color), var(--risk-low));
  color: var(--text-inverse);
  font-weight: 900;
}

@media (max-width: 900px) {
  .control-page {
    padding: 10px;
  }

  .stats-bar {
    grid-template-columns: 1fr;
  }

  .mirror-form {
    grid-template-columns: 1fr;
    align-items: stretch;
  }

  table {
    min-width: 780px;
  }

  .rename-editor {
    grid-template-columns: 1fr;
  }

  .rename-actions {
    justify-content: flex-start;
  }
}

.control-page { grid-template-rows: 38px 48px 142px minmax(0,1fr); gap: 8px; padding: 10px; color: #243149; }
.control-header, .stats-bar, .panel { border-color: #dce4ef; border-radius: 6px; background: #fff; box-shadow: 0 3px 12px rgba(44,66,96,.07); }
.control-header { height: 38px; }
.stats-bar { display: flex; padding: 5px 8px; gap: 0; }
.stat-card { flex: 1; display: flex; align-items: center; justify-content: center; gap: 10px; padding: 3px 12px; border: 0; border-right: 1px solid #e4eaf1; border-radius: 0; background: #fff; }
.stat-card:last-child { border-right: 0; }
.stat-card span { color: #6f7c91; }
.stat-card strong { color: #1769d2; font-size: 20px; }
.stat-card.online strong { color: #178653; }.stat-card.offline strong { color: #c53a32; }
.settings-grid { grid-template-columns: .85fr 1.25fr 1.9fr; gap: 8px; }
.mirror-panel { grid-template-rows: 34px minmax(0,1fr) auto; border-radius: 6px; }
.panel-title { height: 34px; padding: 0 12px; border-color: #e3e9f1; background: #f6f8fb; }
.panel-title strong { color: #263247; font-size: 13px; }
.panel-title span { color: #758195; }
.mirror-form, .location-form, .time-form { gap: 7px; padding: 8px 10px; }
.mirror-form { grid-template-columns: minmax(130px,1fr) auto; }
.location-form { grid-template-columns: repeat(3,minmax(80px,1fr)); }
.location-form .primary { grid-column: 3; justify-self:end; }
.time-form { grid-template-columns: repeat(4,minmax(100px,1fr)); align-items:end; }
.time-form input { min-width: 0; width: 100%; padding: 0 7px; font-size: 11px; }
.time-form button { grid-row: 2; }
.mirror-form label, .location-form label, .time-form label { gap: 3px; color: #5c6a80; font-size: 12px; }
input, select { height: 29px; border-color: #d7e0eb; border-radius: 4px; background: #fff; color: #263247; }
input:disabled { background: #f2f5f8; color: #78869a; }
button { height: 29px; border-color: #d7e0eb; border-radius: 4px; background: #fff; color: #40506a; }
.primary { background: #1769d2; color: #fff; }
.agent-panel { grid-template-rows: 34px minmax(0,1fr) 36px auto; }
.agent-pager { display:flex;align-items:center;justify-content:flex-end;gap:7px;padding:3px 10px;border-top:1px solid #e4eaf1;background:#f7f9fc;color:#68758a;font-size:11px; }
.agent-pager button { height:26px; }
th { background: #eef3f8; color: #53627a; text-align:center; }
td { color: #304058; text-align:center; }
th, td { border-color: #e6ebf2; }
.table-wrap { background: #fff; }
.caps-group { justify-content:center; }.status-col,.ops-col { text-align:center; }
@media (max-width: 1200px) { .control-page { overflow:auto; grid-template-rows:auto; }.settings-grid { grid-template-columns:1fr; }.agent-panel { min-height:480px; }.time-form { grid-template-columns:repeat(2,1fr); } }

/* Keep the control surface predictable at desktop widths. */
.control-page {
  grid-template-rows: 38px 48px 142px minmax(360px, 1fr);
  min-width: 0;
}
.stats-bar,
.settings-grid,
.agent-panel { min-width: 0; }
.stats-bar { overflow: hidden; }
.stats-bar { height: 48px; align-items: center; padding: 0 8px; }
.stat-card { min-width: 0; height: 48px; align-items: center; }
.settings-grid {
  grid-template-columns: minmax(170px, .9fr) minmax(270px, 1.35fr) minmax(420px, 2fr);
}
.mirror-panel { min-width: 0; }
.mirror-form,
.location-form,
.time-form { min-width: 0; }
.location-form label,
.time-form label { min-width: 0; }
.location-form select,
.time-form input,
.time-form select { min-width: 0; max-width: 100%; }
.agent-panel .table-wrap { min-width: 0; overflow: auto; }
.agent-panel table { width: 100%; min-width: 900px; table-layout: fixed; }
.agent-panel th,
.agent-panel td { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.agent-panel .caps-col { white-space: normal; }

@media (max-width: 1200px) {
  .settings-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .time-form { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

@media (max-width: 900px) {
  .control-page { min-height: 0; grid-template-rows: auto; }
  .settings-grid { grid-template-columns: 1fr; }
}

/* Settings panels must grow with their forms; the legacy page grid rows
   were sized for the old Agent table and clipped these cards. */
.control-page {
  display: flex;
  flex-direction: column;
  height: auto;
  min-height: 100%;
  grid-template-rows: none;
}
.settings-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
  align-items: start;
}
.mirror-panel {
  grid-template-rows: 34px auto auto;
}
@media (max-width: 1200px) {
  .settings-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .time-panel { grid-column: 1 / -1; }
  .time-form { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 800px) {
  .settings-grid { grid-template-columns: 1fr; }
  .time-panel { grid-column: auto; }
  .mirror-form,
  .time-form { grid-template-columns: 1fr; }
  .location-form { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}

/* Final settings surface: readable cards, aligned controls and a calm hierarchy. */
.control-page {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 18px;
  min-height: 100%;
  height: auto;
  background:
    radial-gradient(circle at 92% 4%, rgba(23, 105, 210, 0.08), transparent 28%),
    #f3f6fa;
}
.control-header {
  height: auto;
  min-height: 82px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  padding: 16px 20px;
  border: 1px solid #dfe7f0;
  border-radius: 10px;
  background: #fff;
  box-shadow: 0 5px 18px rgba(36, 58, 88, 0.06);
}
.control-heading { min-width: 0; }
.control-kicker {
  display: block;
  margin-bottom: 5px;
  color: #1769d2;
  font-size: 12px;
  font-weight: 800;
  letter-spacing: .14em;
}
.control-heading h2 { margin: 0; color: #1f2d3d; font-size: 20px; line-height: 1.25; }
.control-heading p { margin: 5px 0 0; color: #718096; font-size: 12px; line-height: 1.5; }
.control-live {
  display: inline-flex;
  flex: 0 0 auto;
  align-items: center;
  gap: 7px;
  padding: 7px 11px;
  border: 1px solid #b8dfca;
  border-radius: 999px;
  background: #edf9f2;
  color: #19794b;
  font-size: 11px;
  font-weight: 700;
}
.control-live i { width: 7px; height: 7px; border-radius: 50%; background: #20a66a; box-shadow: 0 0 0 3px #d9f2e5; }
.settings-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; align-items: stretch; }
.panel {
  min-width: 0;
  overflow: visible;
  border: 1px solid #dfe7f0;
  border-radius: 10px;
  background: #fff;
  box-shadow: 0 5px 18px rgba(36, 58, 88, 0.055);
}
.mirror-panel { display: flex; flex-direction: column; min-width: 0; height: 100%; }
.panel-title {
  height: auto;
  min-height: 62px;
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 12px 16px;
  border-bottom: 1px solid #e7edf4;
  border-radius: 10px 10px 0 0;
  background: #f8fafc;
}
.panel-icon {
  display: grid;
  width: 34px;
  height: 34px;
  flex: 0 0 34px;
  place-items: center;
  border: 1px solid #cfe1f8;
  border-radius: 8px;
  background: #eaf4ff;
  color: #1769d2;
  font-size: 11px;
  font-weight: 900;
  letter-spacing: .04em;
}
.panel-heading { min-width: 0; }
.panel-heading strong { display: block; color: #243149; font-size: 14px; line-height: 1.35; }
.panel-heading small { display: block; margin-top: 3px; color: #7b8798; font-size: 11px; line-height: 1.4; }
.mirror-form,
.location-form,
.time-form { padding: 16px; gap: 12px; }
.mirror-form { grid-template-columns: minmax(0, 1fr) auto; align-items: end; }
.location-form { grid-template-columns: repeat(3, minmax(0, 1fr)); align-items: end; }
.location-form .primary { grid-column: 1 / -1; justify-self: end; }
.time-form { grid-template-columns: repeat(2, minmax(0, 1fr)); align-items: end; }
.time-form .time-actions { grid-column: 1 / -1; display: flex; justify-content: flex-end; gap: 8px; }
.mirror-form label,
.location-form label,
.time-form label { display: grid; gap: 6px; min-width: 0; color: #5f6e84; font-size: 11px; font-weight: 600; }
.mirror-form select,
.location-form select,
.time-form input { width: 100%; min-width: 0; height: 36px; border: 1px solid #d6e0eb; border-radius: 6px; background: #fff; color: #243149; padding: 0 10px; font-size: 12px; }
.time-readonly input { background: #f4f7fa; color: #5d6b80; }
.mirror-form input:focus,
.mirror-form select:focus,
.location-form select:focus,
.time-form input:focus { border-color: #6aa8ea; box-shadow: 0 0 0 3px rgba(23, 105, 210, .08); }
.mirror-form button,
.location-form button,
.time-form button { height: 36px; padding: 0 16px; border: 1px solid #d6e0eb; border-radius: 6px; background: #fff; color: #40506a; font-size: 12px; font-weight: 700; white-space: nowrap; }
.mirror-form .primary,
.location-form .primary,
.time-form .primary { border-color: #1769d2; background: #1769d2; color: #fff; }
.mirror-form button:hover:not(:disabled),
.location-form button:hover:not(:disabled),
.time-form button:hover:not(:disabled) { border-color: #8bb8e8; color: #1769d2; background: #f5faff; }
.mirror-form .primary:hover:not(:disabled),
.location-form .primary:hover:not(:disabled),
.time-form .primary:hover:not(:disabled) { border-color: #0f57b0; color: #fff; background: #0f57b0; }
.location-panel .notice.success,
.time-panel .notice.success { margin: 0 16px 14px; border-radius: 6px; }
@media (max-width: 1180px) {
  .settings-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .time-panel { grid-column: 1 / -1; }
  .time-form { grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .time-form .time-actions { grid-column: 1 / -1; }
}
@media (max-width: 760px) {
  .control-page { padding: 12px; }
  .control-header { align-items: flex-start; flex-direction: column; }
  .settings-grid { grid-template-columns: 1fr; }
  .time-panel { grid-column: auto; }
  .mirror-form,
  .time-form { grid-template-columns: 1fr; }
  .location-form { grid-template-columns: 1fr; }
  .time-form .time-actions { grid-column: auto; justify-content: flex-start; }
}
</style>
