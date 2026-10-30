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
.control-page { display: grid; gap: 14px; min-width: 0; }
.control-header { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; padding-bottom: 14px; border-bottom: 1px solid var(--lyf-line); background-image: linear-gradient(90deg, var(--lyf-accent-line), transparent 46%); background-repeat: no-repeat; background-position: left bottom; background-size: 100% 1px; }
.control-kicker { margin: 0 0 5px; color: var(--lyf-accent); font-family: var(--lyf-font-data); font-size: 10px; font-weight: 600; letter-spacing: 0.18em; }
.control-heading h2 { margin: 0; color: var(--lyf-ink); font-size: clamp(21px, 2vw, 27px); font-weight: 650; letter-spacing: -0.02em; }
.control-heading p { margin: 7px 0 0; max-width: 900px; color: var(--lyf-ink-3); font-size: 12px; line-height: 1.6; }
.control-live { display: inline-flex; align-items: center; gap: 6px; color: var(--lyf-success); font-family: var(--lyf-font-data); font-size: 10px; font-weight: 700; letter-spacing: 0.1em; }
.control-live i { width: 5px; height: 5px; border-radius: 50%; background: var(--lyf-success); box-shadow: 0 0 8px var(--lyf-success); }

.settings-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.panel { border: 1px solid var(--lyf-line); border-radius: var(--lyf-radius); background: linear-gradient(180deg, rgb(34 211 238 / 4%), transparent 34%), var(--lyf-surface); overflow: hidden; }
.panel-heading { display: flex; align-items: center; gap: 9px; padding: 12px 16px; border-bottom: 1px solid var(--lyf-line); background: var(--lyf-surface-2); }
.panel-icon { display: grid; width: 26px; height: 26px; place-items: center; border: 1px solid var(--lyf-accent-line); border-radius: var(--lyf-radius-sm); color: var(--lyf-accent); }
.panel-title { color: var(--lyf-ink); font-size: 13px; font-weight: 650; }
.mirror-form, .location-form, .time-form { display: grid; gap: 12px; padding: 14px 16px; }
.mirror-form label, .location-form label, .time-form label { display: grid; gap: 5px; color: var(--lyf-ink-3); font-size: 11px; }
.mirror-form input, .mirror-form select, .location-form input, .location-form select, .time-form input, .time-form select { height: 34px; padding: 0 10px; border: 1px solid var(--lyf-line-2); border-radius: var(--lyf-radius-sm); background: var(--lyf-surface); color: var(--lyf-ink); font: inherit; font-size: 12.5px; outline: 0; }
.mirror-form input:focus, .mirror-form select:focus, .location-form input:focus, .location-form select:focus, .time-form input:focus, .time-form select:focus { border-color: var(--lyf-accent); box-shadow: var(--lyf-glow); }
.location-title { margin: 0 0 2px; color: var(--lyf-ink); font-size: 12.5px; font-weight: 600; }
.time-actions { display: flex; flex-wrap: wrap; gap: 8px; }
.time-readonly { color: var(--lyf-ink-3); font-family: var(--lyf-font-data); font-size: 11px; }
.button, .panel button, .primary { height: 32px; padding: 0 12px; border: 1px solid var(--lyf-line-2); border-radius: var(--lyf-radius-sm); background: var(--lyf-surface); color: var(--lyf-ink-2); font: inherit; font-size: 12px; cursor: pointer; }
.button:hover, .panel button:hover { border-color: var(--lyf-accent); color: var(--lyf-accent); }
.primary { border-color: var(--lyf-accent); background: var(--lyf-accent); color: #031018; font-weight: 650; }
.notice { padding: 10px 14px; border: 1px solid var(--lyf-line); border-left-width: 3px; border-radius: var(--lyf-radius-sm); background: var(--lyf-surface-2); color: var(--lyf-ink-2); font-size: 11.5px; }
.notice.success, .success { border-color: var(--lyf-success-line); background: var(--lyf-success-soft); color: var(--lyf-success); }
.notice.error { border-color: var(--lyf-critical-line); background: var(--lyf-critical-soft); color: var(--lyf-critical); }

@media (max-width: 1100px) { .settings-grid { grid-template-columns: minmax(0, 1fr); } }
@media (max-width: 720px) { .control-header { align-items: flex-start; flex-direction: column; } }
</style>
