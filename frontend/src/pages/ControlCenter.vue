<template>
  <section class="control-page">
    <header class="control-header">
      <h2>控制中心</h2>
    </header>

    <section class="stats-bar">
      <div class="stat-card">
        <span>在线 Agent</span>
        <strong>{{ onlineCount }}</strong>
      </div>
      <div class="stat-card online">
        <span>登记 Agent</span>
        <strong>{{ agents.length }}</strong>
      </div>
      <div class="stat-card offline">
        <span>离线 Agent</span>
        <strong>{{ offlineCount }}</strong>
      </div>
    </section>

    <section class="settings-grid">
      <article class="panel mirror-panel">
        <div class="panel-title"><strong>抓包接口设置</strong><span>安全系统本机镜像抓包口</span></div>
        <form class="mirror-form" @submit.prevent="saveMirrorConfig">
          <label>
            <span>镜像接口</span>
            <select v-model="mirrorInterface" :disabled="!mirrorInterfaces.length">
              <option value="" disabled>{{ mirrorInterfaces.length ? '请选择镜像网卡' : '未读取到可选网卡' }}</option>
              <option v-for="iface in mirrorInterfaces" :key="iface.name" :value="iface.name">{{ mirrorInterfaceLabel(iface) }}</option>
            </select>
          </label>
          <label class="mirror-switch">
            <input v-model="mirrorEnabled" type="checkbox">
            <span>启用镜像流量标识</span>
          </label>
          <button type="submit" class="primary" :disabled="savingMirror || !mirrorInterface.trim()">{{ savingMirror ? '保存中' : '保存设置' }}</button>
          <small>匹配该接口的会话与流量威胁，探针栏统一显示“流量镜像分析”。</small>
        </form>
        <div v-if="mirrorMessage" class="notice success">{{ mirrorMessage }}</div>
      </article>

      <article class="panel mirror-panel location-panel">
        <div class="panel-title"><strong>地点设置</strong><span>同步态势感知被攻击源</span></div>
        <form class="location-form" @submit.prevent="saveTargetLocation">
          <label><span>省份</span><input v-model="targetProvince" placeholder="北京"></label>
          <label><span>城市</span><input v-model="targetCity" placeholder="北京"></label>
          <label><span>市区</span><input v-model="targetDistrict" placeholder="海淀区"></label>
          <button type="submit" class="primary" :disabled="savingTargetLocation || !targetCity.trim()">{{ savingTargetLocation ? '保存中' : '保存地点' }}</button>
          <small>保存后全球态势地图目标点与目标区域会同步为该市区。</small>
        </form>
        <div v-if="targetLocationMessage" class="notice success">{{ targetLocationMessage }}</div>
      </article>
    </section>

    <article class="panel agent-panel">
      <div class="panel-title"><strong>Agent 列表</strong><span>{{ `${onlineCount} 在线 / ${agents.length} 登记` }}</span></div>
      <div class="table-wrap">
        <table>
          <colgroup>
            <col class="col-agent">
            <col class="col-ip">
            <col class="col-uptime">
            <col class="col-caps">
            <col class="col-status">
            <col class="col-action">
          </colgroup>
          <thead><tr><th>探针名</th><th>IP 地址</th><th>运行时间</th><th>开启功能</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-if="loading && !hasLoaded"><td colspan="6" class="empty-cell">正在读取 Agent 数据</td></tr>
            <tr v-else-if="!agents.length"><td colspan="6" class="empty-cell">暂无 Agent 注册</td></tr>
            <template v-for="agent in agents" :key="agent.id || agent.agent_id">
              <tr :class="['agent-row', { offline: !isOnline(agent), editing: renaming && renaming.agent_id === agent.agent_id }]">
                <td>
                  <button type="button" class="probe-name" :title="'点击修改名称'" @click="startRename(agent)">
                    <span>{{ agent.display_name || agent.hostname || agent.agent_id }}</span>
                    <small class="rename-hint">点击改名</small>
                  </button>
                  <small class="agent-id">{{ agent.agent_id }}</small>
                </td>
                <td>{{ cleanIP(agent.ip) }}</td>
                <td>{{ uptimeText(agent) }}</td>
                <td class="caps-col">
                  <div class="caps-group">
                    <button :class="['cap-btn', agent.traffic_enabled ? 'on' : 'off']" :disabled="toggling === agent.agent_id + '_traffic'" @click="toggleCap(agent, 'traffic')">{{ toggling === agent.agent_id + '_traffic' ? '…' : '流量' }}</button>
                    <span class="cap-tag">HIDS</span>
                    <button :class="['cap-btn', 'rasp', agent.rasp_enabled ? 'protect' : 'detect']" :disabled="toggling === agent.agent_id + '_rasp'" @click="toggleCap(agent, 'rasp')" :title="agent.rasp_enabled ? '已开启防护阻断' : '点击审批开启阻断'">{{ toggling === agent.agent_id + '_rasp' ? '…' : (agent.rasp_enabled ? 'RASP 防护' : 'RASP 审计') }}</button>
                  </div>
                </td>
                <td class="status-col">
                  <span :class="['status-pill', agentStatus(agent)]"><span class="status-dot"></span>{{ isOnline(agent) ? '在线' : '离线' }}</span>
                </td>
                <td class="ops-col">
                  <button v-if="!isOnline(agent)" class="cap-btn off del-text" :disabled="deleting === agent.agent_id" @click="deleteAgent(agent)">{{ deleting === agent.agent_id ? '…' : '删除' }}</button>
                </td>
              </tr>
              <tr v-if="renaming && renaming.agent_id === agent.agent_id" class="rename-row">
                <td colspan="6">
                  <div class="rename-editor">
                    <div class="rename-context">
                      <span>修改探针名称</span>
                      <strong>{{ renaming.agent_id }}</strong>
                    </div>
                    <label>
                      <span>新名称</span>
                      <input v-model="renameValue" @keydown.enter="confirmRename" placeholder="输入唯一名称">
                    </label>
                    <div class="rename-actions">
                      <button type="button" @click="renaming = null">取消</button>
                      <button type="button" class="primary" :disabled="!renameValue.trim() || savingRename" @click="confirmRename">{{ savingRename ? '保存中' : '确认' }}</button>
                    </div>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
      <div v-if="error" class="notice error">{{ error }}</div>
    </article>

    <div v-if="raspApproval" class="modal-mask" @click.self="raspApproval = null">
      <section class="score-modal">
        <div class="modal-head"><strong>RASP 防护阻断审批</strong><button @click="raspApproval = null">×</button></div>
        <div class="modal-body">
          <p class="rasp-agent-name">{{ raspApproval.display_name || raspApproval.hostname || raspApproval.agent_id }}</p>
          <div class="rasp-warn">
            <p>将 RASP 从 <b class="rasp-mode-audit">审计模式</b> 切换至 <b class="rasp-mode-protect">防护阻断模式</b></p>
            <ul>
              <li>开启后系统将实时拦截探测到的 SQL 注入 / 命令执行 / 文件访问 / SSRF 等攻击行为</li>
              <li>拦截日志可在威胁中心查看，阻断动作不可撤销</li>
              <li>请确认该探针上的业务应用已通过安全评估</li>
            </ul>
          </div>
        </div>
        <div class="modal-actions"><button @click="raspApproval = null">取消</button><button class="primary" :disabled="approvingRasp" @click="confirmRaspProtection">{{ approvingRasp ? '审批中…' : '确认开启阻断' }}</button></div>
      </section>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { assetAgentClient, overviewClient, trafficClient } from '../api/domain'
import { normalizeItems } from '../shared/api-normalize'

const agents = ref([])
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

const onlineCount = computed(() => agents.value.filter((a) => isOnline(a)).length)
const offlineCount = computed(() => Math.max(agents.value.length - onlineCount.value, 0))

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
    mirrorEnabled.value = Boolean(data?.enabled)
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
    const data = await trafficClient.updateMirrorInterface({ interface: mirrorInterface.value.trim(), enabled: mirrorEnabled.value })
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
    targetLocationMessage.value = `态势目标已同步为 ${data?.label || [targetProvince.value, targetCity.value, targetDistrict.value].filter(Boolean).join('·')}`
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
  loadAgents()
  loadMirrorConfig()
  loadTargetLocation()
})
</script>

<style scoped>
.control-page {
  position: relative;
  height: 100%;
  min-height: 0;
  display: grid;
  grid-template-rows: auto auto auto minmax(0, 1fr);
  gap: 12px;
  padding: 14px;
  color: var(--text-primary);
  box-sizing: border-box;
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
  overflow: hidden;
}

.settings-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.08fr) minmax(360px, 0.92fr);
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
.location-form {
  display: grid;
  grid-template-columns: minmax(220px, 0.45fr) auto auto minmax(260px, 1fr);
  gap: 10px;
  align-items: end;
  padding: 12px 16px;
}

.mirror-form label,
.location-form label {
  display: grid;
  gap: 6px;
  color: var(--text-secondary);
  font-size: 12px;
}

.mirror-form small,
.location-form small {
  align-self: center;
  color: var(--text-muted);
  font-size: 12px;
}

.location-form {
  grid-template-columns: minmax(86px, 0.85fr) minmax(86px, 0.85fr) minmax(96px, 0.9fr) auto minmax(170px, 1fr);
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
  font-size: 10px;
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
</style>
