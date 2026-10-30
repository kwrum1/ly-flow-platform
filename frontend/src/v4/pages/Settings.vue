<template>
  <section class="v-page">
    <header class="v-head">
      <div>
        <p class="v-eyebrow">SYSTEM</p>
        <h1>系统管理</h1>
        <p>平台参数、账户与安装配置。时间源与采集接口保存后立即生效；账户操作写入后端审计。</p>
      </div>
      <div class="v-head-actions">
        <button class="v-btn" type="button" :disabled="loading" @click="load">{{ loading ? '刷新中…' : '刷新' }}</button>
      </div>
    </header>

    <div v-if="error" class="v-error">{{ error }}</div>

    <div class="v-tabs">
      <button v-for="t in tabs" :key="t.key" type="button" class="v-tab" :class="{ active: tab === t.key }" @click="tab = t.key">{{ t.label }}</button>
    </div>

    <!-- platform -->
    <div v-if="tab === 'platform'" class="v-grid c2">
      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">镜像采集接口</div><span class="v-panel-meta">管理口自动排除</span></div>
        <div class="v-panel-body form">
          <label class="v-field"><span>镜像接口</span>
            <select v-model="mirrorInterface" class="v-select">
              <option value="">不启用本机镜像</option>
              <option v-for="i in interfaces" :key="i.name || i" :value="i.name || i">{{ i.label || i.name || i }}</option>
            </select>
          </label>
          <p class="hint">未选择接口时只接收 Agent 上报；选择后由 PF_RING 采集镜像流量。</p>
          <button class="v-btn primary" type="button" :disabled="savingMirror" @click="saveMirror">{{ savingMirror ? '保存中…' : '保存接口' }}</button>
        </div>
      </article>

      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">时间基准</div><span class="v-panel-meta">当前来源 {{ timeSource }}</span></div>
        <div class="v-panel-body form">
          <dl class="v-kv">
            <dt>服务端时间</dt><dd>{{ serverTime }}</dd>
            <dt>平台时间</dt><dd>{{ platformTime }}</dd>
            <dt>偏移</dt><dd class="v-mono">{{ offsetText }}</dd>
            <dt>同步状态</dt><dd><span class="v-state" :data-state="timeState">{{ timeStateLabel }}</span></dd>
          </dl>
          <label class="v-field"><span>NTP 服务器</span><input v-model.trim="ntpServer" class="v-input" placeholder="ntp.aliyun.com"></label>
          <div class="row">
            <button class="v-btn primary" type="button" :disabled="savingTime" @click="saveTime">{{ savingTime ? '保存中…' : '保存时间源' }}</button>
            <button class="v-btn" type="button" :disabled="savingTime" @click="syncNow">立即校准</button>
          </div>
        </div>
      </article>
    </div>

    <!-- accounts -->
    <article v-else-if="tab === 'accounts'" class="v-panel">
      <div class="v-panel-head"><div class="v-panel-title">账户</div><span class="v-panel-meta">{{ users.length }} 个账户</span></div>
      <div class="v-panel-body">
        <div class="v-toolbar">
          <label class="v-field"><span>账号</span><input v-model.trim="newUser.username" class="v-input" placeholder="登录名"></label>
          <label class="v-field"><span>密码</span><input v-model.trim="newUser.password" type="password" class="v-input" placeholder="至少 8 位，含大写与特殊字符"></label>
          <label class="v-field"><span>角色</span>
            <select v-model="newUser.role" class="v-select"><option value="viewer">只读</option><option value="analyst">分析员</option><option value="admin">管理员</option></select>
          </label>
          <button class="v-btn primary" type="button" :disabled="creating" @click="createUser">{{ creating ? '创建中…' : '创建账户' }}</button>
        </div>
      </div>
      <div class="v-table-wrap">
        <table class="v-table">
          <thead><tr><th>账号</th><th>角色</th><th>状态</th><th>最近登录</th><th class="actions">操作</th></tr></thead>
          <tbody>
            <tr v-for="u in users" :key="u.id || u.username">
              <td><b>{{ u.username }}</b><small v-if="u.id === currentUserId">当前登录</small></td>
              <td>{{ roleLabel(u.role) }}</td>
              <td><span class="v-state" :data-state="u.is_active === false ? 'failed' : 'online'">{{ u.is_active === false ? '已停用' : '启用' }}</span></td>
              <td class="num">{{ shortTime(u.last_login_at) }}</td>
              <td class="actions">
                <button class="v-btn sm" type="button" @click="resetPassword(u)">重置密码</button>
                <button class="v-btn sm" type="button" :disabled="u.id === currentUserId" @click="removeUser(u)">删除</button>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-if="!users.length" class="v-table-empty">正在读取账户</div>
      </div>
    </article>

    <!-- install -->
    <div v-else class="v-grid c2">
      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">安装 Agent</div><span class="v-panel-meta">Linux AMD64 / ARM64</span></div>
        <div class="v-panel-body form">
          <pre class="cmd">{{ installCommand || '正在生成…' }}</pre>
          <div class="row"><button class="v-btn" type="button" @click="copy(installCommand)">复制</button><button class="v-btn" type="button" @click="loadInstall">重新生成</button></div>
        </div>
      </article>
      <article class="v-panel">
        <div class="v-panel-head"><div class="v-panel-title">卸载 Agent</div><span class="v-panel-meta">先确认不再需要采集</span></div>
        <div class="v-panel-body form">
          <pre class="cmd">{{ uninstallCommand || '正在生成…' }}</pre>
          <div class="row"><button class="v-btn" type="button" @click="copy(uninstallCommand)">复制</button></div>
        </div>
      </article>
    </div>

    <article class="v-panel">
      <div class="v-panel-head"><div class="v-panel-title">升级与备份</div><span class="v-panel-meta">镜像回滚与备份状态</span></div>
      <div class="v-panel-body form">
        <dl class="v-kv">
          <dt>Server 镜像</dt><dd class="v-mono">{{ versions.server_image || '未知' }}</dd>
          <dt>前端镜像</dt><dd class="v-mono">{{ versions.frontend_image || '未知' }}</dd>
          <dt>备份目录</dt><dd class="v-mono">{{ backup.path || '-' }} · {{ backup.count || 0 }} 个文件</dd>
        </dl>
        <div class="v-table-wrap">
          <table class="v-table">
            <thead><tr><th>备份文件</th><th>大小</th><th>时间</th></tr></thead>
            <tbody>
              <tr v-if="!(backup.items || []).length"><td colspan="3" class="v-empty">备份目录为空或未挂载</td></tr>
              <tr v-for="b in backup.items" :key="b.name">
                <td class="v-mono">{{ b.name }}</td>
                <td class="num">{{ (b.size_bytes / 1024 / 1024).toFixed(1) }} MB</td>
                <td class="num">{{ shortTime(b.modified_at) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <label class="v-field"><span>回滚目标镜像</span><input v-model.trim="rollbackImage" class="v-input" placeholder="ly-flow/server:v36" /></label>
        <pre class="cmd">{{ rollbackCommand }}</pre>
        <div class="row">
          <button class="v-btn" type="button" @click="copy(rollbackCommand)">复制回滚命令</button>
          <button class="v-btn" type="button" @click="copy(backupCommand)">复制备份命令</button>
        </div>
        <ul class="notes">
          <li>备份与回滚在宿主机执行；平台只展示状态并生成命令，不直接重启容器。</li>
          <li>升级前先备份 PostgreSQL 与 ClickHouse；回滚镜像不回滚数据库 schema。</li>
        </ul>
      </div>
    </article>

    <article class="v-panel">
      <div class="v-panel-head"><div class="v-panel-title">开发者</div><span class="v-panel-meta">仅用于数据排查</span></div>
      <div class="v-panel-body form">
        <p class="v-dim">字段覆盖率、采集健康、留存与引擎状态。该页面已从主菜单隐藏，仅在这里进入。</p>
        <RouterLink class="v-btn" to="/health">进入开发者后端</RouterLink>
      </div>
    </article>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { assetAgentClient, authClient, opsClient, overviewClient, trafficClient } from '../../api/domain'
import { classifyClockSource } from '../../domain/data-quality'
import { useAuthStore } from '../../stores/auth'
import { formatChinaDateTime } from '../../shared/time'

const tabs = [
  { key: 'platform', label: '平台设置' },
  { key: 'accounts', label: '账户管理' },
  { key: 'install', label: '安装配置' },
]

const authStore = useAuthStore()
const tab = ref('platform')
const loading = ref(false)
const error = ref('')

const interfaces = ref([])
const mirrorInterface = ref('')
const savingMirror = ref(false)

const systemTime = ref(null)
const versions = ref({})
const backup = ref({ items: [] })
const rollbackImage = ref('')
const ntpServer = ref('')
const savingTime = ref(false)

const users = ref([])
const creating = ref(false)
const newUser = ref({ username: '', password: '', role: 'viewer' })

const installCommand = ref('')
const uninstallCommand = ref('')

const currentUserId = computed(() => authStore.user?.id)
const timeSource = computed(() => systemTime.value?.source || 'unknown')
const clock = computed(() => classifyClockSource(systemTime.value?.source))
const timeState = computed(() => (clock.value.tone === 'success' ? 'online' : clock.value.tone === 'warning' ? 'degraded' : 'unknown'))
const timeStateLabel = computed(() => clock.value.label)
const offsetText = computed(() => { const v = Number(systemTime.value?.offset_ms); return Number.isFinite(v) ? `${Math.round(v / 1000)} s` : '未读取' })
const platformTime = computed(() => systemTime.value?.platform_time ? formatChinaDateTime(systemTime.value.platform_time) : '—')
const serverTime = computed(() => systemTime.value?.server_time ? formatChinaDateTime(systemTime.value.server_time) : '—')

function unwrap(r) { return r?.data?.data ?? r?.data ?? r ?? {} }
function shortTime(v) { return v ? formatChinaDateTime(v) : '-' }
const rollbackCommand = computed(() => {
  const target = rollbackImage.value || 'ly-flow/server:<previous-tag>'
  return `sudo sed -i 's|^LY_SERVER_IMAGE=.*|LY_SERVER_IMAGE=${target}|' /opt/ly-flow-platform/.env\nsudo docker compose -f /opt/ly-flow-platform/docker-compose.yml up -d --force-recreate ly-server`
})
const backupCommand = computed(() => [
  "sudo docker exec ly-flow-platform-postgres-1 pg_dump -U lyflow -Fc lyflow > /opt/lyflow-backup/lyflow-pg-$(date +%F).dump",
  "sudo docker stop ly-flow-platform-clickhouse-1",
  "sudo docker run --rm -v ly-flow-platform_clickhouse_data:/data -v /opt/lyflow-backup:/backup --entrypoint /bin/sh ly-flow/vendor/clickhouse:24.8-alpine-amd64 -c 'tar czf /backup/clickhouse-$(date +%F).tgz -C /data .'",
  "sudo docker start ly-flow-platform-clickhouse-1",
].join('\n'))

function roleLabel(v) { return ({ admin: '管理员', analyst: '分析员', viewer: '只读' })[v] || v || '-' }

async function load() {
  loading.value = true
  error.value = ''
  const [m, t, u, c] = await Promise.allSettled([
    trafficClient.mirrorInterface(),
    overviewClient.systemTime(),
    authClient.users(),
    opsClient.components(),
  ])
  if (m.status === 'fulfilled') {
    const p = unwrap(m.value)
    interfaces.value = p.interfaces || p.candidates || []
    mirrorInterface.value = p.interface || p.current || ''
  }
  if (t.status === 'fulfilled') {
    systemTime.value = t.value
    ntpServer.value = t.value?.ntp_server || ''
  }
  if (u.status === 'fulfilled') {
    const p = unwrap(u.value)
    users.value = Array.isArray(p) ? p : (p.items || [])
  }
  if (c.status === 'fulfilled') {
    const payload = c.value || {}
    versions.value = payload.versions || {}
    backup.value = payload.backup || { items: [] }
  }
  const failed = [m, t, u, c].filter((x) => x.status === 'rejected').length
  if (failed) error.value = `${failed} 个设置接口读取失败。`
  loading.value = false
}

async function saveMirror() {
  savingMirror.value = true
  try { await trafficClient.updateMirrorInterface({ interface: mirrorInterface.value }); await load() } catch (e) { error.value = e?.message || '保存失败' } finally { savingMirror.value = false }
}

async function saveTime() {
  savingTime.value = true
  try { await overviewClient.updateSystemTime({ ntp_server: ntpServer.value, source: ntpServer.value ? 'ntp' : 'manual' }); await load() } catch (e) { error.value = e?.message || '保存失败' } finally { savingTime.value = false }
}

async function syncNow() {
  savingTime.value = true
  try { await overviewClient.updateSystemTime({ sync: true }); await load() } catch (e) { error.value = e?.message || '校准失败' } finally { savingTime.value = false }
}

async function createUser() {
  if (!newUser.value.username || !newUser.value.password) { error.value = '账号与密码不能为空。'; return }
  creating.value = true
  try {
    await authClient.createUser({ ...newUser.value })
    newUser.value = { username: '', password: '', role: 'viewer' }
    await load()
  } catch (e) { error.value = e?.message || '创建失败' } finally { creating.value = false }
}

async function removeUser(u) {
  try { await authClient.deleteUser(u.id); await load() } catch (e) { error.value = e?.message || '删除失败' }
}

async function resetPassword(u) {
  const next = window.prompt(`为 ${u.username} 设置新密码（至少 8 位，含大写与特殊字符）`)
  if (!next) return
  try { await authClient.resetPassword({ user_id: u.id, new_password: next }); error.value = '' } catch (e) { error.value = e?.message || '重置失败' }
}

async function loadInstall() {
  try { const r = await assetAgentClient.installScript(); installCommand.value = typeof r === 'string' ? r : (r?.data || '') } catch { installCommand.value = '' }
  try { const r = await assetAgentClient.uninstallScript(); uninstallCommand.value = typeof r === 'string' ? r : (r?.data || '') } catch { uninstallCommand.value = '' }
}

async function copy(t) { if (!t) return; try { await navigator.clipboard.writeText(t) } catch { /* ignore */ } }

onMounted(() => { load(); loadInstall() })
</script>

<style scoped>
.form { display: grid; gap: 14px; }
.row { display: flex; flex-wrap: wrap; gap: 8px; }
.hint { color: var(--v-ink-3); font-size: 11.5px; line-height: 1.6; }
.cmd { margin: 0; max-height: 260px; padding: 14px; overflow: auto; border: 1px solid var(--v-line); border-radius: var(--v-radius-sm); background: var(--v-surface-3); color: var(--v-ink-2); font-family: var(--v-mono); font-size: 11px; line-height: 1.65; white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
