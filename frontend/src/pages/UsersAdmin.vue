<template>
  <section class="account-page">
    <header class="account-header">
      <div>
        <h2>账户管理</h2>
      </div>
    </header>

    <div v-if="message" class="notice success">{{ message }}</div>
    <div v-if="error" class="notice error">{{ error }}</div>

    <article class="panel table-panel">
      <div class="panel-title"><strong>账户列表</strong><button class="primary" @click="openCreate">新增账户</button></div>
      <table>
        <thead><tr><th>用户名</th><th>角色</th><th>状态</th><th>创建时间</th><th>最近登录</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-if="loading"><td colspan="6" class="empty-cell">正在读取账户数据</td></tr>
          <tr v-else-if="!users.length"><td colspan="6" class="empty-cell">暂无账户</td></tr>
          <tr v-for="user in users" :key="user.id || user.username">
            <td><strong>{{ pickText(user.username, '未命名账户') }}</strong><span v-if="isSelf(user)" class="self-tag">本机账号</span></td>
            <td>
              <select class="role-select" :value="user.role || 'viewer'" :disabled="busy || isSelf(user)" @change="changeRole(user, $event.target.value)">
                <option value="admin">管理员</option>
                <option value="analyst">分析员</option>
                <option value="viewer">只读</option>
              </select>
            </td>
            <td><span :class="['state', user.is_active === false ? 'off' : 'on']">{{ user.is_active === false ? '停用' : '启用' }}</span></td>
            <td>{{ formatTime(user.created_at) }}</td>
            <td>{{ formatTime(user.last_login_at) }}</td>
            <td class="ops">
              <button @click="openReset(user)" :disabled="busy">改密</button>
              <button @click="toggleActive(user)" :disabled="busy || isSelf(user)" :title="isSelf(user) ? '不能停用当前登录账号' : ''">{{ user.is_active === false ? '启用' : '停用' }}</button>
              <button class="danger" @click="deleteUser(user)" :disabled="busy || isSelf(user)" :title="isSelf(user) ? '不能删除当前登录账号' : ''">删除</button>
            </td>
          </tr>
        </tbody>
      </table>
    </article>

    <div v-if="showCreate" class="modal-mask" @click.self="closeCreate">
      <section class="modal-card">
        <div class="modal-title"><strong>新增账户</strong><button @click="closeCreate">×</button></div>
        <div v-if="modalError" class="modal-notice error">{{ modalError }}</div>
        <label><span>用户名</span><input v-model.trim="createForm.username" autocomplete="off"></label>
        <label><span>密码</span><input v-model="createForm.password" type="password" autocomplete="new-password"></label>
        <label><span>确认密码</span><input v-model="createForm.confirmPassword" type="password" autocomplete="new-password"></label>
        <label><span>角色</span>
          <select v-model="createForm.role">
            <option value="viewer">只读</option>
            <option value="analyst">分析员</option>
            <option value="admin">管理员</option>
          </select>
        </label>
        <div class="modal-actions"><button @click="closeCreate" :disabled="busy">取消</button><button class="primary" @click="createUser" :disabled="busy">保存</button></div>
      </section>
    </div>

    <div v-if="resetUser" class="modal-mask" @click.self="closeReset">
      <section class="modal-card">
        <div class="modal-title"><strong>修改 {{ resetUser.username }} 的密码</strong><button @click="closeReset">×</button></div>
        <div v-if="modalError" class="modal-notice error">{{ modalError }}</div>
        <label v-if="isSelf(resetUser)"><span>旧密码</span><input v-model="resetOldPassword" type="password" autocomplete="current-password"></label>
        <label><span>新密码</span><input v-model="resetPassword" type="password" autocomplete="new-password"></label>
        <label><span>确认新密码</span><input v-model="resetConfirmPassword" type="password" autocomplete="new-password"></label>
        <div class="modal-actions"><button @click="closeReset" :disabled="busy">取消</button><button class="primary" @click="submitReset" :disabled="busy">确认</button></div>
      </section>
    </div>
  </section>
</template>

<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { authClient } from '../api/domain'
import { normalizeItems, pickText } from '../shared/api-normalize'
import { formatChinaDateTime } from '../shared/time'
import { useAuthStore } from '../stores/auth'

const authStore = useAuthStore()
const loading = ref(false)
const busy = ref(false)
const error = ref('')
const modalError = ref('')
const message = ref('')
const users = ref([])
const showCreate = ref(false)
const resetUser = ref(null)
const resetOldPassword = ref('')
const resetPassword = ref('')
const resetConfirmPassword = ref('')
const createForm = ref({ username: '', password: '', confirmPassword: '', role: 'viewer' })

function formatTime(value) { return value ? formatChinaDateTime(value) : '-' }
function isSelf(user) { return String(user.id) === String(authStore.user?.id) }

function validatePassword(password, confirmPassword) {
  if (!password) return '请输入密码'
  if (Array.from(password).length < 8) return '密码至少 8 位'
  if (!/\p{Lu}/u.test(password)) return '密码必须包含至少 1 个大写字母'
  if (!/[\p{P}\p{S}]/u.test(password)) return '密码必须包含特殊字符，例如 ， 。 / ! @ #'
  if (password !== confirmPassword) return '两次输入的密码不一致'
  return ''
}

function notify(text) { message.value = text; error.value = '' }
function fail(text) { error.value = text; message.value = '' }
function failModal(text) { modalError.value = text; message.value = '' }
function openCreate() { showCreate.value = true; message.value = ''; error.value = ''; modalError.value = '' }
function closeCreate() { showCreate.value = false; modalError.value = ''; createForm.value = { username: '', password: '', confirmPassword: '', role: 'viewer' } }

async function loadUsers() {
  loading.value = true; error.value = ''
  try { users.value = normalizeItems(await authClient.users({ limit: 100 })).items } catch (e) { fail(e?.message || '无法读取账户列表') } finally { loading.value = false }
}

async function createUser() {
  if (!createForm.value.username) return failModal('请输入用户名')
  const validation = validatePassword(createForm.value.password, createForm.value.confirmPassword)
  if (validation) return failModal(validation)
  busy.value = true
  try {
    // /auth/register intentionally rejects caller-supplied roles; create as viewer,
    // then apply the selected role through the admin-only user update endpoint.
    const createdResponse = await authClient.createUser({ username: createForm.value.username, password: createForm.value.password })
    const created = unwrap(createdResponse)
    const role = createForm.value.role || 'viewer'
    if (role !== 'viewer' && created.id) {
      try {
        await authClient.updateUser(created.id, { role })
      } catch (roleError) {
        closeCreate()
        await loadUsers()
        fail(`账户已创建为只读，角色设置失败：${roleError?.message || role || '未知错误'}`)
        return
      }
    }
    closeCreate(); notify(`账户已新增${role !== 'viewer' ? `（${roleLabel(role)}）` : ''}`); await loadUsers()
  } catch (e) { failModal(e?.message || '新增账户失败') } finally { busy.value = false }
}

async function changeRole(user, role) {
  if (!user?.id || user.role === role || isSelf(user)) return
  busy.value = true
  try {
    await authClient.updateUser(user.id, { role })
    notify(`已将 ${user.username} 的角色调整为${roleLabel(role)}`)
    await loadUsers()
  } catch (e) { fail(e?.message || '角色修改失败') } finally { busy.value = false }
}

function roleLabel(value) { return ({ admin: '管理员', analyst: '分析员', viewer: '只读' })[value] || value }
function unwrap(response) { return response?.data?.data ?? response?.data ?? response ?? {} }

async function toggleActive(user) {
  if (isSelf(user)) return fail('不能停用当前登录账号')
  busy.value = true
  try {
    await authClient.updateUser(user.id, { is_active: user.is_active === false })
    notify(user.is_active === false ? '账户已启用' : '账户已停用'); await loadUsers()
  } catch (e) { fail(e?.message || '账户状态修改失败') } finally { busy.value = false }
}

function openReset(user) { resetUser.value = user; resetOldPassword.value = ''; resetPassword.value = ''; resetConfirmPassword.value = ''; message.value = ''; error.value = ''; modalError.value = '' }
function closeReset() { resetUser.value = null; modalError.value = ''; resetOldPassword.value = ''; resetPassword.value = ''; resetConfirmPassword.value = '' }

async function submitReset() {
  if (!resetUser.value) return
  if (isSelf(resetUser.value) && !resetOldPassword.value) return failModal('请输入旧密码')
  const validation = validatePassword(resetPassword.value, resetConfirmPassword.value)
  if (validation) return failModal(validation)
  busy.value = true
  try {
    if (isSelf(resetUser.value)) await authClient.changePassword({ old_password: resetOldPassword.value, new_password: resetPassword.value })
    else await authClient.resetPassword({ user_id: resetUser.value.id, new_password: resetPassword.value })
    closeReset(); notify('密码已修改')
  } catch (e) { failModal(e?.message || '修改密码失败') } finally { busy.value = false }
}

async function deleteUser(user) {
  if (isSelf(user)) return fail('不能删除当前登录账号')
  if (!window.confirm(`确认删除账户 ${user.username}？`)) return
  busy.value = true
  try { await authClient.deleteUser(user.id); notify('账户已删除'); await loadUsers() } catch (e) { fail(e?.message || '删除账户失败') } finally { busy.value = false }
}

let refreshTimer = null
onMounted(() => {
  loadUsers()
  refreshTimer = setInterval(loadUsers, 5000)
})
onUnmounted(() => clearInterval(refreshTimer))
</script>

<style scoped>
.account-page { display: grid; gap: 14px; min-width: 0; }
.account-header { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; padding-bottom: 14px; border-bottom: 1px solid var(--lyf-line); background-image: linear-gradient(90deg, var(--lyf-accent-line), transparent 46%); background-repeat: no-repeat; background-position: left bottom; background-size: 100% 1px; }
.account-header h2 { margin: 0; color: var(--lyf-ink); font-size: clamp(21px, 2vw, 27px); font-weight: 650; letter-spacing: -0.02em; }
.account-header p { margin: 6px 0 0; color: var(--lyf-ink-3); font-size: 12px; }

.table-panel, .panel { border: 1px solid var(--lyf-line); border-radius: var(--lyf-radius); background: linear-gradient(180deg, rgb(34 211 238 / 4%), transparent 34%), var(--lyf-surface); overflow: hidden; }
.panel-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 16px; border-bottom: 1px solid var(--lyf-line); background: var(--lyf-surface-2); color: var(--lyf-ink); font-size: 13px; font-weight: 650; }

.table-panel table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.table-panel th { height: 38px; padding: 0 12px; border-bottom: 1px solid var(--lyf-line-2); background: var(--lyf-surface-2); color: var(--lyf-ink-3); font-family: var(--lyf-font-data); font-size: 9.5px; font-weight: 600; letter-spacing: 0.08em; text-align: left; text-transform: uppercase; white-space: nowrap; }
.table-panel td { padding: 10px 12px; border-bottom: 1px solid var(--lyf-line); color: var(--lyf-ink-2); vertical-align: middle; }
.table-panel tr:last-child td { border-bottom: 0; }
.table-panel tr:hover { background: rgb(34 211 238 / 4%); }
.table-panel b { color: var(--lyf-ink); font-weight: 600; }
.empty-cell { padding: 26px 12px; color: var(--lyf-ink-3); text-align: center; }

.self-tag { display: inline-flex; margin-left: 6px; padding: 0 6px; border: 1px solid var(--lyf-accent-line); border-radius: 2px; background: var(--lyf-accent-soft); color: var(--lyf-accent); font-size: 9.5px; }
.state { display: inline-flex; align-items: center; gap: 5px; font-family: var(--lyf-font-data); font-size: 10.5px; }
.state.on, .on { color: var(--lyf-success); }
.state.off, .off { color: var(--lyf-ink-3); }
.ops { display: flex; flex-wrap: wrap; gap: 6px; }
.ops button, .primary { height: 26px; padding: 0 9px; border: 1px solid var(--lyf-line-2); border-radius: 2px; background: var(--lyf-surface); color: var(--lyf-ink-2); font: inherit; font-size: 11px; cursor: pointer; }
.ops button:hover { border-color: var(--lyf-accent); color: var(--lyf-accent); }
.ops button.danger, .danger { border-color: var(--lyf-critical-line); color: var(--lyf-critical); }
.primary { height: 32px; padding: 0 12px; border-color: var(--lyf-accent); background: var(--lyf-accent); color: #031018; font-size: 12px; font-weight: 650; }
.role-select { height: 28px; padding: 0 8px; border: 1px solid var(--lyf-line-2); border-radius: 2px; background: var(--lyf-surface); color: var(--lyf-ink); font: inherit; font-size: 11.5px; }

.notice, .error { padding: 10px 14px; border: 1px solid var(--lyf-line); border-left-width: 3px; border-radius: var(--lyf-radius-sm); background: var(--lyf-surface-2); color: var(--lyf-ink-2); font-size: 11.5px; }
.error { border-color: var(--lyf-critical-line); background: var(--lyf-critical-soft); color: var(--lyf-critical); }
.success { color: var(--lyf-success); }

.modal-mask { position: fixed; z-index: 120; inset: 0; display: grid; place-items: center; background: rgb(2 6 12 / 68%); backdrop-filter: blur(2px); }
.modal-card { width: min(520px, 92vw); border: 1px solid var(--lyf-line-2); border-radius: var(--lyf-radius); background: var(--lyf-surface); box-shadow: 0 30px 80px -40px #000; }
.modal-title { display: flex; align-items: center; justify-content: space-between; padding: 14px 18px; border-bottom: 1px solid var(--lyf-line); color: var(--lyf-ink); font-size: 14px; font-weight: 650; }
.modal-card form, .modal-card > div:not(.modal-title) { padding: 16px 18px; }
.modal-actions { display: flex; justify-content: flex-end; gap: 8px; padding: 12px 18px; border-top: 1px solid var(--lyf-line); }
.modal-notice { color: var(--lyf-medium); font-size: 11px; }
.modal-card label { display: grid; gap: 5px; margin-bottom: 10px; color: var(--lyf-ink-3); font-size: 11px; }
.modal-card input, .modal-card select { height: 34px; padding: 0 10px; border: 1px solid var(--lyf-line-2); border-radius: var(--lyf-radius-sm); background: var(--lyf-surface); color: var(--lyf-ink); font: inherit; font-size: 12.5px; }
.modal-card button { height: 32px; padding: 0 12px; border: 1px solid var(--lyf-line-2); border-radius: 2px; background: var(--lyf-surface); color: var(--lyf-ink-2); font: inherit; font-size: 12px; cursor: pointer; }
.modal-card button.primary { border-color: var(--lyf-accent); background: var(--lyf-accent); color: #031018; font-weight: 650; }

@media (max-width: 760px) {
  .account-header { align-items: flex-start; flex-direction: column; }
  .table-panel { overflow-x: auto; }
}
</style>
