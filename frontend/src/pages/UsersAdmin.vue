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
        <thead><tr><th>用户名</th><th>状态</th><th>创建时间</th><th>最近登录</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-if="loading"><td colspan="5" class="empty-cell">正在读取账户数据</td></tr>
          <tr v-else-if="!users.length"><td colspan="5" class="empty-cell">暂无账户</td></tr>
          <tr v-for="user in users" :key="user.id || user.username">
            <td><strong>{{ pickText(user.username, '未命名账户') }}</strong><span v-if="isSelf(user)" class="self-tag">本机账号</span></td>
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
        <div class="modal-actions"><button @click="closeCreate" :disabled="busy">取消</button><button class="primary" @click="createUser" :disabled="busy">保存</button></div>
      </section>
    </div>

    <div v-if="resetUser" class="modal-mask" @click.self="closeReset">
      <section class="modal-card">
        <div class="modal-title"><strong>修改 {{ resetUser.username }} 的密码</strong><button @click="closeReset">×</button></div>
        <div v-if="modalError" class="modal-notice error">{{ modalError }}</div>
        <label><span>旧密码</span><input v-model="resetOldPassword" type="password" autocomplete="current-password"></label>
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
const createForm = ref({ username: '', password: '', confirmPassword: '' })

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
function closeCreate() { showCreate.value = false; modalError.value = ''; createForm.value = { username: '', password: '', confirmPassword: '' } }

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
    await authClient.createUser({ username: createForm.value.username, password: createForm.value.password, role: 'admin' })
    closeCreate(); notify('账户已新增'); await loadUsers()
  } catch (e) { failModal(e?.message || '新增账户失败') } finally { busy.value = false }
}

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
  if (!resetOldPassword.value) return failModal('请输入旧密码')
  const validation = validatePassword(resetPassword.value, resetConfirmPassword.value)
  if (validation) return failModal(validation)
  busy.value = true
  try {
    if (isSelf(resetUser.value)) await authClient.changePassword({ old_password: resetOldPassword.value, new_password: resetPassword.value })
    else await authClient.resetPassword({ user_id: resetUser.value.id, old_password: resetOldPassword.value, new_password: resetPassword.value })
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
.account-page{position:relative;height:100%;min-height:0;display:grid;grid-template-rows:auto auto minmax(0,1fr);gap:12px;padding:14px;color:var(--text-primary);box-sizing:border-box}.account-header,.panel,.modal-card{border:1px solid var(--border-color);border-radius:var(--card-radius);background:var(--bg-card);box-shadow:var(--shadow-card)}.account-header{height:44px;display:flex;align-items:center;padding:0 16px}.account-header h2{margin:0;color:var(--text-primary);font-size:16px}.panel{min-height:0;overflow:hidden}.table-panel{display:grid;grid-template-rows:44px minmax(0,1fr)}.panel-title{height:44px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;border-bottom:1px solid var(--border-light);background:rgba(4,12,24,.38)}.panel-title strong{color:var(--text-primary);font-size:14px}button{height:32px;padding:0 12px;border:1px solid var(--border-color);border-radius:var(--card-radius-sm);background:var(--bg-elevated);color:var(--text-secondary);cursor:pointer;font-size:12px;transition:border-color var(--transition-fast),color var(--transition-fast),background var(--transition-fast)}button:hover:not(:disabled){border-color:var(--border-glow);color:var(--text-primary);background:var(--bg-hover)}button:disabled{opacity:.45;cursor:not-allowed}.primary{border:0;background:linear-gradient(135deg,var(--primary-color),var(--risk-low));color:var(--text-inverse);font-weight:900;box-shadow:0 10px 28px rgba(56,189,248,.18)}input,select{height:32px;min-width:0;border:1px solid var(--border-color);border-radius:var(--card-radius-sm);background:var(--bg-secondary);color:var(--text-primary);padding:0 11px;font-size:12px;outline:0}input:focus,select:focus{border-color:var(--border-glow);box-shadow:0 0 0 3px var(--primary-glow)}table{width:100%;min-width:760px;border-collapse:separate;border-spacing:0;table-layout:fixed}th,td{padding:8px 12px;border-bottom:1px solid var(--border-light);text-align:left;vertical-align:middle}th{position:sticky;top:0;z-index:1;height:36px;color:var(--text-muted);background:var(--bg-card);font-size:11px;font-weight:900;letter-spacing:.08em;text-transform:uppercase}td{height:38px;color:var(--text-primary);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}td strong{color:var(--text-primary);font-size:12px}.empty-cell{height:96px;text-align:center;color:var(--text-secondary)}.self-tag{display:inline-flex;margin-left:8px;padding:3px 8px;border-radius:999px;color:var(--primary-light);background:rgba(125,211,252,.09);font-size:11px}.state{display:inline-flex;align-items:center;justify-content:center;min-width:44px;height:22px;border-radius:999px;font-size:11px;font-weight:900}.state.on{color:var(--risk-low);background:var(--risk-low-bg);border:1px solid var(--risk-low-border)}.state.off{color:var(--risk-critical);background:var(--risk-critical-bg);border:1px solid var(--risk-critical-border)}.ops{display:flex;gap:8px;align-items:center}.danger{color:#fecaca;border-color:var(--risk-critical-border);background:var(--risk-critical-bg)}.notice,.modal-notice{padding:10px 12px;border-radius:var(--card-radius-sm);font-size:12px}.notice.success{border:1px solid var(--risk-low-border);color:var(--risk-low);background:var(--risk-low-bg)}.notice.error,.modal-notice.error{border:1px solid var(--risk-critical-border);color:#fecaca;background:var(--risk-critical-bg)}.modal-mask{position:fixed;inset:0;z-index:40;display:flex;align-items:center;justify-content:center;padding:24px;background:rgba(2,8,23,.58)}.modal-card{width:min(520px,92vw);display:grid;gap:14px;padding:18px}.modal-title{display:flex;align-items:center;justify-content:space-between;padding-bottom:12px;border-bottom:1px solid var(--border-light)}.modal-title strong{font-size:16px}.modal-card label{display:grid;gap:6px;color:var(--text-secondary);font-size:12px}.modal-actions{display:flex;justify-content:flex-end;gap:10px}@media(max-width:900px){.account-page{padding:10px}.ops{flex-wrap:wrap}}
.account-page{color:#243149!important;background:#f3f6fa!important}.account-header,.panel,.modal-card{border-color:#dce3ec!important;background:#fff!important;box-shadow:0 3px 12px rgba(44,66,96,.07)!important}.panel-title{border-color:#e3e9f1!important;background:#f6f8fb!important}.panel-title strong,.account-header h2,td strong{color:#263247!important}input,select{border-color:#d7e0eb!important;background:#fff!important;color:#263247!important}.notice.error,.modal-notice.error{color:#b42318!important;background:#fff3f2!important;border-color:#f0b5b1!important}.primary{background:#1769d2!important;color:#fff!important;box-shadow:none!important}.danger{color:#b42318!important;background:#fff3f2!important}.self-tag{color:#1769ba!important;background:#edf6ff!important}.state.on{color:#178653!important;background:#edf9f2!important}.state.off{color:#b42318!important;background:#fff3f2!important}
</style>
