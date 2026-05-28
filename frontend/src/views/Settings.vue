<template>
  <div class="settings-page">
    <div class="page-header">
      <h1>系统设置</h1>
    </div>

    <div class="settings-container">
      <div class="settings-tabs">
        <button
          :class="{ active: activeTab === 'users' }"
          @click="activeTab = 'users'"
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
          ><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle
            cx="9"
            cy="7"
            r="4"
          /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></svg>
          账号管理
        </button>
        <button
          :class="{ active: activeTab === 'rules' }"
          @click="activeTab = 'rules'"
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
          ><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
          规则管理
        </button>
        <button
          :class="{ active: activeTab === 'alerts' }"
          @click="activeTab = 'alerts'"
        >
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
          ><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /></svg>
          告警设置
        </button>
      </div>

      <div class="settings-content">
        <!-- 账号管理 -->
        <div
          v-if="activeTab === 'users'"
          class="settings-panel"
        >
          <div class="panel-header">
            <h3>账号管理</h3>
            <button
              class="btn-sm-primary"
              :disabled="!isAdmin"
              @click="showAddUserDialog = true"
            >
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                width="14"
                height="14"
              ><line
                x1="12"
                y1="5"
                x2="12"
                y2="19"
              /><line
                x1="5"
                y1="12"
                x2="19"
                y2="12"
              /></svg>
              添加用户
            </button>
          </div>

          <div
            v-if="usersLoading"
            class="empty-state"
          >
            <p>加载用户中...</p>
          </div>
          <div
            v-else-if="usersError"
            class="empty-state error"
          >
            <p>{{ usersError }}</p>
          </div>
          <div
            v-else-if="users.length > 0"
            class="users-table"
          >
            <div class="table-header">
              <div class="th">
                用户名
              </div>
              <div class="th">
                角色
              </div>
              <div class="th">
                状态
              </div>
              <div class="th">
                最后登录
              </div>
              <div class="th">
                创建时间
              </div>
              <div class="th">
                操作
              </div>
            </div>
            <div class="table-body">
              <div
                v-for="user in users"
                :key="user.id"
                class="table-row"
              >
                <div class="td name">
                  <div class="user-avatar">
                    {{ user.username.charAt(0).toUpperCase() }}
                  </div>
                  {{ user.username }}
                </div>
                <div class="td role">
                  <span
                    class="role-badge"
                    :class="user.role"
                  >{{ getRoleText(user.role) }}</span>
                </div>
                <div class="td status">
                  <span
                    class="status-badge"
                    :class="{ active: user.is_active, disabled: !user.is_active }"
                  >
                    {{ user.is_active ? '正常' : '禁用' }}
                  </span>
                </div>
                <div class="td last-login">
                  {{ formatTime(user.last_login_at) }}
                </div>
                <div class="td created">
                  {{ formatTime(user.created_at) }}
                </div>
                <div class="td actions">
                  <button
                    class="btn-link"
                    :disabled="!isAdmin"
                    @click="openPasswordDialog(user)"
                  >
                    修改密码
                  </button>
                  <button
                    class="btn-link"
                    :disabled="!isAdmin"
                    @click="openEditDialog(user)"
                  >
                    编辑
                  </button>
                  <button
                    v-if="currentUserId !== user.id"
                    class="btn-link danger"
                    :disabled="!isAdmin"
                    @click="confirmDelete(user)"
                  >
                    删除
                  </button>
                </div>
              </div>
            </div>
          </div>
          <div
            v-else
            class="empty-state"
          >
            <p>暂无用户数据</p>
          </div>
        </div>

        <!-- 规则管理 -->
        <div
          v-if="activeTab === 'rules'"
          class="settings-panel"
        >
          <div class="panel-header">
            <h3>规则管理</h3>
            <div class="header-actions">
              <button class="btn-secondary">
                导入规则
              </button>
              <button class="btn-secondary">
                导出规则
              </button>
              <button class="btn-sm-primary">
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  width="14"
                  height="14"
                ><line
                  x1="12"
                  y1="5"
                  x2="12"
                  y2="19"
                /><line
                  x1="5"
                  y1="12"
                  x2="19"
                  y2="12"
                /></svg>
                新增规则
              </button>
            </div>
          </div>

          <div class="stats-row">
            <div
              v-for="stat in ruleStats"
              :key="stat.key"
              class="stat-mini"
            >
              <span class="stat-value">{{ stat.value }}</span>
              <span class="stat-label">{{ stat.label }}</span>
            </div>
          </div>

          <div class="filter-tabs">
            <button
              v-for="f in ruleFilters"
              :key="f.key"
              :class="{ active: ruleFilter === f.key }"
              @click="ruleFilter = f.key"
            >
              {{ f.label }}
            </button>
          </div>

          <div class="rules-table">
            <div class="table-header">
              <div class="th">
                规则名称
              </div>
              <div class="th">
                类别
              </div>
              <div class="th">
                严重度
              </div>
              <div class="th">
                状态
              </div>
              <div class="th">
                来源
              </div>
              <div class="th">
                操作
              </div>
            </div>
            <div class="table-body">
              <div
                v-if="rulesLoading"
                class="table-state"
              >
                加载规则中...
              </div>
              <div
                v-else-if="rulesError"
                class="table-state error"
              >
                {{ rulesError }}
              </div>
              <div
                v-else-if="rules.length === 0"
                class="table-state"
              >
                暂无规则数据
              </div>
              <div
                v-for="rule in rules"
                :key="rule.id"
                class="table-row"
              >
                <div class="td name">
                  {{ rule.name }}
                </div>
                <div class="td category">
                  {{ rule.category }}
                </div>
                <div class="td">
                  <span
                    class="risk-badge"
                    :class="rule.level"
                  >{{ rule.levelText }}</span>
                </div>
                <div class="td">
                  <el-switch v-model="rule.enabled" />
                </div>
                <div class="td source">
                  {{ rule.source }}
                </div>
                <div class="td actions">
                  <el-button
                    link
                    type="primary"
                    size="small"
                  >
                    编辑
                  </el-button>
                  <el-button
                    link
                    type="primary"
                    size="small"
                  >
                    详情
                  </el-button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- 告警设置 -->
        <div
          v-if="activeTab === 'alerts'"
          class="settings-panel"
        >
          <div class="panel-header">
            <h3>告警设置</h3>
          </div>
          <div class="form-group switch-group">
            <div class="switch-info">
              <label>告警通知</label>
              <span class="desc">开启后，当检测到威胁事件时发送通知</span>
            </div>
            <label class="switch">
              <input
                v-model="alertSettings.enabled"
                type="checkbox"
              >
              <span class="slider" />
            </label>
          </div>
          <div class="form-group">
            <label>通知方式</label>
            <div class="checkbox-group">
              <label class="checkbox-item"><input
                v-model="alertSettings.methods"
                type="checkbox"
                value="email"
              ><span>邮件</span></label>
              <label class="checkbox-item"><input
                v-model="alertSettings.methods"
                type="checkbox"
                value="webhook"
              ><span>Webhook</span></label>
              <label class="checkbox-item"><input
                v-model="alertSettings.methods"
                type="checkbox"
                value="wecom"
              ><span>企业微信</span></label>
              <label class="checkbox-item"><input
                v-model="alertSettings.methods"
                type="checkbox"
                value="dingtalk"
              ><span>钉钉</span></label>
              <label class="checkbox-item"><input
                v-model="alertSettings.methods"
                type="checkbox"
                value="feishu"
              ><span>飞书</span></label>
            </div>
          </div>
          <div class="form-group">
            <label>告警级别过滤</label>
            <div class="checkbox-group">
              <label class="checkbox-item"><input
                type="checkbox"
                checked
              ><span>严重</span></label>
              <label class="checkbox-item"><input
                type="checkbox"
                checked
              ><span>高危</span></label>
              <label class="checkbox-item"><input
                type="checkbox"
                checked
              ><span>中危</span></label>
              <label class="checkbox-item"><input type="checkbox"><span>低危</span></label>
            </div>
          </div>
          <div class="form-actions">
            <button class="btn-primary">
              保存设置
            </button>
          </div>
        </div>

      </div>

      <!-- 添加用户对话框 -->
      <div
        v-if="showAddUserDialog"
        class="modal-overlay"
        @click.self="showAddUserDialog = false"
      >
        <div class="modal-content">
          <div class="modal-header">
            <h3>添加用户</h3>
            <button
              class="modal-close"
              @click="showAddUserDialog = false"
            >
              &times;
            </button>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <label>用户名</label>
              <input
                v-model="addUserForm.username"
                type="text"
                placeholder="请输入用户名"
              >
            </div>
            <div class="form-group">
              <label>设置密码</label>
              <input
                v-model="addUserForm.password"
                type="password"
                placeholder="请输入密码"
              >
            </div>
            <div class="form-group">
              <label>角色</label>
              <select v-model="addUserForm.role">
                <option value="admin">
                  管理员
                </option>
              </select>
            </div>
            <p class="form-hint">
              密码要求: 至少8位, 包含大写字母、小写字母、数字、特殊字符
            </p>
          </div>
          <div class="modal-footer">
            <button
              class="btn-secondary"
              @click="showAddUserDialog = false"
            >
              取消
            </button>
            <button
              class="btn-primary"
              :disabled="addingUser || !isAdmin"
              @click="addUser"
            >
              {{ addingUser ? '添加中...' : '添加' }}
            </button>
          </div>
        </div>
      </div>

      <!-- 编辑用户对话框 -->
      <div
        v-if="showEditDialog"
        class="modal-overlay"
        @click.self="showEditDialog = false"
      >
        <div class="modal-content">
          <div class="modal-header">
            <h3>编辑用户 - {{ editUserForm.username }}</h3>
            <button
              class="modal-close"
              @click="showEditDialog = false"
            >
              &times;
            </button>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <label>角色</label>
              <select v-model="editUserForm.role">
                <option value="admin">
                  管理员
                </option>
              </select>
            </div>
            <div class="form-group">
              <label>状态</label>
              <select v-model="editUserForm.isActive">
                <option :value="true">
                  正常
                </option>
                <option :value="false">
                  禁用
                </option>
              </select>
            </div>
          </div>
          <div class="modal-footer">
            <button
              class="btn-secondary"
              @click="showEditDialog = false"
            >
              取消
            </button>
            <button
              class="btn-primary"
              :disabled="updatingUser || !isAdmin"
              @click="updateUser"
            >
              {{ updatingUser ? '保存中...' : '保存' }}
            </button>
          </div>
        </div>
      </div>

      <!-- 修改密码对话框 -->
      <div
        v-if="showPasswordDialog"
        class="modal-overlay"
        @click.self="showPasswordDialog = false"
      >
        <div class="modal-content">
          <div class="modal-header">
            <h3>修改密码 - {{ passwordUserForm.username }}</h3>
            <button
              class="modal-close"
              @click="showPasswordDialog = false"
            >
              &times;
            </button>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <label>新密码</label>
              <input
                v-model="passwordUserForm.newPassword"
                type="password"
                placeholder="请输入新密码"
              >
            </div>
            <div class="form-group">
              <label>确认密码</label>
              <input
                v-model="passwordUserForm.confirmPassword"
                type="password"
                placeholder="请确认新密码"
              >
            </div>
            <p class="form-hint">
              密码要求: 至少8位, 包含大写字母、小写字母、数字、特殊字符
            </p>
          </div>
          <div class="modal-footer">
            <button
              class="btn-secondary"
              @click="showPasswordDialog = false"
            >
              取消
            </button>
            <button
              class="btn-primary"
              :disabled="changingPassword || !isAdmin"
              @click="changeUserPassword"
            >
              {{ changingPassword ? '修改中...' : '修改' }}
            </button>
          </div>
        </div>
      </div>

      <!-- 删除确认对话框 -->
      <div
        v-if="showDeleteDialog"
        class="modal-overlay"
        @click.self="showDeleteDialog = false"
      >
        <div class="modal-content modal-small">
          <div class="modal-header">
            <h3>确认删除</h3>
            <button
              class="modal-close"
              @click="showDeleteDialog = false"
            >
              &times;
            </button>
          </div>
          <div class="modal-body">
            <p>确定要删除用户 <strong>{{ deleteTarget?.username }}</strong> 吗？此操作不可恢复。</p>
          </div>
          <div class="modal-footer">
            <button
              class="btn-secondary"
              @click="showDeleteDialog = false"
            >
              取消
            </button>
            <button
              class="btn-danger"
              :disabled="deletingUser || !isAdmin"
              @click="deleteUser"
            >
              {{ deletingUser ? '删除中...' : '删除' }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, onMounted, watch } from 'vue'
import api from '../api'
const activeTab = ref('users')
const users = ref([])
const usersLoading = ref(false)
const usersError = ref('')

const currentUserId = ref(null)
const currentUserRole = ref('')
const isAdmin = computed(() => currentUserRole.value === 'admin')

const showAddUserDialog = ref(false)
const showEditDialog = ref(false)
const showPasswordDialog = ref(false)
const showDeleteDialog = ref(false)

const addingUser = ref(false)
const updatingUser = ref(false)
const changingPassword = ref(false)
const deletingUser = ref(false)

const addUserForm = ref({ username: '', password: '', role: 'admin' })
const editUserForm = ref({ id: null, username: '', role: 'admin', isActive: true })
const passwordUserForm = ref({ id: null, username: '', newPassword: '', confirmPassword: '' })
const deleteTarget = ref(null)

const basicSettings = ref({
  name: '流影安全态势感知平台',
  description: '新一代网络安全态势感知与安全运营平台',
  retention: 30
})

const alertSettings = ref({ enabled: true, methods: ['email', 'webhook'] })
const securitySettings = ref({ twoFA: false, sessionTimeout: true, passwordStrength: 'high' })

const ruleStats = ref([
  { key: 'total', label: '规则总数', value: 0 },
  { key: 'enabled', label: '已启用', value: 0 },
  { key: 'custom', label: '自定义', value: 0 }
])
const ruleFilters = [
  { key: 'all', label: '全部' },
  { key: 'enabled', label: '已启用' },
  { key: 'critical', label: '严重' },
  { key: 'high', label: '高危' }
]
const ruleFilter = ref('all')
const allRules = ref([])
const rulesLoading = ref(false)
const rulesError = ref('')
const rules = computed(() => {
  if (ruleFilter.value === 'enabled') return allRules.value.filter(rule => rule.enabled)
  if (['critical', 'high'].includes(ruleFilter.value)) return allRules.value.filter(rule => rule.level === ruleFilter.value)
  return allRules.value
})

const unwrap = (payload) => payload?.data ?? payload ?? {}
const requestJSON = async (path, options = {}) => {
  const method = String(options.method || 'GET').toUpperCase()
  const body = typeof options.body === 'string' ? JSON.parse(options.body) : options.body

  if (method === 'GET') return api.get(path)
  if (method === 'POST') return api.post(path, body || {})
  if (method === 'PUT') return api.put(path, body || {})
  if (method === 'DELETE') return api.delete(path, body ? { data: body } : undefined)

  throw new Error(`Unsupported method: ${method}`)
}
const getUserInfo = () => {
  const id = localStorage.getItem('user_id')
  const role = localStorage.getItem('role')
  if (id) currentUserId.value = parseInt(id)
  if (role) currentUserRole.value = role
}

const ensureAdminAction = () => {
  if (isAdmin.value) return true
  usersError.value = 'Permission denied: 当前账号无管理员权限，无法执行该操作。'
  return false
}

const loadUsers = async () => {
  usersLoading.value = true
  usersError.value = ''
  try {
    const body = unwrap(await requestJSON('/auth/users'))
    users.value = Array.isArray(body) ? body : (body.items || [])
    if (users.value.length > 0 && !currentUserId.value) {
      currentUserId.value = users.value[0].id
    }
  } catch (err) {
    usersError.value = err.message || '用户加载失败'
    users.value = []
  } finally {
    usersLoading.value = false
  }
}

const validatePassword = (pwd) => {
  if (pwd.length < 8) return '密码至少8位'
  if (!/[A-Z]/.test(pwd)) return '密码必须包含大写字母'
  if (!/[a-z]/.test(pwd)) return '密码必须包含小写字母'
  if (!/[0-9]/.test(pwd)) return '密码必须包含数字'
  if (!/[!@#$%^&*()]/.test(pwd)) return '密码必须包含特殊字符(!@#$%^&*)'
  return null
}

const addUser = async () => {
  if (!ensureAdminAction()) return
  const err = validatePassword(addUserForm.value.password)
  if (err) { alert(err); return }
  if (!addUserForm.value.username) { alert('请输入用户名'); return }

  addingUser.value = true
  try {
    await requestJSON('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        username: addUserForm.value.username,
        password: addUserForm.value.password,
        role: addUserForm.value.role
      })
    })
    showAddUserDialog.value = false
    addUserForm.value = { username: '', password: '', role: 'admin' }
    await loadUsers()
  } catch (e) {
    alert(e?.message || 'Operation failed: 添加失败')
  } finally {
    addingUser.value = false
  }
}

const openEditDialog = (user) => {
  if (!ensureAdminAction()) return
  editUserForm.value = { id: user.id, username: user.username, role: user.role, isActive: user.is_active }
  showEditDialog.value = true
}

const updateUser = async () => {
  if (!ensureAdminAction()) return
  updatingUser.value = true
  try {
    await requestJSON(`/auth/users/${editUserForm.value.id}`, {
      method: 'PUT',
      body: JSON.stringify({ role: editUserForm.value.role, is_active: editUserForm.value.isActive })
    })
    showEditDialog.value = false
    await loadUsers()
  } catch (e) {
    alert(e?.message || 'Operation failed: 更新失败')
  } finally {
    updatingUser.value = false
  }
}

const openPasswordDialog = (user) => {
  if (!ensureAdminAction()) return
  passwordUserForm.value = { id: user.id, username: user.username, newPassword: '', confirmPassword: '' }
  showPasswordDialog.value = true
}

const changeUserPassword = async () => {
  if (!ensureAdminAction()) return
  if (passwordUserForm.value.newPassword !== passwordUserForm.value.confirmPassword) {
    alert('两次输入的密码不一致')
    return
  }
  const err = validatePassword(passwordUserForm.value.newPassword)
  if (err) { alert(err); return }

  changingPassword.value = true
  try {
    await requestJSON('/auth/users/password', {
      method: 'PUT',
      body: JSON.stringify({ user_id: passwordUserForm.value.id, new_password: passwordUserForm.value.newPassword })
    })
    showPasswordDialog.value = false
    alert('密码修改成功')
  } catch (e) {
    alert(e?.message || 'Operation failed: 修改失败')
  } finally {
    changingPassword.value = false
  }
}

const confirmDelete = (user) => {
  if (!ensureAdminAction()) return
  deleteTarget.value = user
  showDeleteDialog.value = true
}

const deleteUser = async () => {
  if (!ensureAdminAction()) return
  if (!deleteTarget.value) return
  deletingUser.value = true
  try {
    await requestJSON(`/auth/users/${deleteTarget.value.id}`, {
      method: 'DELETE'
    })
    showDeleteDialog.value = false
    deleteTarget.value = null
    await loadUsers()
  } catch (e) {
    alert(e?.message || 'Operation failed: 删除失败')
  } finally {
    deletingUser.value = false
  }
}

const getRoleText = (role) => {
  const map = { admin: '管理员' }
  return map[role] || role
}

const formatTime = (time) => {
  if (!time) return '-'
  const d = new Date(time)
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`
}

const severityText = (level) => ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[level] || '低危')
const normalizeRule = (rule, index) => {
  const level = String(rule.severity || rule.level || 'low').toLowerCase()
  return {
    id: rule.id || index,
    name: rule.name || rule.rule_name || '-',
    category: rule.category || rule.language || rule.action || '-',
    level,
    levelText: severityText(level),
    enabled: Boolean(rule.enabled),
    source: rule.source || rule.module || 'RASP'
  }
}
const refreshRuleStats = (apiStats = {}) => {
  ruleStats.value = [
    { key: 'total', label: '规则总数', value: apiStats.totalRules ?? allRules.value.length },
    { key: 'enabled', label: '已启用', value: apiStats.enabledRules ?? allRules.value.filter(rule => rule.enabled).length },
    { key: 'custom', label: '自定义', value: apiStats.customRules ?? allRules.value.length }
  ]
}
const loadRules = async () => {
  rulesLoading.value = true
  rulesError.value = ''
  try {
    const [rulesBody, statsBody] = await Promise.all([
      requestJSON('/rasp/rules'),
      requestJSON('/rules/stats')
    ])
    const listBody = unwrap(rulesBody)
    const items = Array.isArray(listBody) ? listBody : (listBody.items || listBody.rules || [])
    allRules.value = items.map(normalizeRule)
    refreshRuleStats(unwrap(statsBody))
  } catch (err) {
    rulesError.value = err.message || '规则加载失败'
    allRules.value = []
    refreshRuleStats()
  } finally {
    rulesLoading.value = false
  }
}

onMounted(() => {
  getUserInfo()
  const params = new URLSearchParams(window.location.search)
  if (params.get('tab') === 'users') {
    activeTab.value = 'users'
  }
  if (activeTab.value === 'users') {
    loadUsers()
  }
  if (activeTab.value === 'rules') {
    loadRules()
  }
})

watch(activeTab, (newTab) => {
  if (newTab === 'users') {
    loadUsers()
  }
  if (newTab === 'rules') {
    loadRules()
  }
})
</script>

<style scoped>
.settings-page { min-height: 100%; }
.page-header { margin-bottom: 24px; }
.page-header h1 { font-size: 24px; font-weight: 700; color: var(--text-primary); }
.settings-container { display: flex; gap: 24px; }
.settings-tabs { width: 200px; flex-shrink: 0; display: flex; flex-direction: column; gap: 4px; }
.settings-tabs button { display: flex; align-items: center; gap: 10px; width: 100%; padding: 12px 16px; background: transparent; border: none; border-radius: 8px; color: var(--text-secondary); font-size: 14px; cursor: pointer; transition: all var(--transition-fast); text-align: left; }
.settings-tabs button:hover { background: var(--bg-hover); color: var(--text-primary); }
.settings-tabs button.active { background: var(--sidebar-item-active); color: var(--primary-color); }
.settings-tabs button svg { width: 18px; height: 18px; }
.settings-content { flex: 1; }
.settings-panel { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; padding: 24px; }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border-color); }
.panel-header h3 { font-size: 16px; font-weight: 600; color: var(--text-primary); }
.panel-header .header-actions { display: flex; gap: 8px; }
.form-group { margin-bottom: 20px; }
.form-group label { display: block; font-size: 13px; font-weight: 500; color: var(--text-secondary); margin-bottom: 8px; }
.form-group input[type="text"],
.form-group input[type="number"],
.form-group input[type="password"],
.form-group textarea,
.form-group select { width: 100%; max-width: 400px; padding: 10px 14px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-primary); font-size: 14px; box-sizing: border-box; }
.form-group textarea { resize: vertical; }
.switch-group { display: flex; align-items: center; justify-content: space-between; max-width: 400px; margin-bottom: 20px; }
.switch-info label { display: block; margin-bottom: 0; }
.switch-info .desc { font-size: 12px; color: var(--text-muted); }
.switch { position: relative; width: 44px; height: 24px; }
.switch input { opacity: 0; width: 0; height: 0; }
.switch .slider { position: absolute; cursor: pointer; inset: 0; background: var(--bg-secondary); border-radius: 24px; transition: all var(--transition-fast); }
.switch .slider::before { content: ''; position: absolute; width: 18px; height: 18px; left: 3px; top: 3px; background: white; border-radius: 50%; transition: all var(--transition-fast); }
.switch input:checked + .slider { background: var(--primary-color); }
.switch input:checked + .slider::before { transform: translateX(20px); }
.checkbox-group { display: flex; flex-wrap: wrap; gap: 16px; }
.checkbox-item { display: flex; align-items: center; gap: 6px; cursor: pointer; }
.checkbox-item input { width: 16px; height: 16px; accent-color: var(--primary-color); }
.checkbox-item span { font-size: 13px; color: var(--text-primary); }
.form-actions { display: flex; gap: 12px; margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--border-color); }
.btn-primary { padding: 10px 20px; background: var(--primary-color); border: none; border-radius: 6px; color: white; font-size: 14px; font-weight: 500; cursor: pointer; }
.btn-primary:hover { background: var(--primary-light); }
.btn-secondary { padding: 10px 16px; background: transparent; border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-secondary); font-size: 13px; cursor: pointer; }
.btn-secondary:hover { border-color: var(--text-muted); color: var(--text-primary); }
.btn-sm-primary { display: flex; align-items: center; gap: 6px; padding: 8px 14px; background: var(--primary-color); border: none; border-radius: 6px; color: white; font-size: 13px; cursor: pointer; }
.btn-sm-primary:hover { background: var(--primary-light); }
.btn-sm-primary svg { width: 14px; height: 14px; }
.users-table { margin-top: 16px; }
.table-header { display: flex; background: var(--bg-secondary); border-radius: 8px 8px 0 0; }
.th { flex: 1; padding: 12px 16px; font-size: 12px; font-weight: 600; color: var(--text-secondary); }
.table-body { border: 1px solid var(--border-color); border-top: none; border-radius: 0 0 8px 8px; }
.table-state { padding: 32px; text-align: center; color: var(--text-muted); }
.table-state.error { color: var(--risk-critical); }
.table-row { display: flex; align-items: center; padding: 12px 16px; border-bottom: 1px solid var(--border-color); }
.table-row:last-child { border-bottom: none; }
.table-row:hover { background: var(--bg-hover); }
.td { flex: 1; font-size: 13px; color: var(--text-primary); display: flex; align-items: center; gap: 8px; }
.td.email { color: var(--text-secondary); }
.td.last-login { color: var(--text-secondary); font-size: 12px; }
.td.actions { gap: 4px; }
.user-avatar { width: 28px; height: 28px; background: linear-gradient(135deg, var(--primary-color), var(--primary-light)); border-radius: 6px; display: flex; align-items: center; justify-content: center; color: white; font-size: 12px; font-weight: 600; }
.role-badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; }
.role-badge.admin { background: rgba(139, 92, 246, 0.15); color: #8b5cf6; }
.role-badge.operator { background: rgba(24, 144, 255, 0.15); color: var(--primary-color); }
.role-badge.analyst { background: rgba(82, 196, 26, 0.15); color: var(--risk-low); }
.role-badge.viewer { background: var(--bg-hover); color: var(--text-muted); }
.status-badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; }
.status-badge.active { background: var(--risk-low-bg); color: var(--risk-low); }
.status-badge.disabled { background: var(--bg-hover); color: var(--text-muted); }
.stats-row { display: flex; gap: 12px; margin-bottom: 16px; }
.stat-mini { flex: 1; padding: 12px 16px; background: var(--bg-secondary); border-radius: 8px; text-align: center; }
.stat-mini .stat-value { display: block; font-size: 20px; font-weight: 700; color: var(--text-primary); }
.stat-mini .stat-label { font-size: 12px; color: var(--text-secondary); }
.filter-tabs { display: flex; gap: 8px; margin-bottom: 16px; }
.filter-tabs button { padding: 6px 12px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 6px; color: var(--text-secondary); font-size: 12px; cursor: pointer; }
.filter-tabs button.active { background: var(--primary-color); border-color: var(--primary-color); color: white; }
.rules-table { border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; }
.risk-badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; }
.risk-badge.critical { background: var(--risk-critical-bg); color: var(--risk-critical); }
.risk-badge.high { background: var(--risk-high-bg); color: var(--risk-high); }
.risk-badge.medium { background: var(--risk-medium-bg); color: var(--risk-medium); }

/* Modal styles */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 1000; }
.modal-content { background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 12px; width: 420px; max-width: 90vw; }
.modal-content.modal-small { width: 360px; }
.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid var(--border-color); }
.modal-header h3 { font-size: 16px; font-weight: 600; }
.modal-close { background: none; border: none; font-size: 24px; color: var(--text-muted); cursor: pointer; }
.modal-close:hover { color: var(--text-primary); }
.modal-body { padding: 20px; }
.modal-footer { display: flex; justify-content: flex-end; gap: 12px; padding: 16px 20px; border-top: 1px solid var(--border-color); }
.form-hint { font-size: 12px; color: var(--text-muted); margin-top: 8px; }
.btn-link { background: none; border: none; color: var(--primary-color); font-size: 13px; cursor: pointer; padding: 4px 8px; }
.btn-link:hover { text-decoration: underline; }
.btn-link.danger { color: var(--risk-high); }
.btn-danger { padding: 10px 20px; background: var(--risk-high); border: none; border-radius: 6px; color: white; font-size: 14px; cursor: pointer; }
.btn-danger:hover { background: #dc2626; }
.empty-state { text-align: center; padding: 40px; color: var(--text-muted); }
.empty-state.error { color: var(--risk-critical); }
.td.created { color: var(--text-secondary); font-size: 12px; }
</style>