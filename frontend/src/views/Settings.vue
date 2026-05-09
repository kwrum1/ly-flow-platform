<template>
  <div class="settings">
    <el-card title="系统设置">
      <el-tabs v-model="activeTab">
        <el-tab-pane label="基本信息" name="basic">
          <el-form :model="basicSettings" label-width="120px">
            <el-form-item label="系统名称">
              <el-input v-model="basicSettings.name" />
            </el-form-item>
            <el-form-item label="系统描述">
              <el-input v-model="basicSettings.description" type="textarea" rows="3" />
            </el-form-item>
            <el-form-item label="时区">
              <el-select v-model="basicSettings.timezone">
                <el-option label="Asia/Shanghai" value="Asia/Shanghai" />
                <el-option label="UTC" value="UTC" />
              </el-select>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveBasicSettings">保存</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="告警设置" name="alerts">
          <el-form :model="alertSettings" label-width="120px">
            <el-form-item label="告警通知">
              <el-switch v-model="alertSettings.enabled" />
            </el-form-item>
            <el-form-item label="通知方式">
              <el-checkbox-group v-model="alertSettings.methods">
                <el-checkbox label="email">邮件</el-checkbox>
                <el-checkbox label="sms">短信</el-checkbox>
                <el-checkbox label="webhook">Webhook</el-checkbox>
              </el-checkbox-group>
            </el-form-item>
            <el-form-item label="告警阈值">
              <el-input-number v-model="alertSettings.threshold" :min="1" :max="100" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="saveAlertSettings">保存</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="数据源配置" name="datasource">
          <el-form :model="datasourceSettings" label-width="120px">
            <el-form-item label="数据源类型">
              <el-select v-model="datasourceSettings.type">
                <el-option label="Elasticsearch" value="elasticsearch" />
                <el-option label="MySQL" value="mysql" />
                <el-option label="ClickHouse" value="clickhouse" />
              </el-select>
            </el-form-item>
            <el-form-item label="连接地址">
              <el-input v-model="datasourceSettings.host" />
            </el-form-item>
            <el-form-item label="端口">
              <el-input-number v-model="datasourceSettings.port" :min="1" :max="65535" />
            </el-form-item>
            <el-form-item label="数据库名">
              <el-input v-model="datasourceSettings.database" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="testConnection">测试连接</el-button>
              <el-button type="primary" @click="saveDatasourceSettings" style="margin-left: 10px">保存</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <el-tab-pane label="用户管理" name="users">
          <el-table :data="users" v-loading="loadingUsers">
            <el-table-column prop="username" label="用户名" />
            <el-table-column prop="email" label="邮箱" />
            <el-table-column prop="role" label="角色" width="120" />
            <el-table-column prop="last_login" label="最后登录" width="180" />
            <el-table-column label="操作" width="150">
              <template #default="{ row }">
                <el-button size="small" @click="editUser(row)">编辑</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api'

const activeTab = ref('basic')
const loadingUsers = ref(false)
const users = ref([])

const basicSettings = ref({
  name: '流影安全态势感知平台',
  description: '网络安全态势感知与威胁检测系统',
  timezone: 'Asia/Shanghai'
})

const alertSettings = ref({
  enabled: true,
  methods: ['email', 'webhook'],
  threshold: 10
})

const datasourceSettings = ref({
  type: 'elasticsearch',
  host: 'localhost',
  port: 9200,
  database: 'flows'
})

const saveBasicSettings = async () => {
  try {
    await api.put('/settings/basic', basicSettings.value)
    ElMessage.success('保存成功')
  } catch (error) {
    ElMessage.error('保存失败')
  }
}

const saveAlertSettings = async () => {
  try {
    await api.put('/settings/alerts', alertSettings.value)
    ElMessage.success('保存成功')
  } catch (error) {
    ElMessage.error('保存失败')
  }
}

const testConnection = async () => {
  try {
    await api.post('/settings/datasource/test', datasourceSettings.value)
    ElMessage.success('连接成功')
  } catch (error) {
    ElMessage.error('连接失败')
  }
}

const saveDatasourceSettings = async () => {
  try {
    await api.put('/settings/datasource', datasourceSettings.value)
    ElMessage.success('保存成功')
  } catch (error) {
    ElMessage.error('保存失败')
  }
}

const loadUsers = async () => {
  loadingUsers.value = true
  try {
    const data = await api.get('/users')
    users.value = data.data
  } catch (error) {
    console.error('Failed to load users:', error)
  } finally {
    loadingUsers.value = false
  }
}

const editUser = (user) => {
  ElMessage.info(`编辑用户: ${user.username}`)
}

onMounted(() => {
  if (activeTab.value === 'users') {
    loadUsers()
  }
})
</script>