<template>
  <div class="vulnerabilities">
    <el-card title="漏洞管理">
      <div class="toolbar">
        <el-form :inline="true" :model="filters">
          <el-form-item label="严重程度">
            <el-select v-model="filters.severity" clearable>
              <el-option label="全部" value="" />
              <el-option label="严重" value="critical" />
              <el-option label="高" value="high" />
              <el-option label="中" value="medium" />
              <el-option label="低" value="low" />
            </el-select>
          </el-form-item>
          <el-form-item label="状态">
            <el-select v-model="filters.status" clearable>
              <el-option label="全部" value="" />
              <el-option label="未修复" value="open" />
              <el-option label="已修复" value="fixed" />
              <el-option label="忽略" value="ignored" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="loadData">搜索</el-button>
          </el-form-item>
        </el-form>
      </div>

      <el-table :data="vulnerabilities" v-loading="loading">
        <el-table-column prop="cve_id" label="CVE ID" width="160" />
        <el-table-column prop="title" label="漏洞标题" />
        <el-table-column prop="severity" label="严重程度" width="100">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="cvss" label="CVSS" width="80" />
        <el-table-column prop="affected_assets" label="受影响资产" width="120" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="discovered_at" label="发现时间" width="180" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../api'

const vulnerabilities = ref([])
const loading = ref(false)
const filters = ref({ severity: '', status: '' })

const getSeverityType = (severity) => {
  const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' }
  return map[severity] || 'info'
}

const getStatusType = (status) => {
  const map = { open: 'danger', fixed: 'success', ignored: 'info' }
  return map[status] || 'info'
}

const loadData = async () => {
  loading.value = true
  try {
    const data = await api.get('/vulnerabilities', { params: filters.value })
    vulnerabilities.value = data.data
  } catch (error) {
    console.error('Failed to load vulnerabilities:', error)
  } finally {
    loading.value = false
  }
}

onMounted(loadData)
</script>