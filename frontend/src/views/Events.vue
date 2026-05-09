<template>
  <div class="events">
    <el-card title="事件列表">
      <div class="toolbar">
        <el-form :inline="true" :model="filters">
          <el-form-item label="级别">
            <el-select v-model="filters.severity" clearable>
              <el-option label="全部" value="" />
              <el-option label="严重" value="critical" />
              <el-option label="高" value="high" />
              <el-option label="中" value="medium" />
              <el-option label="低" value="low" />
            </el-select>
          </el-form-item>
          <el-form-item label="类型">
            <el-select v-model="filters.type" clearable>
              <el-option label="全部" value="" />
              <el-option label="DPI" value="dpi" />
              <el-option label="日志" value="log" />
              <el-option label="端点" value="endpoint" />
            </el-select>
          </el-form-item>
          <el-form-item label="时间范围">
            <el-date-picker v-model="filters.dateRange" type="daterange" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click="loadEvents">搜索</el-button>
          </el-form-item>
        </el-form>
      </div>

      <el-table :data="events" v-loading="loading" @row-click="handleRowClick">
        <el-table-column prop="timestamp" label="时间" width="180" />
        <el-table-column prop="severity" label="级别" width="100">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="type" label="类型" width="100" />
        <el-table-column prop="src_ip" label="源IP" width="140" />
        <el-table-column prop="dst_ip" label="目标IP" width="140" />
        <el-table-column prop="domain" label="域名" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'new' ? 'danger' : 'info'">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
      </el-table>

      <el-pagination
        v-model:current-page="pagination.page"
        v-model:page-size="pagination.size"
        :total="pagination.total"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next"
        @size-change="loadEvents"
        @current-change="loadEvents"
      />
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { eventsAPI } from '../api/events'

const router = useRouter()
const events = ref([])
const loading = ref(false)
const filters = ref({ severity: '', type: '', dateRange: null })
const pagination = ref({ page: 1, size: 20, total: 0 })

const getSeverityType = (severity) => {
  const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' }
  return map[severity] || 'info'
}

const handleRowClick = (row) => {
  router.push(`/events/${row.id}`)
}

const loadEvents = async () => {
  loading.value = true
  try {
    const params = {
      page: pagination.value.page,
      size: pagination.value.size,
      ...filters.value
    }
    const data = await eventsAPI.list(params)
    events.value = data.data
    pagination.value.total = data.total
  } catch (error) {
    console.error('Failed to load events:', error)
  } finally {
    loading.value = false
  }
}

onMounted(loadEvents)
</script>

<style scoped>
.toolbar {
  margin-bottom: 16px;
}
</style>
