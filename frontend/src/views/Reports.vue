<template>
  <div class="reports">
    <el-card title="报告中心">
      <div class="toolbar">
        <el-form :inline="true">
          <el-form-item>
            <el-button
              type="primary"
              @click="generateReport"
            >
              生成报告
            </el-button>
          </el-form-item>
        </el-form>
      </div>

      <el-table
        v-loading="loading"
        :data="reports"
      >
        <el-table-column
          prop="name"
          label="报告名称"
        />
        <el-table-column
          prop="type"
          label="类型"
          width="120"
        />
        <el-table-column
          prop="period"
          label="时间范围"
          width="180"
        />
        <el-table-column
          prop="created_at"
          label="创建时间"
          width="180"
        />
        <el-table-column
          prop="size"
          label="大小"
          width="100"
        />
        <el-table-column
          label="操作"
          width="150"
        >
          <template #default="{ row }">
            <el-button
              size="small"
              @click="downloadReport(row)"
            >
              下载
            </el-button>
            <el-button
              size="small"
              type="danger"
              @click="deleteReport(row)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog
      v-model="generateVisible"
      title="生成报告"
      width="500px"
    >
      <el-form
        :model="reportForm"
        label-width="100px"
      >
        <el-form-item label="报告名称">
          <el-input v-model="reportForm.name" />
        </el-form-item>
        <el-form-item label="报告类型">
          <el-select v-model="reportForm.type">
            <el-option
              label="安全日报"
              value="daily"
            />
            <el-option
              label="安全周报"
              value="weekly"
            />
            <el-option
              label="安全月报"
              value="monthly"
            />
            <el-option
              label="威胁分析报告"
              value="threat"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="时间范围">
          <el-date-picker
            v-model="reportForm.dateRange"
            type="daterange"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="generateVisible = false">
          取消
        </el-button>
        <el-button
          type="primary"
          @click="handleGenerate"
        >
          生成
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api'

const reports = ref([])
const loading = ref(false)
const generateVisible = ref(false)
const reportForm = ref({
  name: '',
  type: 'daily',
  dateRange: null
})

const loadData = async () => {
  loading.value = true
  try {
    const data = await api.get('/reports')
    reports.value = data.data
  } catch (error) {
    console.error('Failed to load reports:', error)
  } finally {
    loading.value = false
  }
}

const generateReport = () => {
  generateVisible.value = true
}

const handleGenerate = async () => {
  try {
    await api.post('/reports/generate', reportForm.value)
    ElMessage.success('报告生成中...')
    generateVisible.value = false
    loadData()
  } catch (error) {
    ElMessage.error('生成失败')
  }
}

const downloadReport = (row) => {
  window.open(`/api/v1/reports/${row.id}/download`, '_blank')
}

const deleteReport = async (row) => {
  try {
    await api.delete(`/reports/${row.id}`)
    ElMessage.success('删除成功')
    loadData()
  } catch (error) {
    ElMessage.error('删除失败')
  }
}

onMounted(loadData)
</script>