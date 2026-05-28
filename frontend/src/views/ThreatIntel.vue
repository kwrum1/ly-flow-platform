<template>
  <div class="threat-intel">
    <el-card title="威胁情报">
      <div class="toolbar">
        <el-form
          :inline="true"
          :model="filters"
        >
          <el-form-item label="类型">
            <el-select
              v-model="filters.type"
              clearable
            >
              <el-option
                label="全部"
                value=""
              />
              <el-option
                label="IP"
                value="ip"
              />
              <el-option
                label="域名"
                value="domain"
              />
              <el-option
                label="文件"
                value="file"
              />
            </el-select>
          </el-form-item>
          <el-form-item label="威胁类型">
            <el-select
              v-model="filters.category"
              clearable
            >
              <el-option
                label="全部"
                value=""
              />
              <el-option
                label="挖矿"
                value="mining"
              />
              <el-option
                label="涉诈"
                value="fraud"
              />
              <el-option
                label="僵尸网络"
                value="botnet"
              />
              <el-option
                label="恶意软件"
                value="malware"
              />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button
              type="primary"
              @click="loadData"
            >
              搜索
            </el-button>
          </el-form-item>
        </el-form>
      </div>

      <el-table
        v-loading="loading"
        :data="intelList"
      >
        <el-table-column
          prop="indicator"
          label="威胁指标"
        />
        <el-table-column
          prop="type"
          label="类型"
          width="100"
        />
        <el-table-column
          prop="category"
          label="威胁类别"
          width="120"
        >
          <template #default="{ row }">
            <el-tag>{{ row.category }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="confidence"
          label="置信度"
          width="100"
        >
          <template #default="{ row }">
            <el-progress
              :percentage="row.confidence"
              :color="getConfidenceColor(row.confidence)"
            />
          </template>
        </el-table-column>
        <el-table-column
          prop="first_seen"
          label="首次发现"
          width="180"
        />
        <el-table-column
          prop="last_seen"
          label="最后发现"
          width="180"
        />
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../api'

const intelList = ref([])
const loading = ref(false)
const filters = ref({ type: '', category: '' })

const getConfidenceColor = (value) => {
  if (value >= 80) return '#67c23a'
  if (value >= 60) return '#e6a23c'
  return '#f56c6c'
}

const loadData = async () => {
  loading.value = true
  try {
    const data = await api.get('/threat-intel', { params: filters.value })
    intelList.value = data.data
  } catch (error) {
    console.error('Failed to load threat intel:', error)
  } finally {
    loading.value = false
  }
}

onMounted(loadData)
</script>

<style scoped>
.toolbar {
  margin-bottom: 16px;
}
</style>