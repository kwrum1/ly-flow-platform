<template>
  <div class="assets">
    <el-card title="资产列表">
      <el-table :data="assets" v-loading="loading">
        <el-table-column prop="hostname" label="主机名" width="180" />
        <el-table-column prop="ip" label="IP地址" width="140" />
        <el-table-column prop="os" label="操作系统" width="120" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="row.status === 'online' ? 'success' : 'info'">
              {{ row.status }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_seen" label="最后活跃" width="180" />
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button size="small" @click="showDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="detailVisible" title="资产详情" width="600px">
      <el-descriptions :column="2" border v-if="currentAsset">
        <el-descriptions-item label="主机名">{{ currentAsset.hostname }}</el-descriptions-item>
        <el-descriptions-item label="IP地址">{{ currentAsset.ip }}</el-descriptions-item>
        <el-descriptions-item label="操作系统">{{ currentAsset.os }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ currentAsset.status }}</el-descriptions-item>
        <el-descriptions-item label="Agent版本">{{ currentAsset.agent_version }}</el-descriptions-item>
        <el-descriptions-item label="首次活跃">{{ currentAsset.first_seen }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import api from '../api'

const assets = ref([])
const loading = ref(false)
const detailVisible = ref(false)
const currentAsset = ref(null)

const showDetail = (asset) => {
  currentAsset.value = asset
  detailVisible.value = true
}

onMounted(async () => {
  loading.value = true
  try {
    const data = await api.get('/assets')
    assets.value = data.data
  } catch (error) {
    console.error('Failed to load assets:', error)
  } finally {
    loading.value = false
  }
})
</script>
