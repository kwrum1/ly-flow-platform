<template>
  <div class="event-detail">
    <el-card title="事件详情">
      <el-descriptions :column="2" border v-if="event">
        <el-descriptions-item label="事件ID">{{ event.id }}</el-descriptions-item>
        <el-descriptions-item label="时间">{{ event.timestamp }}</el-descriptions-item>
        <el-descriptions-item label="级别">
          <el-tag :type="getSeverityType(event.severity)">{{ event.severity }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="类型">{{ event.type }}</el-descriptions-item>
        <el-descriptions-item label="源IP">{{ event.src_ip }}</el-descriptions-item>
        <el-descriptions-item label="目标IP">{{ event.dst_ip }}</el-descriptions-item>
        <el-descriptions-item label="域名">{{ event.domain }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ event.status }}</el-descriptions-item>
      </el-descriptions>

      <el-tabs style="margin-top: 20px">
        <el-tab-pane label="详情信息">
          <pre>{{ event?.detail }}</pre>
        </el-tab-pane>
        <el-tab-pane label="相关事件">
          <el-table :data="relatedEvents">
            <el-table-column prop="timestamp" label="时间" width="180" />
            <el-table-column prop="type" label="类型" width="100" />
            <el-table-column prop="src_ip" label="源IP" width="140" />
            <el-table-column prop="domain" label="域名" />
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { eventsAPI } from '../api/events'

const route = useRoute()
const event = ref(null)
const relatedEvents = ref([])

const getSeverityType = (severity) => {
  const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' }
  return map[severity] || 'info'
}

onMounted(async () => {
  try {
    const id = route.params.id
    const data = await eventsAPI.detail(id)
    event.value = data.event
    relatedEvents.value = data.related || []
  } catch (error) {
    console.error('Failed to load event:', error)
  }
})
</script>

<style scoped>
.event-detail {
  padding: 20px;
}
pre {
  background: #f5f5f5;
  padding: 16px;
  border-radius: 4px;
  overflow: auto;
}
</style>