<template>
  <div class="dashboard">
    <el-row :gutter="20">
      <el-col :span="6" v-for="stat in stats" :key="stat.key">
        <el-card shadow="hover">
          <div class="stat-card">
            <div class="stat-value">{{ stat.value }}</div>
            <div class="stat-label">{{ stat.label }}</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-row :gutter="20" style="margin-top: 20px">
      <el-col :span="12">
        <el-card title="告警趋势">
          <div ref="trendChartRef" style="height: 300px"></div>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card title="告警分布">
          <div ref="pieChartRef" style="height: 300px"></div>
        </el-card>
      </el-col>
    </el-row>

    <el-card style="margin-top: 20px" title="最新告警">
      <el-table :data="recentAlerts">
        <el-table-column prop="timestamp" label="时间" width="180" />
        <el-table-column prop="severity" label="级别" width="100">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="category" label="类别" width="120" />
        <el-table-column prop="src_ip" label="源IP" width="140" />
        <el-table-column prop="domain" label="域名" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'
import { statsAPI } from '../api/events'

const stats = ref([])
const recentAlerts = ref([])
const trendChartRef = ref(null)
const pieChartRef = ref(null)
let trendChart = null
let pieChart = null

const getSeverityType = (severity) => {
  const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' }
  return map[severity] || 'info'
}

const initCharts = () => {
  trendChart = echarts.init(trendChartRef.value)
  trendChart.setOption({
    title: { text: '告警趋势' },
    xAxis: { type: 'category', data: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] },
    yAxis: { type: 'value' },
    series: [{ data: [820, 932, 901, 934, 1290, 1330, 1320], type: 'line', smooth: true }]
  })

  pieChart = echarts.init(pieChartRef.value)
  pieChart.setOption({
    title: { text: '告警分布' },
    series: [{
      type: 'pie',
      radius: '50%',
      data: [
        { value: 1048, name: '挖矿' },
        { value: 735, name: '涉诈' },
        { value: 580, name: 'DGA' },
        { value: 484, name: 'DNS Tunnel' },
        { value: 300, name: '其他' }
      ]
    }]
  })
}

onMounted(async () => {
  try {
    const data = await statsAPI.dashboard()
    stats.value = data.stats
    recentAlerts.value = data.recent_alerts
  } catch (error) {
    console.error('Failed to load dashboard:', error)
  }
  initCharts()
})

onUnmounted(() => {
  trendChart?.dispose()
  pieChart?.dispose()
})
</script>

<style scoped>
.stat-card {
  text-align: center;
}
.stat-value {
  font-size: 32px;
  font-weight: bold;
  color: #409eff;
}
.stat-label {
  margin-top: 8px;
  color: #666;
}
</style>
