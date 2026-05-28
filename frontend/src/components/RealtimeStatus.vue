<template>
  <span
    class="status-badge realtime-status"
    :class="stateClass"
    data-testid="realtime-status"
  >{{ stateLabel }}</span>
</template>

<script setup>
import { computed } from 'vue'
import { CONNECTION_STATUS } from '../realtime'

const props = defineProps({
  status: {
    type: String,
    default: CONNECTION_STATUS.IDLE,
  },
})

const statusMeta = {
  [CONNECTION_STATUS.OPEN]: { label: '实时连接正常', className: 'success' },
  [CONNECTION_STATUS.CONNECTING]: { label: '实时连接中', className: 'info' },
  [CONNECTION_STATUS.DEGRADED]: { label: '实时降级轮询', className: 'warning' },
  [CONNECTION_STATUS.ERROR]: { label: '实时连接异常', className: 'critical' },
  [CONNECTION_STATUS.CLOSED]: { label: '实时连接关闭', className: 'muted' },
  [CONNECTION_STATUS.IDLE]: { label: '实时连接空闲', className: 'muted' },
}

const currentMeta = computed(() => statusMeta[props.status] || statusMeta[CONNECTION_STATUS.IDLE])
const stateLabel = computed(() => currentMeta.value.label)
const stateClass = computed(() => currentMeta.value.className)
</script>

<style scoped>
.realtime-status {
  white-space: nowrap;
}

.realtime-status.warning {
  border-color: rgba(250, 204, 21, 0.45);
  background: rgba(250, 204, 21, 0.16);
  color: #fef08a;
}

.realtime-status.muted {
  border-color: var(--border-color);
  background: rgba(100, 116, 139, 0.2);
  color: var(--text-muted);
}
</style>
