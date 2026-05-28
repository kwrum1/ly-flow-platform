<template>
  <CommercialPage
    :eyebrow="eyebrow"
    :title="domain.title"
    :description="domain.purpose"
    primary-title="后端接口"
    primary-hint="商业化功能必须由接口驱动"
    :routes="domain.routes"
  />
</template>

<script setup>
import { computed } from 'vue'
import CommercialPage from './CommercialPage.vue'
import { backendContractDomains } from '../contracts/backend-contracts'

const props = defineProps({
  domainId: { type: String, required: true },
  eyebrow: { type: String, default: '流影能力域' },
})

const domain = computed(() => backendContractDomains.find((item) => item.id === props.domainId) || backendContractDomains[0])
</script>
