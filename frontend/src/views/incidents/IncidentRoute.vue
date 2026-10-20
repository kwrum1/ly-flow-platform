<template>
  <IncidentTimelineV2 v-if="features.attackV2" />
  <Incidents v-else />
</template>

<script setup>
import Incidents from '../Incidents.vue'
import { features } from '../../config/features'
import IncidentTimelineV2 from './IncidentTimelineV2.vue'
</script>
