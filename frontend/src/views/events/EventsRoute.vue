<template>
  <EventsV2 v-if="features.attackV2" />
  <EventsWorkbench v-else />
</template>

<script setup>
import EventsWorkbench from '../../pages/EventsWorkbench.vue'
import { features } from '../../config/features'
import EventsV2 from './EventsV2.vue'
</script>
