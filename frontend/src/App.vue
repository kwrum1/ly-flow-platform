<template>
  <router-view :key="platformTimeVersion" />
</template>

<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import './assets/styles/global.css'
import { PLATFORM_TIME_UPDATED_EVENT, getPlatformTimeVersion } from './shared/time'

const platformTimeVersion = ref(getPlatformTimeVersion())

function syncPlatformTimeVersion() {
  platformTimeVersion.value = getPlatformTimeVersion()
}

onMounted(() => {
  window.addEventListener(PLATFORM_TIME_UPDATED_EVENT, syncPlatformTimeVersion)
})

onUnmounted(() => {
  window.removeEventListener(PLATFORM_TIME_UPDATED_EVENT, syncPlatformTimeVersion)
})
</script>
