<template>
  <el-input
    class="ly-console-search"
    type="search"
    :model-value="modelValue"
    :placeholder="placeholder"
    :aria-label="label"
    :clearable="clearable"
    @update:model-value="updateValue"
    @keyup.enter="submitSearch"
  >
    <template #prefix>
      <el-icon aria-hidden="true"><Search /></el-icon>
    </template>
  </el-input>
</template>

<script setup>
import { Search } from '@element-plus/icons-vue'

defineOptions({ name: 'ConsoleSearchField' })

const props = defineProps({
  modelValue: { type: String, default: '' },
  label: { type: String, required: true },
  placeholder: { type: String, default: '' },
  clearable: { type: Boolean, default: true },
})

const emit = defineEmits(['update:modelValue', 'search'])

function updateValue(value) {
  emit('update:modelValue', value)
}

function submitSearch() {
  emit('search', props.modelValue)
}
</script>
