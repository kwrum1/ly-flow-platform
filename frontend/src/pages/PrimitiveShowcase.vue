<template>
  <ConsoleFrame data-testid="primitive-showcase">
    <template #rail>
      <nav class="showcase-rail" aria-label="LyFlow primary navigation" data-qa-box="rail">
        <button class="showcase-rail__button is-active" type="button" aria-label="运营概览">
          <el-icon><Monitor /></el-icon>
        </button>
        <button class="showcase-rail__button" type="button" aria-label="告警中心">
          <el-icon><Bell /></el-icon>
        </button>
        <button class="showcase-rail__button" type="button" aria-label="系统设置">
          <el-icon><Setting /></el-icon>
        </button>
      </nav>
    </template>

    <template #navigation>
      <nav class="showcase-navigation" aria-label="LyFlow secondary navigation" data-qa-box="navigation">
        <strong>安全运营</strong>
        <button class="is-active" type="button">态势概览</button>
        <button type="button">事件队列</button>
        <button type="button">资产状态</button>
      </nav>
    </template>

    <div class="showcase-workspace" data-qa-box="workspace">
      <ConsoleIdentityRow title="设计基础组件" context="T16 独立验收页，不进入产品导航">
        <template #actions>
          <el-button type="primary">刷新状态</el-button>
        </template>
      </ConsoleIdentityRow>

      <div class="showcase-content">
        <div class="showcase-toolbar" data-qa-box="toolbar">
          <ConsoleSearchField
            v-model="query"
            label="搜索基础组件"
            placeholder="搜索组件或令牌"
            @search="lastSearch = query"
          />
          <el-button>筛选</el-button>
          <span class="showcase-toolbar__result" aria-live="polite">{{ lastSearch }}</span>
        </div>

        <div class="showcase-grid">
          <ConsoleSurface aria-labelledby="type-heading">
            <template #header><span id="type-heading">字体层级</span></template>
            <div class="type-stack">
              <p class="type-20" data-type-token="20" data-qa-clip>20px 页面标题</p>
              <p class="type-16" data-type-token="16" data-qa-clip>16px 分区标题</p>
              <p class="type-14" data-type-token="14" data-qa-clip>14px 操作正文与表格内容</p>
              <p class="type-12" data-type-token="12" data-qa-clip>12px 元数据与辅助说明</p>
            </div>
          </ConsoleSurface>

          <ConsoleSurface aria-labelledby="state-heading">
            <template #header><span id="state-heading">语义状态</span></template>
            <div class="state-list">
              <span class="state-chip is-healthy" data-showcase-state="healthy">健康 正常采集</span>
              <span class="state-chip is-warning" data-showcase-state="warning">警告 数据延迟</span>
              <span class="state-chip is-abnormal" data-showcase-state="abnormal">异常 连接中断</span>
            </div>
          </ConsoleSurface>

          <ConsoleSurface aria-labelledby="geometry-heading">
            <template #header><span id="geometry-heading">几何与图标</span></template>
            <div class="geometry-row">
              <button class="geometry-control" type="button">8px 控件</button>
              <div class="visualization-well">12px 可视化区域</div>
              <el-icon class="showcase-icon" aria-label="18px 提示图标"><InfoFilled /></el-icon>
            </div>
          </ConsoleSurface>

          <ConsoleSurface aria-labelledby="state-cycle-heading">
            <template #header><span id="state-cycle-heading">内容状态</span></template>
            <div class="content-states">
              <p aria-live="polite">加载：正在同步策略</p>
              <p>空状态：暂无匹配记录</p>
              <p role="alert">错误：连接失败，请重试</p>
            </div>
          </ConsoleSurface>
        </div>
      </div>
    </div>
  </ConsoleFrame>
</template>

<script setup>
import { Bell, InfoFilled, Monitor, Setting } from '@element-plus/icons-vue'
import { ref } from 'vue'

import {
  ConsoleFrame,
  ConsoleIdentityRow,
  ConsoleSearchField,
  ConsoleSurface,
} from '../design-system/index.js'

defineOptions({ name: 'PrimitiveShowcase' })

const query = ref('')
const lastSearch = ref('')
</script>

<style scoped src="../design-system/primitive-showcase.css"></style>
