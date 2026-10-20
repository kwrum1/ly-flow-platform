import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import * as ElementPlusIcons from '@element-plus/icons-vue'
import App from './App.vue'
import router from './router'
import { useAuthStore } from './stores/auth'

try {
  document.documentElement.dataset.theme = localStorage.getItem('lyflow-theme') === 'dark' ? 'dark' : 'light'
} catch {
  document.documentElement.dataset.theme = 'light'
}

const app = createApp(App)
const pinia = createPinia()

for (const [key, component] of Object.entries(ElementPlusIcons)) {
  app.component(key, component)
}

app.use(pinia)
app.use(router)
app.use(ElementPlus)

const authStore = useAuthStore(pinia)
authStore.initializeSession().catch(() => {})

app.mount('#app')
