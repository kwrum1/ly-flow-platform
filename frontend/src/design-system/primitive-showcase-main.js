import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'

import PrimitiveShowcase from '../pages/PrimitiveShowcase.vue'

createApp(PrimitiveShowcase).use(ElementPlus).mount('#showcase')
