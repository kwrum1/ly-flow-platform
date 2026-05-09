import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://ly-server:8080',
        changeOrigin: true
      },
      '/ws': {
        target: 'ws://ly-server:8080',
        ws: true
      }
    }
  }
})
