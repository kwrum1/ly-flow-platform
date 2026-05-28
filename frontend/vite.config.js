import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  test: {
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
  },
  server: {
    port: 3000,
    host: '0.0.0.0',
    proxy: {
      '/api': {
        target: process.env.VITE_API_TARGET || 'http://localhost:8080',
        changeOrigin: true
      },
      '/ws': {
        target: process.env.VITE_WS_TARGET || 'ws://localhost:8080',
        ws: true
      }
    }
  },
  define: {
    'import.meta.env.VITE_API_BASE': JSON.stringify('/api')
  }
})
