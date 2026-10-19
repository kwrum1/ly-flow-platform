import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  preview: {
    port: 3200,
    host: '0.0.0.0',
    proxy: {
      '/api': { target: 'https://10.1.18.126', changeOrigin: true, secure: false },
      '/ws': { target: 'wss://10.1.18.126', ws: true, secure: false },
    },
  },
  define: { 'import.meta.env.VITE_API_BASE': JSON.stringify('/api') },
})
