import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

const apiTarget = 'http://localhost:3000';

export default defineConfig({
  plugins: [vue()],
  base: '/',
  publicDir: false,
  build: {
    outDir: 'public',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/admin': apiTarget,
      '/api': apiTarget,
      '/health': apiTarget,
    },
    fs: {
      deny: ['.env', '.env.*', 'client/**', 'database/**', 'src/**'],
    },
  },
});
