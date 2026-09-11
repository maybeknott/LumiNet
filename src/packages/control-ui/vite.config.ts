import { readFileSync } from 'node:fs';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

const packageVersion = (JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as { version: string }).version;
const buildVersion = process.env.LUMINET_BUILD_VERSION?.trim() || process.env.GITHUB_REF_NAME?.trim() || packageVersion;

export default defineConfig({
  base: './',
  define: {
    'import.meta.env.VITE_APP_VERSION': JSON.stringify(buildVersion),
  },
  plugins: [react(), tailwindcss()],
  build: {
    sourcemap: true,
  },
});
