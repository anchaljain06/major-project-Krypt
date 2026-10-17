import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath } from 'node:url'

// The key-transparency library lives in ../shared and is imported from its TS
// sources (shared/README.md, "How to consume it"). The alias and fs.allow let
// both `vite build` and the dev server reach it; tsconfig.app.json has the
// matching `paths` entry for the type checker.
const sharedDir = fileURLToPath(new URL('../shared/src', import.meta.url))

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@krypt/shared': `${sharedDir}/index.ts` },
  },
  server: {
    fs: { allow: ['.', sharedDir] },
  },
})
