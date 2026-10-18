import { defineConfig, type Plugin } from 'vite';
import { resolve } from 'node:path';

// Cross-origin isolation (COOP + COEP) gives performance.now() ~5 µs
// resolution instead of ~100 µs (strategy section 6.1, method rule 1).
const isolation = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

// @oqs/liboqs-js 0.15.1 loads its WASM glue with
//   import(isDeno ? `../../../../dist/X.deno.js` : `../../../../dist/X.min.js`)
// inside a variable, which Rollup cannot follow, so a production build ships a
// dangling relative import. Rewrite it to a literal import of the browser/Node
// build so Vite bundles the module (WASM is inlined in that file).
// It also re-maps '@oqs/liboqs-js/kem' and '/sig' to virtual modules that
// export only the ML-KEM / ML-DSA wrappers, so the other ~100 algorithms are
// not emitted as chunks.
const OQS_ALG = resolve(import.meta.dirname, 'node_modules/@oqs/liboqs-js/src/algorithms');
const OQS_SHIMS: Record<string, string> = {
  '@oqs/liboqs-js/kem': [512, 768, 1024]
    .map((n) => `export { createMLKEM${n} } from '${OQS_ALG}/kem/ml-kem/ml-kem-${n}.js';`)
    .join('\n'),
  '@oqs/liboqs-js/sig': [44, 65, 87]
    .map((n) => `export { createMLDSA${n} } from '${OQS_ALG}/sig/ml-dsa/ml-dsa-${n}.js';`)
    .join('\n'),
};

function liboqsStaticImport(): Plugin {
  return {
    name: 'krypt-liboqs-static-import',
    enforce: 'pre',
    resolveId(id) {
      return id in OQS_SHIMS ? `\0${id}` : null;
    },
    load(id) {
      return id.startsWith('\0') && id.slice(1) in OQS_SHIMS ? OQS_SHIMS[id.slice(1)] : null;
    },
    transform(code, id) {
      if (!id.includes('@oqs/liboqs-js/src/algorithms/')) return null;
      const m = code.match(/`(\.\.\/\.\.\/\.\.\/\.\.\/dist\/[\w-]+\.min\.js)`/);
      if (!m) return null;
      return code.replace('await import(modulePath)', `await import('${m[1]}')`);
    },
  };
}

export default defineConfig({
  plugins: [liboqsStaticImport()],
  root: resolve(import.meta.dirname, 'bench'),
  base: './',
  // The E4 ratchet ops import the shipped key schedule from ../frontend/src/crypto.
  server: {
    headers: isolation, host: true, port: 5174, strictPort: false,
    fs: { allow: [import.meta.dirname, resolve(import.meta.dirname, '../frontend/src/crypto')] },
  },
  preview: { headers: isolation, host: true, port: 4174, strictPort: false },
  // Worker bundles do not inherit top-level plugins.
  worker: { format: 'es', plugins: () => [liboqsStaticImport()] },
  build: {
    outDir: resolve(import.meta.dirname, 'dist'),
    emptyOutDir: true,
    target: 'es2022',
    // Benchmark code must not be minified into something unlike what ships;
    // keep defaults (esbuild minify) to match the production frontend build.
    chunkSizeWarningLimit: 4096,
  },
});
