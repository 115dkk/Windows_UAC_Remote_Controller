import { fileURLToPath, URL } from 'node:url';
import { resolve } from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => ({
  root: 'ui',
  plugins: [react(), {
    name: 'isolate-gallery-from-product',
    apply: 'build',
    configResolved(config) {
      const output = resolve(config.root, config.build.outDir);
      const gallery = fileURLToPath(new URL('./target/ui-qa', import.meta.url));
      const normalize = (path: string) => process.platform === 'win32' ? path.toLowerCase() : path;
      if (mode === 'qa' && normalize(output) !== normalize(gallery)) {
        throw new Error('The synthetic gallery may only build into target/ui-qa.');
      }
    },
    generateBundle(_options, bundle) {
      if (mode === 'qa') return;
      for (const output of Object.values(bundle)) {
        if (output.type !== 'chunk') continue;
        if (Object.keys(output.modules).some((id) => /\/qa-(fixtures|preview)\.tsx?(?:\?|$)/u.test(id.replaceAll('\\', '/')))) {
          throw new Error('Synthetic gallery code is forbidden in a product build.');
        }
      }
    },
  }],
  clearScreen: false,
  server: { host: '127.0.0.1', port: 1420, strictPort: true },
  build: {
    outDir: mode === 'qa' ? '../target/ui-qa' : '../dist',
    emptyOutDir: true,
    target: ['es2022', 'chrome110'],
    sourcemap: false,
    rolldownOptions: {
      input: fileURLToPath(new URL(mode === 'qa' ? './ui/qa.html' : './ui/index.html', import.meta.url)),
    },
  },
}));
