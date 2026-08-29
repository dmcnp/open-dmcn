import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { createHash } from 'node:crypto';

// Subresource Integrity: inject integrity="sha384-…" on the hashed <script>/<link>
// the build emits, so the browser refuses a tampered bundle (defence-in-depth behind
// the strict CSP). The inline nonce'd runtime-config <script> has no src and is left
// alone. Vite already adds crossorigin to these tags; the integrity attribute we add
// is static text that survives the Go html/template render of index.html.
function sriPlugin(): Plugin {
  return {
    name: 'dmcn-sri',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const integrity: Record<string, string> = {};
      for (const [fileName, chunk] of Object.entries(bundle)) {
        const source = chunk.type === 'chunk' ? chunk.code : chunk.source;
        const buf = Buffer.from(source as string | Uint8Array);
        integrity['/' + fileName] = 'sha384-' + createHash('sha384').update(buf).digest('base64');
      }
      const index = bundle['index.html'];
      if (index && index.type === 'asset' && typeof index.source === 'string') {
        index.source = index.source.replace(
          /<(script|link)\b([^>]*?)\b(src|href)="([^"]+)"([^>]*)>/g,
          (m, tag, pre, attr, url, post) => {
            const key = url.startsWith('/') ? url : '/' + url;
            const intg = integrity[key];
            if (!intg || m.includes('integrity=')) return m;
            return `<${tag}${pre}${attr}="${url}"${post} integrity="${intg}">`;
          },
        );
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), sriPlugin()],
  // The two modules that are this BUILD's rather than the client's: what deployment it is,
  // and which protobuf bundle it carries. Aliased so the shared tree names them by identity
  // instead of by path, and can therefore be shared verbatim.
  resolve: {
    alias: {
      '@deployment': fileURLToPath(new URL('./app/deployment.tsx', import.meta.url)),
      '@proto': fileURLToPath(new URL('./app/proto/dmcn.js', import.meta.url)),
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      // In dev, the SPA (vite on :5173) proxies its API calls to the running dmcnd
      // daemon (HTTPS on :8443 by default). The reference client is self-contained —
      // there is no separate account/funnel service.
      '/api': {
        target: 'https://localhost:8443',
        secure: false,
      },
    },
  },
});
