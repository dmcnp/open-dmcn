import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { brotliCompressSync, constants as zlib, gzipSync } from 'node:zlib';

// Subresource Integrity: inject integrity="sha384-…" on the hashed <script>/<link>
// the build emits, so the browser refuses a tampered bundle (defence-in-depth behind
// the strict CSP). The inline nonce'd runtime-config <script> has no src and is left
// alone. Vite already adds crossorigin to these tags; the integrity attribute we add
// is static text that survives the Go html/template render of index.html.
//
// It runs at writeBundle, over the files on DISK, and that is the whole correctness argument.
// A digest taken from `chunk.code` in generateBundle is a digest of what the chunk looked like at
// that moment, and vite may still change a chunk afterwards — when it does, the build succeeds,
// the page ships, and the browser refuses to execute the script with nothing said at build time.
// Hashing what is actually written cannot drift from what is actually served.
function sriPlugin(): Plugin {
  return {
    name: 'dmcn-sri',
    apply: 'build',
    enforce: 'post',
    async writeBundle(options, bundle) {
      const dir = options.dir ?? 'dist';
      const integrity: Record<string, string> = {};
      const pages: string[] = [];
      for (const fileName of Object.keys(bundle)) {
        if (fileName.endsWith('.html')) {
          pages.push(fileName);
          continue;
        }
        const buf = await readFile(path.join(dir, fileName));
        integrity['/' + fileName] = 'sha384-' + createHash('sha384').update(buf).digest('base64');
      }
      for (const page of pages) {
        const file = path.join(dir, page);
        const html = await readFile(file, 'utf8');
        const withSri = html.replace(
          /<(script|link)\b([^>]*?)\b(src|href)="([^"]+)"([^>]*)>/g,
          (m, tag, pre, attr, url, post) => {
            const key = url.startsWith('/') ? url : '/' + url;
            const intg = integrity[key];
            if (!intg || m.includes('integrity=')) return m;
            return `<${tag}${pre}${attr}="${url}"${post} integrity="${intg}">`;
          },
        );
        if (withSri !== html) await writeFile(file, withSri);
      }
    },
  };
}

// DMCN_SERVER runs the dev server against a live dmcnd instead of a local one
// (`make dev-web SERVER=mail.dmcn.dev`): this source tree, hot-reloaded, talking to that
// server's API with that server's configuration. A bare host means https.
const remote = (() => {
  const v = process.env.DMCN_SERVER?.trim();
  if (!v) return '';
  return (v.includes('://') ? v : `https://${v}`).replace(/\/+$/, '');
})();

// remoteConfigPlugin gives the dev page the live server's runtime config. The daemon renders
// it into index.html per request (the `const env = {…}` block), and without it the client
// falls back to defaults that describe no real deployment: no address domain, no petition
// screen, no domain root key to check the bridge against. So each dev page load takes the
// block from the server's own page. Its NONCE is dropped: the dev server sends no CSP for a
// nonce to satisfy.
function remoteConfigPlugin(origin: string): Plugin {
  const block = /const env = \{[\s\S]*?\};/;
  return {
    name: 'dmcn-remote-config',
    apply: 'serve',
    transformIndexHtml: {
      order: 'pre',
      async handler(html) {
        const res = await fetch(`${origin}/`, { headers: { accept: 'text/html' } });
        if (!res.ok) throw new Error(`DMCN_SERVER: GET ${origin}/ answered ${res.status}`);
        const live = (await res.text()).match(block)?.[0];
        if (!live) throw new Error(`DMCN_SERVER: ${origin}/ has no runtime config block. Is it a dmcnd web client?`);
        return html.replace(block, live.replace(/NONCE: '[^']*'/, "NONCE: ''"));
      },
    },
  };
}

// Precompression: a brotli and a gzip copy of every script and stylesheet, written beside it
// (name.br, name.gz). The server answers with whichever the browser accepts (webcore.ServeFile, internal/web/server)
// and never compresses on the fly, so these are made once, here, at the slowest and smallest
// settings. Like the SRI pass, it runs over the files on disk, after anything that rewrites them;
// SRI hashes the uncompressed bytes, which is what the browser checks after decoding.
function precompressPlugin(): Plugin {
  return {
    name: 'dmcn-precompress',
    apply: 'build',
    enforce: 'post',
    async writeBundle(options, bundle) {
      const dir = options.dir ?? 'dist';
      for (const fileName of Object.keys(bundle)) {
        if (!/\.(js|css)$/.test(fileName)) continue;
        const file = path.join(dir, fileName);
        const raw = await readFile(file);
        // Below this, the encodings' own framing eats most of the saving.
        if (raw.length < 1024) continue;
        await writeFile(`${file}.br`, brotliCompressSync(raw, {
          params: { [zlib.BROTLI_PARAM_QUALITY]: zlib.BROTLI_MAX_QUALITY, [zlib.BROTLI_PARAM_SIZE_HINT]: raw.length },
        }));
        await writeFile(`${file}.gz`, gzipSync(raw, { level: zlib.Z_BEST_COMPRESSION }));
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), sriPlugin(), precompressPlugin(), ...(remote ? [remoteConfigPlugin(remote)] : [])],
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
      // daemon (HTTPS on :8443 by default), or to the live server DMCN_SERVER names.
      // The reference client is self-contained — there is no separate account/funnel
      // service — and it authenticates with a bearer header, not a cookie, so a
      // same-origin proxy is all it takes.
      '/api': remote
        ? { target: remote, changeOrigin: true }
        : { target: 'https://localhost:8443', secure: false },
    },
  },
});
