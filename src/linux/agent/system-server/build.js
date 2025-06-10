import esbuild from 'esbuild';
import alias from 'esbuild-plugin-alias';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const BUFFER_SHIM = require.resolve('@frida/buffer');

esbuild.build({
  entryPoints: ['index.js'],
  outfile: 'system-server.js',
  bundle: true,
  platform: 'node',
  target: ['es2022'],
  legalComments: 'none',
  minify: true,
  plugins: [
    alias({
      'buffer': BUFFER_SHIM,
      'node:buffer': BUFFER_SHIM,
    }),
  ],
}).catch(() => process.exit(1));
