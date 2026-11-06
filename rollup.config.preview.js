// Browser preview build: same plugin UI, but decky-frontend-lib is
// stubbed and serverAPI is mocked so the UI can run in a plain browser.
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import replace from '@rollup/plugin-replace';
import typescript from '@rollup/plugin-typescript';
import { defineConfig } from 'rollup';

import path from 'path';
import importAssets from 'rollup-plugin-import-assets';

// Redirect decky-frontend-lib to the browser stub (no extra deps).
const dflStub = {
  name: 'dfl-stub',
  resolveId(id) {
    if (id === 'decky-frontend-lib') {
      return path.resolve(__dirname, 'src/preview-dfl-stub.tsx');
    }
    return null;
  }
};

export default defineConfig({
  input: 'src/preview.tsx',
  plugins: [
    dflStub,
    commonjs(),
    nodeResolve(),
    typescript(),
    json(),
    replace({
      preventAssignment: false,
      'process.env.NODE_ENV': JSON.stringify('production'),
    }),
    importAssets({
      publicPath: './'
    })
  ],
  context: 'window',
  // react is bundled (no Steam globals in a browser).
  external: [],
  output: {
    file: 'dist/preview.js',
    format: 'iife'
  }
});
