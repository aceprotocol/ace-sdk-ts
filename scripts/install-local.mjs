#!/usr/bin/env node
// Build the unpublished SDK once, seed npm's content-addressed cache, then use
// real registry-shaped lockfiles to install consumers without publishing.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const update = process.argv.includes('--update-locks');
const consumers = process.argv.slice(2).filter((arg) => arg !== '--update-locks').map((path) => resolve(path));
if (!consumers.length) throw new Error('Usage: node scripts/install-local.mjs [--update-locks] /path/to/consumer ...');
const npm = (args, cwd = root, capture = false) => execFileSync('npm', args, { cwd, stdio: capture ? 'pipe' : 'inherit', encoding: 'utf8' });
const temp = mkdtempSync(join(tmpdir(), 'ace-sdk-package-'));
try {
  npm(['run', 'build']);
  const [artifact] = JSON.parse(npm(['pack', '--json', '--pack-destination', temp], root, true));
  const tarball = join(temp, artifact.filename);
  npm(['cache', 'add', tarball]);
  for (const consumer of consumers) {
    const manifestPath = join(consumer, 'package.json');
    const lockPath = join(consumer, 'package-lock.json');
    if (update) {
      const manifest = readFileSync(manifestPath, 'utf8');
      const expected = JSON.parse(manifest).dependencies['@ace-protocol/sdk'];
      if (expected !== artifact.version) throw new Error(`Consumer must pin SDK ${artifact.version}: ${consumer}`);
      try {
        npm(['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', tarball], consumer);
      } finally {
        writeFileSync(manifestPath, manifest);
      }
      const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
      lock.packages[''].dependencies['@ace-protocol/sdk'] = expected;
      const entry = lock.packages['node_modules/@ace-protocol/sdk'];
      if (entry.integrity !== artifact.integrity) throw new Error('npm produced an unexpected SDK integrity');
      entry.resolved = `https://registry.npmjs.org/@ace-protocol/sdk/-/sdk-${artifact.version}.tgz`;
      writeFileSync(lockPath, JSON.stringify(lock, null, 2) + '\n');
    }
    const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
    if (lock.packages['node_modules/@ace-protocol/sdk']?.integrity !== artifact.integrity) {
      throw new Error(`SDK source differs from ${consumer}'s lock. Review it, then rerun with --update-locks.`);
    }
    npm(['ci', '--no-audit', '--no-fund'], consumer);
  }
  console.log(`Installed SDK ${artifact.version} (${artifact.integrity}) into ${consumers.length} consumer(s).`);
} finally {
  rmSync(temp, { recursive: true, force: true });
}
