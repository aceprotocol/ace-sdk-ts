// No network downloads. Release CI must build the pinned Rust source before packaging the SDK.
import { mkdir, copyFile, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const source = new URL('../../session-core/pkg/', import.meta.url);
const destination = new URL('../dist/session-core/', import.meta.url);
await mkdir(destination, { recursive: true });
const hashes = JSON.parse(await readFile(new URL('SHA256.json', source), 'utf8'));
for (const file of ['ace_session_core.js', 'ace_session_core_bg.wasm']) {
  const path = `wasm/${file}`, bytes = await readFile(new URL(path, source));
  if (createHash('sha256').update(bytes).digest('hex') !== hashes[path]) throw Error(`Session core artifact mismatch: ${path}`);
  await copyFile(new URL(path, source), new URL(file, destination));
}
