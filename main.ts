// main.ts — the entrypoint the grader runs (node /bot/main.ts, Node 22).
//
// The forge itself is the Go program in this repository, shipped as a statically linked
// Linux amd64 binary (./forge) and the Go source it was built from. This file is a thin
// launcher: it spawns ./forge and waits for it. The Go program owns the whole lifecycle
// (bind an ephemeral port, POST {"port": N} to $MAKEFUN_ENV_URL/register, poll
// GET $MAKEFUN_ENV_URL/done, exit 0) and the whole HTTP surface (git smart HTTP, REST v3,
// GraphQL v4, MCP). No package, no Node built-in beyond child_process/path/url.
//
// The repository is mounted read-only at /bot in a trial, so the forge writes its store
// under /tmp (FORGE_DATA) unless the caller set FORGE_DATA already.

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const dir = dirname(fileURLToPath(import.meta.url));
const binary = join(dir, 'forge');

const env = { ...process.env };
if (!env.FORGE_DATA) env.FORGE_DATA = '/tmp/forge-data';

const child = spawn(binary, [], { env, stdio: 'inherit' });
child.on('error', (err) => {
  process.stderr.write(`[entry] failed to start ${binary}: ${err.message}\n`);
  process.exit(1);
});
child.on('exit', (code, signal) => {
  if (signal) {
    process.stderr.write(`[entry] forge stopped by signal ${signal}\n`);
    process.exit(1);
  }
  process.exit(code ?? 1);
});
