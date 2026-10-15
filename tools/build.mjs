// Build script: compiles the server and the web client with tsc and copies static assets.
import { spawnSync, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const local = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc');
const tsc = fs.existsSync(local) ? [process.execPath, local] : [process.platform === 'win32' ? 'tsc.cmd' : 'tsc'];

function run(args) {
  const r = spawnSync(tsc[0], [...tsc.slice(1), ...args], { cwd: root, stdio: 'inherit', shell: tsc.length === 1 && process.platform === 'win32' });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

run(['-p', 'tsconfig.server.json']);
if (fs.existsSync(path.join(root, 'web')) && fs.readdirSync(path.join(root, 'web'), { recursive: true }).some(f => String(f).endsWith('.ts'))) {
  run(['-p', 'tsconfig.web.json']);
  const out = path.join(root, 'dist', 'web');
  fs.mkdirSync(out, { recursive: true });
  for (const f of fs.readdirSync(path.join(root, 'web'))) {
    if (/\.(html|css|svg|png|ico|json)$/.test(f)) fs.copyFileSync(path.join(root, 'web', f), path.join(out, f));
  }
}

// Record which commit this build was made from, so a running instance can say what it is (flowscope version, Admin > System).
// FLOWSCOPE_REVISION wins: the Docker image and the Proxmox installer build from a copy with no .git folder and pass it in.
function revision() {
  const given = (process.env.FLOWSCOPE_REVISION || '').trim();
  if (/^[0-9A-Za-z][0-9A-Za-z._-]{0,79}$/.test(given)) return given;
  try {
    const git = (...a) => execFileSync('git', a, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    const id = git('rev-parse', 'HEAD');
    if (/^[0-9a-f]{40}$/.test(id)) return id + (git('status', '--porcelain', '--untracked-files=no') ? '-dirty' : '');
  } catch { /* no git, or not a checkout */ }
  return 'unknown';
}
fs.mkdirSync(path.join(root, 'dist', 'src'), { recursive: true });
fs.writeFileSync(path.join(root, 'dist', 'src', 'buildinfo.json'), JSON.stringify({ revision: revision(), builtAt: new Date().toISOString() }) + '\n');
console.log('build ok');
