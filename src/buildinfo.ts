import fs from 'node:fs';

/**
 * Which build is running. tools/build.mjs writes dist/src/buildinfo.json when it compiles: the git commit the build was made from
 * (from FLOWSCOPE_REVISION when the build has no .git folder, as in the Docker image and the Proxmox installer, else from git) and the
 * time. A run from source with no build step has no file, and then the revision is reported as "unknown".
 */
export interface BuildInfo { revision: string; builtAt: string | null }

const SAFE = /^[0-9A-Za-z][0-9A-Za-z._-]{0,79}$/;

export function readBuildInfo(file: URL = new URL('./buildinfo.json', import.meta.url)): BuildInfo {
  try {
    const j = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<BuildInfo>;
    const revision = typeof j.revision === 'string' && SAFE.test(j.revision) ? j.revision : 'unknown';
    const builtAt = typeof j.builtAt === 'string' && !Number.isNaN(Date.parse(j.builtAt)) ? j.builtAt : null;
    return { revision, builtAt };
  } catch { return { revision: 'unknown', builtAt: null }; }
}

export const BUILD: BuildInfo = readBuildInfo();

/** The first seven characters of a commit id; anything else (a tag name, "unknown", "<id>-dirty") is shown as it is. */
export function shortRevision(rev: string): string {
  const m = /^([0-9a-f]{40})(-dirty)?$/.exec(rev);
  return m ? m[1].slice(0, 7) + (m[2] ?? '') : rev;
}

export function describeVersion(version: string, b: BuildInfo = BUILD): string {
  return `${version} (revision ${shortRevision(b.revision)})`;
}
