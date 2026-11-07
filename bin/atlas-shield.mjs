#!/usr/bin/env node
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const [major = 0, minor = 0] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 18)) {
  process.stderr.write('Atlas Shield: Node.js >=22.18.0 is required.\n');
  process.exit(2);
}

try {
  const binPath = realpathSync(fileURLToPath(import.meta.url));
  const pkgRoot = resolve(dirname(binPath), '..');
  if (realpathSync(pkgRoot) !== pkgRoot) {
    throw new Error('Refusing to load module outside package src directory.');
  }
  const pkgJsonPath = resolve(pkgRoot, 'package.json');
  const pkgJsonStat = lstatSync(pkgJsonPath);
  if (pkgJsonStat.isSymbolicLink() || !pkgJsonStat.isFile() || realpathSync(pkgJsonPath) !== pkgJsonPath) {
    throw new Error('Refusing to load module outside package src directory.');
  }
  const srcCandidate = resolve(pkgRoot, 'src');
  const srcStat = lstatSync(srcCandidate);
  if (srcStat.isSymbolicLink() || !srcStat.isDirectory() || realpathSync(srcCandidate) !== srcCandidate) {
    throw new Error('Refusing to load module outside package src directory.');
  }
  const realSrcDir = srcCandidate;
  const srcDirUrl = new URL('./', pathToFileURL(resolve(realSrcDir, '_'))).href;

  function resolveVerifiedSrcPath(url) {
    const parsed = new URL(url);
    if (parsed.protocol !== 'file:' || parsed.search || parsed.hash || !parsed.pathname.toLowerCase().endsWith('.ts')) {
      throw new Error('Refusing to load module outside package src directory.');
    }
    const requestedPath = fileURLToPath(parsed);
    const rel = relative(realSrcDir, requestedPath);
    if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
      throw new Error('Refusing to load module outside package src directory.');
    }
    let current = realSrcDir;
    const parts = rel.split(sep);
    for (let i = 0; i < parts.length; i++) {
      current = resolve(current, parts[i]);
      const st = lstatSync(current);
      if (st.isSymbolicLink() || (i === parts.length - 1 ? !st.isFile() : !st.isDirectory())) {
        throw new Error('Refusing to load module outside package src directory.');
      }
    }
    if (realpathSync(requestedPath) !== requestedPath) {
      throw new Error('Refusing to load module outside package src directory.');
    }
    return requestedPath;
  }

  const needsStripTypes = realSrcDir.split(/[\\/]/).some(segment => segment.toLowerCase() === 'node_modules');
  const { registerHooks, stripTypeScriptTypes } = await import('node:module');
  const hooks = {
    resolve(specifier, context, nextResolve) {
      if (context.parentURL?.startsWith(srcDirUrl) && !specifier.startsWith('node:')) {
        if (!specifier.startsWith('./') && !specifier.startsWith('../')) {
          throw new Error('Refusing to resolve module outside package src directory.');
        }
        const candidateUrl = new URL(specifier, context.parentURL).href;
        if (!candidateUrl.startsWith(srcDirUrl)) {
          throw new Error('Refusing to resolve module outside package src directory.');
        }
        resolveVerifiedSrcPath(candidateUrl);
      }
      const resolved = nextResolve(specifier, context);
      if (context.parentURL?.startsWith(srcDirUrl) && !resolved.url.startsWith('node:')) {
        if (!resolved.url.startsWith(srcDirUrl)) {
          throw new Error('Refusing to resolve module outside package src directory.');
        }
        resolveVerifiedSrcPath(resolved.url);
      }
      return resolved;
    },
  };
  if (needsStripTypes) {
    hooks.load = (url, context, nextLoad) => {
      if (url.startsWith(srcDirUrl) && url.toLowerCase().endsWith('.ts')) {
        const targetPath = resolveVerifiedSrcPath(url);
        return {
          format: 'module',
          shortCircuit: true,
          source: stripTypeScriptTypes(readFileSync(targetPath, 'utf8'), { mode: 'strip', sourceUrl: url }),
        };
      }
      return nextLoad(url, context);
    };
  }
  registerHooks(hooks);

  const cliUrl = new URL('./cli.ts', srcDirUrl).href;
  resolveVerifiedSrcPath(cliUrl);
  await import(cliUrl);
} catch (error) {
  const rawMessage = error instanceof Error ? error.message : 'Bootstrap failed.';
  const clean = rawMessage.replace(/[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, ' ');
  process.stderr.write(`Atlas Shield: ${clean}\n`);
  process.exit(2);
}
