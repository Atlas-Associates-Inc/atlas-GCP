#!/usr/bin/env node
const [major = 0, minor = 0] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 18)) {
  process.stderr.write('Atlas Shield: Node.js >=22.18.0 is required.\n');
  process.exit(2);
}
await import('../src/cli.ts');
