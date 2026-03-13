#!/usr/bin/env node

import { obfuscate, deobfuscate } from 'altcha-lib/obfuscation';

const [command, ...rest] = process.argv.slice(2);

if (!command || !['obfuscate', 'deobfuscate'].includes(command)) {
  console.error('Usage: altcha-lib <obfuscate|deobfuscate> [data]');
  process.exit(1);
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let buf = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => buf += chunk);
    process.stdin.on('end', () => resolve(buf.trim()));
    process.stdin.on('error', reject);
  });
}

try {
  const data = rest.length ? rest.join(' ') : await readStdin();

  if (!data) {
    console.error(`Error: No data provided for ${command}`);
    process.exit(1);
  }

  const result = command === 'obfuscate' ? await obfuscate(data) : await deobfuscate(data);
  console.log(result);
} catch (err) {
  console.error(`Error during ${command}: ${err.message}`);
  process.exit(1);
}