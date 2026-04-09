#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { Worker as NodeWorker } from 'node:worker_threads';
import { obfuscate, deobfuscate } from 'altcha-lib/obfuscation';
import { createChallenge, solveChallengeWorkers, verifySolution } from 'altcha-lib';

const ALGORITHMS = [
	'PBKDF2/SHA-256',
	'PBKDF2/SHA-384',
	'PBKDF2/SHA-512',
	'SCRYPT',
	'ARGON2ID',
	'SHA-256',
	'SHA-384',
	'SHA-512',
];

const USAGE = `Usage: altcha-lib <command> [options]

Commands:
  obfuscate [data]       Obfuscate a string
  deobfuscate [data]     Deobfuscate a string
  create                 Create a new challenge
  solve [challenge]      Solve a challenge (JSON)
                         --workers <n>          Number of worker threads (default: 1)
  verify [challenge] [solution]  Verify a challenge solution (JSON files or inline JSON)

Options for create:
  --algorithm <algo>         Algorithm (default: PBKDF2/SHA-256)
                             Supported: ${ALGORITHMS.join(', ')}
  --cost <n>                 Cost parameter (default: 5000 for SHA/PBKDF2, 16384 for SCRYPT, 3 for ARGON2ID)
  --hmac-secret <secret>     HMAC secret for signing the challenge
  --hmac-key-secret <secret> HMAC secret for signing the derived key (deterministic mode)
  --counter <n>              Known counter value for deterministic mode
  --expires <seconds>        Seconds until the challenge expires
  --key-prefix <prefix>      Key prefix override
  --memory-cost <n>          Memory cost (SCRYPT/ARGON2ID only)
  --parallelism <n>          Parallelism (SCRYPT/ARGON2ID only)

Options for verify:
  --hmac-secret <secret>     HMAC secret used when creating the challenge
  --hmac-key-secret <secret> HMAC key secret used when creating the challenge (deterministic mode)
`;

const [command, ...rest] = process.argv.slice(2);

const COMMANDS = ['obfuscate', 'deobfuscate', 'create', 'solve', 'verify'];

if (!command || !COMMANDS.includes(command)) {
	process.stderr.write(USAGE);
	process.exit(1);
}

function readStdin() {
	return new Promise((resolve, reject) => {
		let buf = '';
		process.stdin.setEncoding('utf-8');
		process.stdin.on('data', (chunk) => (buf += chunk));
		process.stdin.on('end', () => resolve(buf.trim()));
		process.stdin.on('error', reject);
	});
}

async function readInput(arg, label) {
	let raw;
	if (arg) {
		try {
			raw = (await readFile(arg, 'utf-8')).trim();
		} catch {
			// Not a readable file — treat as inline JSON string
			raw = arg;
		}
	} else {
		raw = await readStdin();
	}
	if (!raw) {
		console.error(`Error: No ${label} provided`);
		process.exit(1);
	}
	return raw;
}

function parseArgs(args) {
	const opts = {};
	const positional = [];
	for (let i = 0; i < args.length; i++) {
		if (args[i].startsWith('--')) {
			const key = args[i].slice(2);
			if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
				opts[key] = args[++i];
			} else {
				opts[key] = true;
			}
		} else {
			positional.push(args[i]);
		}
	}
	return { opts, positional };
}

function getWorkerName(algorithm) {
	const algo = (algorithm || '').toUpperCase();
	if (algo.startsWith('PBKDF2')) return 'pbkdf2';
	if (algo === 'SCRYPT') return 'scrypt';
	if (algo === 'ARGON2ID') return 'argon2id';
	return 'sha';
}

function createWorker(algorithm) {
	const workerModuleUrl = new URL(
		`../dist/esm/v2/workers/${getWorkerName(algorithm)}.js`,
		import.meta.url
	).href;
	// Shim Web Worker globals (self.onmessage / self.postMessage) so the
	// existing dist worker modules work inside a node:worker_threads context.
	const shim = `
import { parentPort } from 'node:worker_threads';
const self = { onmessage: null, postMessage(d) { parentPort.postMessage(d); } };
globalThis.self = self;
parentPort.on('message', (data) => { if (typeof self.onmessage === 'function') self.onmessage({ data }); });
await import(${JSON.stringify(workerModuleUrl)});
`;
	const worker = new NodeWorker(
		new URL(`data:text/javascript,${encodeURIComponent(shim)}`),
		{ type: 'module' }
	);
	// Adapt EventEmitter API to the EventTarget API expected by solveChallengeWorkers.
	worker.addEventListener = (event, handler) => {
		worker.on(event === 'message' ? 'message' : event, (data) =>
			event === 'message' ? handler({ data }) : handler(data)
		);
	};
	return worker;
}

async function getDeriveKey(algorithm) {
	const algo = (algorithm || 'PBKDF2/SHA-256').toUpperCase();
	if (algo.startsWith('PBKDF2')) {
		const mod = await import('altcha-lib/algorithms/pbkdf2');
		return mod.deriveKey;
	} else if (algo === 'SCRYPT') {
		const mod = await import('altcha-lib/algorithms/scrypt');
		return mod.deriveKey;
	} else if (algo === 'ARGON2ID') {
		const mod = await import('altcha-lib/algorithms/argon2id');
		return mod.deriveKey;
	} else {
		const mod = await import('altcha-lib/algorithms/sha');
		return mod.deriveKey;
	}
}

function getDefaultCost(algorithm) {
	const algo = (algorithm || 'SHA-256').toUpperCase();
	if (algo === 'SCRYPT') return 16384;
	if (algo === 'ARGON2ID') return 3;
	return 5000;
}

function getDefaultMemoryCost(algorithm) {
	const algo = (algorithm || '').toUpperCase();
	if (algo === 'SCRYPT') return 8;
	if (algo === 'ARGON2ID') return 65536;
	return undefined;
}

try {
	if (command === 'obfuscate' || command === 'deobfuscate') {
		const data = rest.length ? rest.join(' ') : await readStdin();
		if (!data) {
			console.error(`Error: No data provided for ${command}`);
			process.exit(1);
		}
		const result =
			command === 'obfuscate' ? await obfuscate(data) : await deobfuscate(data);
		console.log(result);
	} else if (command === 'create') {
		const { opts } = parseArgs(rest);
		const algorithm = opts['algorithm'] || 'SHA-256';
		const cost = opts['cost']
			? parseInt(opts['cost'], 10)
			: getDefaultCost(algorithm);
		const hmacSecret = opts['hmac-secret'];
		const hmacKeySecret = opts['hmac-key-secret'];
		const counter = opts['counter'] !== undefined ? parseInt(opts['counter'], 10) : undefined;
		const expires = opts['expires'] ? parseInt(opts['expires'], 10) : undefined;
		const keyPrefix = opts['key-prefix'];
		const memoryCost = opts['memory-cost']
			? parseInt(opts['memory-cost'], 10)
			: getDefaultMemoryCost(algorithm);
		const parallelism = opts['parallelism']
			? parseInt(opts['parallelism'], 10)
			: undefined;

		const deriveKey = await getDeriveKey(algorithm);
		const challenge = await createChallenge({
			algorithm,
			cost,
			counter,
			deriveKey,
			expiresAt: expires ? new Date(Date.now() + expires * 1000) : undefined,
			hmacSignatureSecret: hmacSecret,
			hmacKeySignatureSecret: hmacKeySecret,
			keyPrefix,
			memoryCost,
			parallelism,
		});
		console.log(JSON.stringify(challenge, null, 2));
	} else if (command === 'solve') {
		const { opts, positional } = parseArgs(rest);
		const workers = opts['workers'] ? parseInt(opts['workers'], 10) : undefined;
		const raw = await readInput(positional.length ? positional[0] : null, 'challenge JSON');
		let challenge;
		try {
			challenge = JSON.parse(raw);
		} catch {
			console.error('Error: Invalid JSON for challenge');
			process.exit(1);
		}
		const algorithm = challenge?.parameters?.algorithm;
		const solution = await solveChallengeWorkers({
			challenge,
			concurrency: workers ?? 1,
			createWorker: () => createWorker(algorithm),
		});
		if (!solution) {
			console.error('Error: Failed to solve challenge (timeout or aborted)');
			process.exit(1);
		}
		console.log(JSON.stringify(solution, null, 2));
	} else if (command === 'verify') {
		const { opts, positional } = parseArgs(rest);
		const hmacSecret = opts['hmac-secret'];
		const hmacKeySecret = opts['hmac-key-secret'];
		if (!hmacSecret) {
			console.error('Error: --hmac-secret is required for verify');
			process.exit(1);
		}
		let challenge, solution;
		if (positional.length >= 2) {
			const rawChallenge = await readInput(positional[0], 'challenge JSON');
			const rawSolution = await readInput(positional[1], 'solution JSON');
			try {
				challenge = JSON.parse(rawChallenge);
			} catch {
				console.error('Error: Invalid JSON for challenge');
				process.exit(1);
			}
			try {
				solution = JSON.parse(rawSolution);
			} catch {
				console.error('Error: Invalid JSON for solution');
				process.exit(1);
			}
		} else {
			const raw = await readInput(positional.length ? positional[0] : null, 'payload JSON');
			let payload;
			try {
				payload = JSON.parse(raw);
			} catch {
				console.error('Error: Invalid JSON for payload');
				process.exit(1);
			}
			({ challenge, solution } = payload);
			if (!challenge || !solution) {
				console.error(
					'Error: Payload must contain "challenge" and "solution" fields'
				);
				process.exit(1);
			}
		}
		const algorithm = challenge?.parameters?.algorithm;
		const deriveKey = await getDeriveKey(algorithm);
		const result = await verifySolution({
			challenge,
			solution,
			deriveKey,
			hmacSignatureSecret: hmacSecret,
			hmacKeySignatureSecret: hmacKeySecret,
		});
		console.log(JSON.stringify(result, null, 2));
		if (!result.verified) {
			process.exit(1);
		}
	}
} catch (err) {
	console.error(`Error: ${err.message}`);
	process.exit(1);
}
