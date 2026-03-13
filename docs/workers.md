# Workers

The library supports solving challenges using Web Workers.

In Node.js environments, use the `web-worker` package to provide compatibility with `node:worker_threads`.

```ts
import Worker from 'web-worker';
import { solveChallengeWorkers } from 'altcha-lib';

const workerPath = import.meta.resolve('altcha-lib/workers/pbkdf2');

const solution = await solveChallengeWorkers({
	challenge,
	concurrency: 4,
	createWorker() {
		return new Worker(workerPath, {
			type: 'module',
		});
	},
});
```