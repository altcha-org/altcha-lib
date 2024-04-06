import { benchmark } from './helpers.js';
import {
  createChallenge,
  solveChallenge,
  solveChallengeWorkers,
} from '../lib/index.js';

const hmacKey = 'test';
const workers = 8;
const workerScript = await import.meta.resolve!('../lib/worker.ts');

const challenge1 = await createChallenge({
  hmacKey,
  maxNumber: 1000,
  number: 1000,
});

const challenge2 = await createChallenge({
  hmacKey,
  maxNumber: 10000,
  number: 10000,
});

const challenge3 = await createChallenge({
  hmacKey,
  maxNumber: 50000,
  number: 50000,
});

const challenge4 = await createChallenge({
  hmacKey,
  maxNumber: 100000,
  number: 100000,
});

const challenge5 = await createChallenge({
  hmacKey,
  maxNumber: 500000,
  number: 500000,
});

await benchmark('solveChallenge()', (bench) => {
  bench
    .add('n = 1,000', async () => {
      await solveChallenge(challenge1.challenge, challenge1.salt).promise;
    })
    .add('n = 10,000', async () => {
      await solveChallenge(challenge2.challenge, challenge2.salt).promise;
    })
    .add('n = 50,000', async () => {
      await solveChallenge(challenge3.challenge, challenge3.salt).promise;
    })
    .add('n = 100,000', async () => {
      await solveChallenge(challenge4.challenge, challenge4.salt).promise;
    })
    .add('n = 500,000', async () => {
      await solveChallenge(challenge5.challenge, challenge5.salt).promise;
    })
});

await benchmark(`solveChallengeWorkers() (${workers} workers)`, (bench) => {
  bench
    .add('n = 1,000', async () => {
      await solveChallengeWorkers(
        workerScript,
        workers,
        challenge1.challenge,
        challenge1.salt,
        challenge1.algorithm,
        challenge1.max,
      );
    })
    .add('n = 10,000', async () => {
      await solveChallengeWorkers(
        workerScript,
        workers,
        challenge2.challenge,
        challenge2.salt,
        challenge2.algorithm,
        challenge2.max,
      );
    })
    .add('n = 50,000', async () => {
      await solveChallengeWorkers(
        workerScript,
        workers,
        challenge3.challenge,
        challenge3.salt,
        challenge3.algorithm,
        challenge3.max,
      );
    })
    .add('n = 100,000', async () => {
      await solveChallengeWorkers(
        workerScript,
        workers,
        challenge4.challenge,
        challenge4.salt,
        challenge4.algorithm,
        challenge4.max,
      );
    })
    .add('n = 500,000', async () => {
      await solveChallengeWorkers(
        workerScript,
        workers,
        challenge5.challenge,
        challenge5.salt,
        challenge5.algorithm,
        challenge5.max,
      );
    });
});
