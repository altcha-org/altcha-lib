import { solveChallenge } from './index.ts';

let controller: AbortController | undefined = undefined;

onmessage = async (message) => {
  const { type, payload } = message.data;
  if (type === 'abort') {
    controller?.abort();
    controller = undefined;
  } else if (type === 'work') {
    const { algorithm, challenge, max, salt, start } = payload || {};
    const result = solveChallenge(challenge, salt, algorithm, max, start);
    controller = result.controller;
    result.promise.then((solution) => {
      self.postMessage(solution ? { ...solution, worker: true } : solution);
    });
  }
};

export {};
