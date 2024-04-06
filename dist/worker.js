import { solveChallenge } from './index.js';
let controller = undefined;
onmessage = async (message) => {
    const { type, payload } = message.data;
    if (type === 'abort') {
        controller?.abort();
        controller = undefined;
    }
    else if (type === 'work') {
        const { alg, challenge, max, salt, start } = payload || {};
        const result = solveChallenge(challenge, salt, alg, max, start);
        controller = result.controller;
        result.promise.then((solution) => {
            self.postMessage(solution ? { ...solution, worker: true } : solution);
        });
    }
};
