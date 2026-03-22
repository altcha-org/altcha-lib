import { solveChallenge } from '../pow.js';
export function handler(options) {
    const { deriveKey } = options;
    let controller = undefined;
    self.onmessage = async (message) => {
        const { challenge, counterMode, counterStart, counterStep, timeout, type } = message.data;
        if (type === 'abort') {
            controller?.abort();
        }
        else if (type === 'work') {
            controller = new AbortController();
            let solution;
            try {
                solution = await solveChallenge({
                    challenge,
                    controller,
                    counterStart,
                    counterStep,
                    deriveKey,
                    counterMode,
                    timeout,
                });
            }
            catch (err) {
                return self.postMessage({ error: err });
            }
            self.postMessage(solution);
        }
    };
}
