"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.handler = handler;
const pow_js_1 = require("../pow.js");
function handler(options) {
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
                solution = await (0, pow_js_1.solveChallenge)({
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
