"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const index_js_1 = require("./index.js");
let controller = undefined;
onmessage = async (message) => {
    const { type, payload } = message.data;
    if (type === 'abort') {
        controller?.abort();
        controller = undefined;
    }
    else if (type === 'work') {
        const { algorithm, challenge, max, salt, start } = payload || {};
        const result = (0, index_js_1.solveChallenge)(challenge, salt, algorithm, max, start);
        controller = result.controller;
        result.promise.then((solution) => {
            self.postMessage(solution ? { ...solution, worker: true } : solution);
        });
    }
};
