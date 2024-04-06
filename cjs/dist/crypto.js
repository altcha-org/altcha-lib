"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
if (!('crypto' in globalThis)) {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    globalThis.crypto = require('node:crypto').webcrypto;
}
