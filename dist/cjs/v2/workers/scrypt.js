"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const shared_js_1 = require("./shared.js");
const scrypt_js_1 = require("../algorithms/scrypt.js");
(0, shared_js_1.handler)({
    deriveKey: scrypt_js_1.deriveKey,
});
