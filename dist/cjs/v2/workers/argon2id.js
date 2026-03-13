"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const shared_js_1 = require("./shared.js");
const argon2id_js_1 = require("../algorithms/argon2id.js");
(0, shared_js_1.handler)({
    deriveKey: argon2id_js_1.deriveKey,
});
