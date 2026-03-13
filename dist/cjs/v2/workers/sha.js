"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const shared_js_1 = require("./shared.js");
const sha_js_1 = require("../algorithms/sha.js");
(0, shared_js_1.handler)({
    deriveKey: sha_js_1.deriveKey,
});
