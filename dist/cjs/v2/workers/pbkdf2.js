"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const shared_js_1 = require("./shared.js");
const pbkdf2_js_1 = require("../algorithms/pbkdf2.js");
(0, shared_js_1.handler)({
    deriveKey: pbkdf2_js_1.deriveKey,
});
