"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.State = exports.HmacAlgorithm = void 0;
var HmacAlgorithm;
(function (HmacAlgorithm) {
    HmacAlgorithm["SHA_256"] = "SHA-256";
    HmacAlgorithm["SHA_384"] = "SHA-384";
    HmacAlgorithm["SHA_512"] = "SHA-512";
})(HmacAlgorithm || (exports.HmacAlgorithm = HmacAlgorithm = {}));
var State;
(function (State) {
    State["CODE"] = "code";
    State["ERROR"] = "error";
    State["VERIFIED"] = "verified";
    State["VERIFYING"] = "verifying";
    State["UNVERIFIED"] = "unverified";
    State["EXPIRED"] = "expired";
})(State || (exports.State = State = {}));
