"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CappedMap = void 0;
class CappedMap extends Map {
    constructor(options) {
        super();
        const { maxSize } = options;
        this.maxSize = maxSize;
    }
    set(key, value) {
        if (this.size >= this.maxSize && !this.has(key)) {
            this.delete(this.keys().next().value);
        }
        super.set(key, value);
        return this;
    }
}
exports.CappedMap = CappedMap;
