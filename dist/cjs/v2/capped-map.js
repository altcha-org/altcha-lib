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
    /** Adds `key` unless it is present; returns `true` if it was added. Synchronous, hence atomic. */
    setIfAbsent(key, value) {
        if (this.has(key)) {
            return false;
        }
        this.set(key, value);
        return true;
    }
}
exports.CappedMap = CappedMap;
