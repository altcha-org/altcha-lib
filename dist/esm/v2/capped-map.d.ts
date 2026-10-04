export declare class CappedMap<K = unknown, V = unknown> extends Map {
    readonly maxSize: number;
    constructor(options: {
        maxSize: number;
    });
    set(key: K, value: V): this;
    /** Adds `key` unless it is present; returns `true` if it was added. Synchronous, hence atomic. */
    setIfAbsent(key: K, value: V): boolean;
}
