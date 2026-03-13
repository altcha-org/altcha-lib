export declare class CappedMap<K = unknown, V = unknown> extends Map {
    readonly maxSize: number;
    constructor(options: {
        maxSize: number;
    });
    set(key: K, value: V): this;
}
