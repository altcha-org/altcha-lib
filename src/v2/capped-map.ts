export class CappedMap<K = unknown, V = unknown> extends Map {
	readonly maxSize: number;

	constructor(options: { maxSize: number }) {
		super();
		const { maxSize } = options;
		this.maxSize = maxSize;
	}

	override set(key: K, value: V) {
		if (this.size >= this.maxSize && !this.has(key)) {
			this.delete(this.keys().next().value);
		}
		super.set(key, value);
		return this;
	}
}
