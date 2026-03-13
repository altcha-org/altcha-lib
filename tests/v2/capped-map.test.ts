import { describe, expect, test } from 'vitest';
import { CappedMap } from '../../src/v2/capped-map.js';

describe('CappedMap', () => {
	test('should limit the number of entries to specified maxSize', () => {
		const maxSize = 10;
		const map = new CappedMap({
			maxSize,
		});
		for (let i = 0; i < maxSize * 2; i++) {
			map.set(String(i), i);
		}
		expect(map.size).toEqual(maxSize);
		const keys = Object.keys(Object.fromEntries(map.entries()));
		expect(keys[0]).toEqual(String(maxSize));
		expect(keys[maxSize - 1]).toEqual(String(maxSize * 2 - 1));
	});
});
