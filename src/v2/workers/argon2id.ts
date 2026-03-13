import { handler } from './shared.js';
import { deriveKey } from '../algorithms/argon2id.js';

handler({
	deriveKey,
});

export {};
