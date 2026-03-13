import { handler } from './shared.js';
import { deriveKey } from '../algorithms/scrypt.js';

handler({
	deriveKey,
});

export {};
