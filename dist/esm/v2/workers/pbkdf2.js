import { handler } from './shared.js';
import { deriveKey } from '../algorithms/pbkdf2.js';
handler({
    deriveKey,
});
