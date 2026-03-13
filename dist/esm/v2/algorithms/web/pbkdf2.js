export async function deriveKey(parameters, salt, password) {
    const { cost, keyLength = 32 } = parameters;
    const hash = parameters.algorithm.startsWith('PBKDF2/')
        ? parameters.algorithm.slice(7)
        : 'SHA-256';
    const passwordKey = await crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveKey']);
    const derivedKey = await crypto.subtle.deriveKey({
        name: 'PBKDF2',
        salt: salt,
        iterations: cost,
        hash,
    }, passwordKey, { name: 'AES-GCM', length: keyLength * 8 }, true, ['encrypt']);
    return {
        derivedKey: new Uint8Array(await crypto.subtle.exportKey('raw', derivedKey)),
    };
}
