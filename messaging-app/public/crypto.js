/**
 * TeaTime Crypto Module
 * Handles identity key pair generation and SealedBox decryption
 * using libsodium-wrappers for asymmetric challenge-response authentication.
 *
 * Loaded in preload.js (Node.js context), exposed to renderer via contextBridge.
 */

const _sodium = require('libsodium-wrappers');

// libsodium requires async initialization
let sodiumReady = _sodium.ready;

const TeaCrypto = {
    /**
     * Wait for libsodium WASM to initialize.
     * Must be called before any other crypto function.
     */
    async init() {
        await sodiumReady;
    },

    /**
     * Generate a new X25519 key pair for identity.
     * Returns { publicKey: base64, secretKey: base64 }
     */
    generateKeyPair() {
        const keyPair = _sodium.crypto_box_keypair();
        return {
            publicKey: _sodium.to_base64(keyPair.publicKey, _sodium.base64_variants.ORIGINAL),
            secretKey: _sodium.to_base64(keyPair.privateKey, _sodium.base64_variants.ORIGINAL)
        };
    },

    /**
     * Decrypt a SealedBox encrypted challenge using the user's key pair.
     * @param {string} encryptedB64 - Base64-encoded SealedBox ciphertext from server
     * @param {string} publicKeyB64 - Base64-encoded X25519 public key
     * @param {string} secretKeyB64 - Base64-encoded X25519 secret key
     * @returns {string} Hex string of the decrypted challenge
     */
    decryptChallenge(encryptedB64, publicKeyB64, secretKeyB64) {
        const ciphertext = _sodium.from_base64(encryptedB64, _sodium.base64_variants.ORIGINAL);
        const publicKey = _sodium.from_base64(publicKeyB64, _sodium.base64_variants.ORIGINAL);
        const secretKey = _sodium.from_base64(secretKeyB64, _sodium.base64_variants.ORIGINAL);

        // crypto_box_seal_open: proper SealedBox decryption matching PyNaCl's SealedBox
        const decrypted = _sodium.crypto_box_seal_open(ciphertext, publicKey, secretKey);

        // Convert to hex string to match the server's challenge_hex format
        return _sodium.to_hex(decrypted);
    }
};

module.exports = TeaCrypto;
