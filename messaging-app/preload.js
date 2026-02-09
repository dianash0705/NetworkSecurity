const { contextBridge, ipcRenderer } = require('electron');
const path = require('path');

// Load TeaCrypto module (libsodium key generation + SealedBox decryption)
let TeaCrypto;
try {
    TeaCrypto = require(path.join(__dirname, 'public', 'crypto.js'));
    console.log('[preload] TeaCrypto loaded successfully');
} catch (e) {
    console.error('[preload] Failed to load TeaCrypto:', e);
}

contextBridge.exposeInMainWorld('electronAPI', {
    onSetPort: (callback) => ipcRenderer.on('set-api-port', (event, port) => callback(port))
});

// Expose crypto functions to the renderer process
if (TeaCrypto) {
    contextBridge.exposeInMainWorld('TeaCrypto', {
        init: () => TeaCrypto.init(),
        generateKeyPair: () => TeaCrypto.generateKeyPair(),
        decryptChallenge: (encryptedB64, publicKeyB64, secretKeyB64) =>
            TeaCrypto.decryptChallenge(encryptedB64, publicKeyB64, secretKeyB64)
    });
} else {
    console.error('[preload] TeaCrypto not available - crypto functions will be undefined');
}