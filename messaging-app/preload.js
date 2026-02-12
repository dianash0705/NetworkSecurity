const { contextBridge, ipcRenderer } = require('electron');
const path = require('path');

// Load TeaCrypto module (libsodium key generation + SealedBox decryption)
contextBridge.exposeInMainWorld('electronAPI', {
    onSetPort: (callback) => ipcRenderer.on('set-api-port', (event, port) => callback(port))
});