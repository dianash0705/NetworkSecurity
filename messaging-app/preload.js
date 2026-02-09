const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    onSetPort: (callback) => ipcRenderer.on('set-api-port', (event, port) => callback(port))
});