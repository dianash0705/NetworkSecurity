// renderer.js
let localApiPort = null;

// 1. קבלת הפורט מ-Electron
if (window.electronAPI) {
    window.electronAPI.onSetPort((port) => {
        console.log(`[Encryption Service] Ready on port ${port}`);
        localApiPort = port;
    });
}

// 2. חשיפת "שירות ההצפנה" ל-app.js דרך האובייקט window
window.EncryptionService = {
    encrypt: async (text, recipientId) => {
        if (!localApiPort) {
            console.error("Encryption service not ready yet");
            return null;
        }

        try {
            const response = await fetch(`http://127.0.0.1:${localApiPort}/encrypt-message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    text: text,
                    recipient_id: recipientId
                })
            });
            
            if (!response.ok) throw new Error("Local encryption failed");
            return await response.json(); // מחזיר { encrypted_content: "..." }

        } catch (error) {
            console.error("Encryption Error:", error);
            return null;
        }
    }
};