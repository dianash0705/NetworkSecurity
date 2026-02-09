// renderer.js

let localApiPort = null;

// Placeholder for the Double Ratchet Session State.
// CRITICAL NOTE: In a working app, this MUST be initialized with real keys derived from X3DH.
// Sending "{}" causes the Python 'double_ratchet' library to crash (500 Error) because it expects keys like 'RK', 'CKs', etc.
// For now, we initialize it as "{}" just to pass the schema validation, but encryption will fail on the server side until real keys are present.
let currentSessionState = "{}"; 

// Helper function to convert string to Base64 (handles Unicode/Hebrew correctly)
function toBase64(str) {
    return btoa(unescape(encodeURIComponent(str)));
}

// Helper function to decode Base64 back to string
function fromBase64(str) {
    return decodeURIComponent(escape(atob(str)));
}

// 1. Receive port from Electron
if (window.electronAPI) {
    window.electronAPI.onSetPort((port) => {
        console.log(`[Encryption Service] Ready on port ${port}`);
        localApiPort = port;
    });
}

// 2. Expose "Encryption Service" to app.js via the window object
// renderer.js - פונקציית encrypt המתוקנת
window.EncryptionService = {
    encrypt: async (text, recipientId) => {
        if (!localApiPort) {
            console.error("Encryption service not ready yet");
            return null;
        }

        const stateB64 = toBase64(currentSessionState);
        const plaintextB64 = toBase64(text);
        const adB64 = toBase64(JSON.stringify({ to: recipientId }));

        try {
            const response = await fetch(`http://127.0.0.1:${localApiPort}/encrypt-message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    state_b64: stateB64,
                    plaintext_b64: plaintextB64,
                    authenticated_data_b64: adB64
                })
            });
            
            // --- התיקון כאן ---
            if (!response.ok) {
                // קוראים את התשובה כטקסט פעם אחת בלבד
                const rawError = await response.text();
                let errorObj;
                
                try {
                    // מנסים להמיר ל-JSON אם אפשר
                    errorObj = JSON.parse(rawError);
                } catch (e) {
                    // אם זה לא JSON, משתמשים בטקסט הגולמי
                    errorObj = rawError;
                }

                console.error(`Local encryption failed (Status ${response.status}):`, errorObj);
                throw new Error("Local encryption failed on server");
            }
            
            const data = await response.json(); 

            if (data.success) {
                currentSessionState = fromBase64(data.state_b64);
                return { 
                    encrypted_content: data.ciphertext_b64,
                    header: data.header_b64
                }; 
            } else {
                return null;
            }

        } catch (error) {
            console.error("Encryption Error:", error);
            return null;
        }
    }
};