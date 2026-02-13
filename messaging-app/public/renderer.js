// renderer.js

let localApiPort = null;

// Per-conversation ratchet states stored in localStorage
// Key format: `teatime_ratchet_state_${currentUsername}_${recipientId}`
let currentUsername = null;
let conversationStates = {};  // Runtime cache: { recipientId -> state_b64 }

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

// Helper: Get storage key for a conversation
function getStateStorageKey(username, recipientId) {
    return `teatime_ratchet_state_${username}_${recipientId}`;
}

// Helper: Load ratchet state from localStorage (or undefined if not exists)
function loadRatchetState(username, recipientId) {
    const key = getStateStorageKey(username, recipientId);
    const stored = localStorage.getItem(key);
    if (stored) {
        conversationStates[recipientId] = stored;
        return stored;
    }
    return undefined;
}

// Helper: Save ratchet state to localStorage and memory
function saveRatchetState(username, recipientId, state_b64) {
    const key = getStateStorageKey(username, recipientId);
    localStorage.setItem(key, state_b64);
    conversationStates[recipientId] = state_b64;
}

async function fetchIdentityKeyB64(username) {
    const resp = await fetch(`${API_BASE}/get-identity-key/${encodeURIComponent(username)}`);
    if (resp.ok) {
        const data = await resp.json();
        return data.identity_key_public;
    } else {
        throw new Error(`Failed to fetch identity key for user ${username}, status: ${resp.status}`);
    }
}

// 2. Expose "Encryption Service" to app.js via the window object
window.EncryptionService = {
    setCurrentUsername: (username) => {
        currentUsername = username;
        conversationStates = {};
    },

    getLocalApiPort: () => localApiPort,

    initSenderRatchet: async (recipientId, shared_serret_b64, peer_dh_public_key_b64) => {
        if (!localApiPort) {
            console.error("Encryption service not ready yet");
            return false;
        }

        try {
            const response = await fetch(`http://127.0.0.1:${localApiPort}/init-sender-double-ratchet`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    shared_secret_b64: shared_serret_b64,
                    peer_dh_public_key_b64: peer_dh_public_key_b64,
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error(`[initSenderDoubleRatchet] Failed (Status ${response.status}):`, errorText);
                return false;
            }

            const data = await response.json();

            saveRatchetState(currentUsername, recipientId, data.state_b64);
            return true;
        } catch (error) {
            console.error("[initSenderDoubleRatchet] Error:", error);
            return false;
        }
    },

    initReceiverRatchet: async (recipientId, shared_serret_b64, self_dh_public_key_b64, self_dh_private_key_b64) => {
        if (!localApiPort) {
            console.error("Encryption service not ready yet");
            return false;
        }

        try {
            const response = await fetch(`http://127.0.0.1:${localApiPort}/init-receiver-double-ratchet`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    shared_secret_b64: shared_serret_b64,
                    self_dh_public_key_b64: self_dh_public_key_b64,
                    self_dh_private_key_b64: self_dh_private_key_b64,
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                console.error(`[initReceiverDoubleRatchet] Failed (Status ${response.status}):`, errorText);
                return false;
            }

            const data = await response.json();

            saveRatchetState(currentUsername, recipientId, data.state_b64);
            return true;
        } catch (error) {
            console.error("[initReceiverDoubleRatchet] Error:", error);
            return false;
        }
    },

    encrypt: async (text, recipientId) => {
        if (!localApiPort) {
            console.error("Encryption service not ready yet");
            return null;
        }

        if (!currentUsername) {
            console.error("currentUsername not set");
            return null;
        }

        // Load state from storage (or memory cache)
        let stateb64 = conversationStates[recipientId];
        if (!stateb64) {
            stateb64 = loadRatchetState(currentUsername, recipientId);
        }
        if (!stateb64) {
            console.error(`No ratchet state for conversation with ${recipientId}`);
            return null;
        }

        const plaintextB64 = toBase64(text);

        const senderIdentityKeyB64 = localStorage.getItem(`teatime_identity_pub_${currentUsername}`);
        const receiverIdentityKeyB64 = await fetchIdentityKeyB64(recipientId);
        const adB64 = toBase64(JSON.stringify({
          sender_identity_key_b64: senderIdentityKeyB64,
          receiver_identity_key_b64: receiverIdentityKeyB64,
        }));

        try {
            const response = await fetch(`http://127.0.0.1:${localApiPort}/encrypt-message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    state_b64: stateb64,
                    plaintext_b64: plaintextB64,
                    authenticated_data_b64: adB64
                })
            });

            if (!response.ok) {
                const rawError = await response.text();
                let errorObj;
                try {
                    errorObj = JSON.parse(rawError);
                } catch (e) {
                    errorObj = rawError;
                }
                console.error(`[encrypt] Local encryption failed (Status ${response.status}):`, errorObj);
                throw new Error("Local encryption failed on server");
            }

            const data = await response.json();

            if (data.success) {
                // Update state after encryption
                saveRatchetState(currentUsername, recipientId, data.state_b64);
                return {
                    encrypted_content: data.ciphertext_b64,
                    header: data.header_b64
                };
            } else {
                console.error("[encrypt] Server returned success: false");
                return null;
            }

        } catch (error) {
            console.error("[encrypt] Error:", error);
            return null;
        }
    },

    decrypt: async (headerB64, ciphertextB64, recipientId) => {
        /**
         * Decrypt a message received from recipientId.
         * recipientId: the sender of the message (from the receiver's perspective)
         */
        if (!localApiPort) {
            console.error("Encryption service not ready yet");
            return null;
        }

        if (!currentUsername) {
            console.error("currentUsername not set");
            return null;
        }

        // Load state for this conversation
        let stateb64 = conversationStates[recipientId];
        if (!stateb64) {
            stateb64 = loadRatchetState(currentUsername, recipientId);
        }
        if (!stateb64) {
            console.error(`No ratchet state for conversation with ${recipientId}`);
            return null;
        }

        const receiverIdentityKeyB64 = localStorage.getItem(`teatime_identity_pub_${currentUsername}`);
        const sender_identity_key_b64 = await fetchIdentityKeyB64(recipientId);

        const adB64 = toBase64(JSON.stringify({
          sender_identity_key_b64: sender_identity_key_b64,
          receiver_identity_key_b64: receiverIdentityKeyB64,
        }));

        try {
            const response = await fetch(`http://127.0.0.1:${localApiPort}/decrypt-message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    state_b64: stateb64,
                    header_b64: headerB64,
                    ciphertext_b64: ciphertextB64,
                    authenticated_data_b64: adB64
                })
            });

            if (!response.ok) {
                const rawError = await response.text();
                let errorObj;
                try {
                    errorObj = JSON.parse(rawError);
                } catch (e) {
                    errorObj = rawError;
                }
                console.error(`[decrypt] Failed (Status ${response.status}):`, errorObj);
                return null;
            }

            const data = await response.json();

            if (data.success) {
                // Update state after decryption
                saveRatchetState(currentUsername, recipientId, data.state_b64);
                return fromBase64(data.plaintext_b64);
            } else {
                console.error("[decrypt] Server returned success: false");
                return null;
            }

        } catch (error) {
            console.error("[decrypt] Error:", error);
            return null;
        }
    }
};