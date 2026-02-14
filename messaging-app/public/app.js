// API Base URL - FastAPI backend (use 127.0.0.1 to match server binding)
const API_BASE = 'http://127.0.0.1:8000';
const WS_BASE = 'ws://127.0.0.1:8000';

let currentUser = null;
let selectedContact = null;
let allUsers = [];  // List of friend usernames
let pollInterval = null;
let lastMessageId = 0;  // Track last seen message to detect new ones
let ws = null;  // WebSocket connection for real-time notifications

// Vibe emojis for user statuses
const vibeEmojis = ['🌸', '✨', '🌙', '🍃', '🦋', '🌺', '💫', '🌈', '🍀', '☁️', '🎀', '🧸'];

// DOM Elements
const usernameInput = document.getElementById('usernameInput');
const loginBtn = document.getElementById('loginBtn');
const loginSection = document.getElementById('loginSection');
const status = document.getElementById('status');
const app = document.getElementById('app');
const contactList = document.getElementById('contactList');
const chatWith = document.getElementById('chatWith');
const messagesDiv = document.getElementById('messages');
const messageInput = document.getElementById('messageInput');
const sendBtn = document.getElementById('sendBtn');
const inputArea = document.getElementById('inputArea');
const currentUserDisplay = document.getElementById('currentUserDisplay');

// Request browser notification permission
if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
}

// Wait for sidecar helper: resolves when `localApiPort` is set by the renderer/preload
async function waitForLocalApi(timeoutMs = 5000) {
    const start = Date.now();
    while (!localApiPort) {
        if (Date.now() - start > timeoutMs) {
            throw new Error('Local encryption sidecar not available');
        }
        await new Promise(r => setTimeout(r, 100));
    }
    return localApiPort;
}

// Login event listeners
loginBtn.addEventListener('click', login);
usernameInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') login(); });

async function login() {
    const username = usernameInput.value.trim();
    if (!username) return;

    currentUser = username;
    status.textContent = '🔄 Connecting...';
    
    try {
        // Wait for the local encryption sidecar to be available
        await waitForLocalApi();

        // Step 1: Check if user already exists
        const existsRes = await fetch(`${API_BASE}/user-exists/${encodeURIComponent(username)}`);
        const existsData = await existsRes.json();

        if (existsData.exists) {
            // --- Existing user: challenge-response authentication ---
            status.textContent = '🔐 Authenticating...';

            // Load stored private key from localStorage
            const storedPub = localStorage.getItem(`teatime_identity_pub_${username}`);
            const storedSec = localStorage.getItem(`teatime_identity_sec_${username}`);

            if (!storedPub || !storedSec) {
                status.textContent = '❌ No identity key found for this user on this device';
                status.classList.add('error');
                currentUser = null;
                return;
            }

            console.log(`[AUTH] ${username} authenticated`);

        } else {
            // --- New user: generate keys via sidecar and register ---
            status.textContent = '🔑 Generating identity keys...';

            // Call the local sidecar service to generate X3DH identity key pair
            let keyPair;
            try {
                const keyGenRes = await fetch(`http://127.0.0.1:${localApiPort}/x3dh-create-identity-key`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });

                if (!keyGenRes.ok) {
                    throw new Error('Failed to generate keys from sidecar');
                }

                const keyGenData = await keyGenRes.json();
                keyPair = keyGenData.x3dh_identity_key; // { identity_key_private_b64, identity_key_public_b64 }
            } catch (e) {
                console.error('Key generation error:', e);
                status.textContent = '❌ Failed to generate identity keys';
                status.classList.add('error');
                currentUser = null;
                return;
            }

            // Store identity keys in localStorage (private key stays local)
            localStorage.setItem(`teatime_identity_pub_${username}`, keyPair.identity_key_public_b64);
            localStorage.setItem(`teatime_identity_sec_${username}`, keyPair.identity_key_private_b64);
            // Store Ed25519 signing keypair
            if (keyPair.signing_key_public_b64) {
                localStorage.setItem(`teatime_signing_pub_${username}`, keyPair.signing_key_public_b64);
            }
            if (keyPair.signing_key_private_b64) {
                localStorage.setItem(`teatime_signing_priv_${username}`, keyPair.signing_key_private_b64);
            }

            // --- Generate a signed prekey via sidecar ---
            let prekeyData = null;
            try {
                const prekeyRes = await fetch(`http://127.0.0.1:${localApiPort}/x3dh-create-new-prekey`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ x3dh_identity_key: keyPair })
                });

                if (!prekeyRes.ok) throw new Error('prekey generation failed');
                prekeyData = await prekeyRes.json();
            } catch (e) {
                console.error('Prekey generation error:', e);
                status.textContent = '❌ Failed to generate prekey';
                status.classList.add('error');
                currentUser = null;
                return;
            }

            // Store prekey private locally and extract public/signature for server
            const prekeyPrivB64 = prekeyData.prekey_private_b64;
            const prekeyPubB64 = prekeyData.prekey_public_b64;
            const prekeySigB64 = prekeyData.prekey_signature_b64;
            localStorage.setItem(`teatime_signed_prekey_priv_${username}`, prekeyPrivB64);
            localStorage.setItem(`teatime_signed_prekey_pub_${username}`, prekeyPubB64);
            
            // --- Generate one-time keys via sidecar ---
            let onetimeKeysData = null;
            try {
                const otkRes = await fetch(`http://127.0.0.1:${localApiPort}/x3dh-create-onetime-keys`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ number_of_keys: 10 })
                });

                if (!otkRes.ok) throw new Error('onetime keys generation failed');
                onetimeKeysData = await otkRes.json();
            } catch (e) {
                console.error('Onetime keys generation error:', e);
                status.textContent = '❌ Failed to generate one-time keys';
                status.classList.add('error');
                currentUser = null;
                return;
            }

            // Save private one-time keys locally and prepare public-only array for server
            const otkPairs = [];
            const onetimePubs = [];
            for (const k of onetimeKeysData.onetime_keys) {
                otkPairs.push({
                    public_b64: k.onetime_key_public_b64,
                    private_b64: k.onetime_key_private_b64,
                });

                onetimePubs.push(k.onetime_key_public_b64);
            }
            localStorage.setItem(
                `teatime_onetime_keypairs_${username}`,
                JSON.stringify(otkPairs)
            );

            // Register with the server (send only public key material)
            const response = await fetch(`${API_BASE}/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: username,
                    public_key: keyPair.identity_key_public_b64,
                    identity_key_public: keyPair.identity_key_public_b64,
                    prekey_public: prekeyPubB64,
                    prekey_signature_public: prekeySigB64,
                    signing_key_public: keyPair.signing_key_public_b64,
                    onetime_keys_public: onetimePubs
                })
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.detail || 'Registration failed');
            }

            console.log(`[AUTH] ${username} registered with new identity key`);
        }

        // --- Authentication successful — enter the app ---
        status.textContent = `✨ Connected as ${currentUser}`;
        
        // Set username in encryption service immediately
        if (window.EncryptionService) {
            window.EncryptionService.setCurrentUsername(currentUser);
        }

        usernameInput.disabled = true;
        loginBtn.disabled = true;
        loginSection.style.display = 'none';
        app.style.display = 'block';
        currentUserDisplay.textContent = `Logged in as ${currentUser}`;
        
        // Fetch friends list from backend
        await fetchFriends();
        
        // Connect WebSocket for real-time notifications
        connectWebSocket();
        
        // Start polling for new messages (as fallback)
        startMessagePolling();

    } catch (error) {
        console.error('Login error:', error);
        status.textContent = `❌ ${error.message || 'Server not available'}`;
        status.classList.add('error');
        currentUser = null;
    }
}

function getRandomVibe() {
    return vibeEmojis[Math.floor(Math.random() * vibeEmojis.length)];
}

// --- WebSocket Connection for Real-Time Notifications ---
function connectWebSocket() {
    if (ws) {
        ws.close();
    }
    
    ws = new WebSocket(`${WS_BASE}/ws/${currentUser}`);
    
    ws.onopen = () => {
        console.log('🔌 WebSocket connected for real-time notifications');
        // Send periodic pings to keep connection alive
        setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send('ping');
            }
        }, 30000);
    };
    
    ws.onmessage = async (event) => {
        try {
            const data = JSON.parse(event.data);
            console.log('📨 WebSocket message received:', data);
            
            if (data.type === 'new_message') {
                let notificationText = data.encrypted_content;

                // Attempt to decrypt for notification
                if (window.EncryptionService) {
                    window.EncryptionService.setCurrentUsername(currentUser);
                    try {
                        // Check cache first
                        const cached = getDecryptedMessage(data.message_id);
                        if (cached) {
                            notificationText = cached;
                        } else {
                            if (data.x3dh_ephemeral_public_b64) {
                                await handleReceiverX3DH(data.sender, data.x3dh_ephemeral_public_b64, data.one_time_key_public_b64);
                            }
                            const decrypted = await window.EncryptionService.decrypt(
                                data.header_b64,
                                data.encrypted_content,
                                data.sender
                            );
                            if (decrypted) {
                                notificationText=decrypted;
                                saveDecryptedMessage(data.message_id, decrypted);
                            } else {
                                console.log(`⚠️ Could not decrypt message from ${data.sender}`);
                            }
                        }
                    } catch (e) { console.error('WS Decrypt error:', e); }
                }

                // Show popup notification
                showNotification(data.sender, notificationText);
                
                // If we're currently viewing the conversation with this sender, refresh it
                if (selectedContact === data.sender) {
                    loadConversationFromBackend(data.sender);
                }
            } else if (data.type === 'new_friend') {
                // Someone added us as a friend
                if (!allUsers.includes(data.username)) {
                    allUsers.push(data.username);
                    renderContacts();
                    showNotification(data.username, `${data.username} added you as a friend! 🎉`);
                }
            }
        } catch (e) {
            // Ignore non-JSON messages (like "pong")
            console.log('WS:', event.data);
        }
    };
    
    ws.onclose = () => {
        console.log('🔌 WebSocket disconnected, reconnecting in 3s...');
        setTimeout(() => {
            if (currentUser) {
                connectWebSocket();
            }
        }, 3000);
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
}

function getInitials(name) {
    return name.charAt(0).toUpperCase();
}

// Fetch friends list from backend
async function fetchFriends() {
    try {
        const response = await fetch(`${API_BASE}/friends/${currentUser}`);
        if (response.ok) {
            const data = await response.json();
            allUsers = data.friends.map(f => f.username);
        }
    } catch (error) {
        console.error('Error fetching friends:', error);
    }
    renderContacts();
}

// Helper: Save sent message plaintext locally (since server only has encrypted)
function saveSentMessage(encryptedContent, plaintext) {
    try {
        const key = `teatime_sent_map_${currentUser}`;
        let map = {};
        const stored = localStorage.getItem(key);
        if (stored) {
            map = JSON.parse(stored);
        }
        map[encryptedContent] = plaintext;
        localStorage.setItem(key, JSON.stringify(map));
    } catch (e) {
        console.error("Failed to save sent message plaintext:", e);
    }
}

// Helper: Get sent message plaintext
function getSentMessage(encryptedContent) {
    try {
        const key = `teatime_sent_map_${currentUser}`;
        const stored = localStorage.getItem(key);
        if (stored) {
            const map = JSON.parse(stored);
            return map[encryptedContent];
        }
    } catch (e) {
        return null;
    }
    return null;
}

// Helper: Save decrypted received message plaintext locally
function saveDecryptedMessage(messageId, plaintext) {
    if (!messageId) return;
    try {
        const key = `teatime_decrypted_map_${currentUser}`;
        let map = {};
        const stored = localStorage.getItem(key);
        if (stored) {
            map = JSON.parse(stored);
        }
        map[messageId] = plaintext;
        localStorage.setItem(key, JSON.stringify(map));
    } catch (e) {
        console.error("Failed to save decrypted message:", e);
    }
}

// Helper: Get decrypted received message plaintext
function getDecryptedMessage(messageId) {
    if (!messageId) return null;
    try {
        const key = `teatime_decrypted_map_${currentUser}`;
        const stored = localStorage.getItem(key);
        if (stored) {
            const map = JSON.parse(stored);
            return map[messageId];
        }
    } catch (e) {
        return null;
    }
    return null;
}

function consumeOnetimePrivateForPublic(currentUser, publicB64) {
  const key = `teatime_onetime_keypairs_${currentUser}`;
  const raw = localStorage.getItem(key);

  if (!raw) {
    throw new Error(
      `[OTK] No one-time key store found for ${currentUser}`
    );
  }

  let pairs;
  try {
    pairs = JSON.parse(raw);
  } catch (e) {
    throw new Error(
      `[OTK] Corrupted one-time key store for ${currentUser}: ${e.message}`
    );
  }

  if (!Array.isArray(pairs)) {
    throw new Error(`[OTK] Invalid keypair format (expected array)`);
  }

  const idx = pairs.findIndex(
    p => p.public_b64 === publicB64
  );

  if (idx === -1) {
    throw new Error(
      `[OTK] No matching private key for public=${publicB64}...`
    );
  }

  const priv = pairs[idx].private_b64;

  if (!priv) {
    throw new Error(`[OTK] Matched entry but private key missing`);
  }

  // consume it
  pairs.splice(idx, 1);
  localStorage.setItem(key, JSON.stringify(pairs));

  console.log(`[OTK] Consumed one-time key for ${currentUser}`);
  return priv;
}


// Helper: Handle X3DH Receiver Flow
async function handleReceiverX3DH(senderName, ephemeralKey, oneTimeKeyPublicB64) {
    try {
        // Ensure username is set in encryption service
        if (window.EncryptionService) {
            window.EncryptionService.setCurrentUsername(currentUser);
        }

        // Check if we already have a state for this user to avoid re-consuming keys
        const stateKey = `teatime_ratchet_state_${currentUser}_${senderName}`;
        if (localStorage.getItem(stateKey)) {
            return true; // Already initialized
        }

        console.log(`[X3DH] Attempting to initialize receiver session for ${senderName}...`);

        // Get our stored keys
        const ourIdentityPrivate = localStorage.getItem(`teatime_identity_sec_${currentUser}`);
        const ourPrekeyPrivate = localStorage.getItem(`teatime_signed_prekey_priv_${currentUser}`);
        const ourPrekeyPublic = localStorage.getItem(`teatime_signed_prekey_pub_${currentUser}`);

        const remote_identity_key_public = await fetchIdentityKeyB64(senderName);

        let ourOnetimePrivate = consumeOnetimePrivateForPublic(currentUser, oneTimeKeyPublicB64);

        if (!ourIdentityPrivate) {
            console.error("Missing our identity private key for X3DH receiver");
            return false;
        }

        if(!ourPrekeyPrivate) {
            console.error("Missing our ourPrekeyPrivate for X3DH receiver");
            return false;
        }

        if(!ourPrekeyPublic) {
            console.error("Missing our ourPrekeyPublic for X3DH receiver");
            return false;
        }

        // Call X3DH receiver via sidecar
        const localApiPort = window.EncryptionService.getLocalApiPort();
        if (!localApiPort) {
            console.error("Local API port not available");
            return false;
        }

        console.log("[X3DH Receiver] Calling sidecar with:", {
                self_identity_key_private_b64: ourIdentityPrivate,
                self_prekey_private_b64: ourPrekeyPrivate,
                self_onetime_key_private_b64: ourOnetimePrivate,
                peer_identity_key_public_b64: remote_identity_key_public,
                peer_ephemeral_key_public_b64: ephemeralKey
        });

        const x3dhReceiverResp = await fetch(`http://127.0.0.1:${localApiPort}/do-x3dh-by-receiver`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                self_identity_key_private_b64: ourIdentityPrivate,
                self_prekey_private_b64: ourPrekeyPrivate,
                self_onetime_key_private_b64: ourOnetimePrivate,
                peer_identity_key_public_b64: remote_identity_key_public,
                peer_ephemeral_key_public_b64: ephemeralKey
            })
        });

        if (!x3dhReceiverResp.ok) {
            console.error('X3DH receiver failed sidecar call');
            return false;
        }

        const x3dhReceiverResult = await x3dhReceiverResp.json();
        const sharedSecret = x3dhReceiverResult.shared_secret_key_b64;

        // Initialize ratchet as receiver
        const initRatchetSuccess = await window.EncryptionService.initReceiverRatchet(
            senderName,
            sharedSecret,
            ourPrekeyPublic,
            ourPrekeyPrivate
        );

        if (initRatchetSuccess) {
            console.log(`[X3DH] Successfully initialized session with ${senderName}`);
            return true;
        }
    } catch (e) {
        console.error("[X3DH] Error in handleReceiverX3DH:", e);
    }
    return false;
}

// Add a friend (server-validated: must be a registered user)
async function addFriend(friendUsername) {
    if (!friendUsername || friendUsername === currentUser) return;
    
    if (allUsers.includes(friendUsername)) {
        alert(`${friendUsername} is already your friend!`);
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/add-friend`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: currentUser,
                friend_username: friendUsername
            })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            if (result.status === 'already_friends') {
                alert(result.message);
            } else {
                // New friendship established! 
                // Clear any stale encryption state to ensure a fresh X3DH handshake
                const stateKey = `teatime_ratchet_state_${currentUser}_${friendUsername}`;
                if (localStorage.getItem(stateKey)) {
                    console.log(`[addFriend] Clearing stale ratchet state for ${friendUsername}`);
                    localStorage.removeItem(stateKey);
                }

                allUsers.push(friendUsername);
                renderContacts();
            }
        } else {
            alert(result.detail || 'Failed to add friend');
        }
    } catch (error) {
        console.error('Error adding friend:', error);
        alert('Server error. Please try again.');
    }
}

function addUserToList(username) {
    if (!allUsers.includes(username) && username !== currentUser) {
        allUsers.push(username);
        renderContacts();
    }
}

// Show notification popup
let notificationCount = 0;

function showNotification(sender, message) {
    console.log(`🔔 SHOWING NOTIFICATION from ${sender}: ${message}`);
    
    // Debug alert - remove after testing
    // alert(`New message from ${sender}: ${message}`);
    
    // Calculate position for stacking notifications
    const offset = notificationCount * 90;
    notificationCount++;
    
    // In-app notification toast
    const toast = document.createElement('div');
    toast.className = 'notification-toast';
    toast.style.cssText = `
        position: fixed;
        top: ${20 + offset}px;
        right: 20px;
        background: white;
        border-radius: 16px;
        padding: 16px 20px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
        display: flex;
        align-items: center;
        gap: 12px;
        z-index: 99999;
        cursor: pointer;
        max-width: 320px;
        border-left: 4px solid #98FB98;
        animation: slideIn 0.3s ease-out;
    `;
    toast.innerHTML = `
        <div style="width: 44px; height: 44px; border-radius: 50%; background: linear-gradient(135deg, #FFDAB9, #FFE4EC); display: flex; align-items: center; justify-content: center; font-size: 18px; font-weight: 700;">${getInitials(sender)}</div>
        <div style="flex: 1; min-width: 0;">
            <div style="font-weight: 700; font-size: 14px; margin-bottom: 2px;">${sender}</div>
            <div style="color: #8E8A9D; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(message.substring(0, 50))}${message.length > 50 ? '...' : ''}</div>
        </div>
        <button style="background: none; border: none; cursor: pointer; padding: 4px; font-size: 14px; opacity: 0.6;" class="notification-close">✕</button>
    `;
    
    // Click to open conversation
    toast.onclick = (e) => {
        if (!e.target.classList.contains('notification-close')) {
            addUserToList(sender);
            selectContact(sender);
            removeToast(toast);
        }
    };
    
    toast.querySelector('.notification-close').onclick = (e) => {
        e.stopPropagation();
        removeToast(toast);
    };
    
    document.body.appendChild(toast);
    console.log(`✅ Toast appended to body`);
    
    // Play notification sound (optional visual flash as fallback)
    try {
        document.body.style.boxShadow = 'inset 0 0 100px rgba(152, 251, 152, 0.5)';
        setTimeout(() => { document.body.style.boxShadow = ''; }, 300);
    } catch (e) {}
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            removeToast(toast);
        }
    }, 5000);
    
    // Browser notification
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(`🍵 New message from ${sender}`, {
            body: message.substring(0, 100),
            icon: 'icon.png'
        });
    }
}

function removeToast(toast) {
    toast.classList.add('fade-out');
    setTimeout(() => {
        toast.remove();
        notificationCount = Math.max(0, notificationCount - 1);
    }, 300);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function renderContacts() {
    contactList.innerHTML = '';
    
    if (allUsers.length === 0) {
        contactList.innerHTML = `
            <div style="text-align: center; padding: 20px; color: var(--text-secondary);">
                <div style="font-size: 32px; margin-bottom: 8px;">🌙</div>
                <p>No friends yet...</p>
                <input type="text" id="newContactInput" placeholder="Enter username" 
                    style="margin-top: 12px; padding: 8px 12px; border: 2px solid var(--lavender-dark); 
                    border-radius: 12px; font-family: inherit; font-size: 12px; width: 100%;">
                <button id="addContactBtn" 
                    style="margin-top: 8px; padding: 8px 16px; border: none; border-radius: 12px; 
                    background: var(--mint); cursor: pointer; font-family: inherit; font-weight: 600;">
                    Add Friend 🌸
                </button>
                <div id="addFriendError" style="margin-top: 8px; font-size: 12px; color: var(--peach-dark);"></div>
            </div>
        `;
        
        setTimeout(() => {
            const addBtn = document.getElementById('addContactBtn');
            const input = document.getElementById('newContactInput');
            if (addBtn && input) {
                addBtn.onclick = () => {
                    const name = input.value.trim();
                    if (name) addFriend(name);
                };
                input.onkeypress = (e) => {
                    if (e.key === 'Enter') {
                        const name = input.value.trim();
                        if (name) addFriend(name);
                    }
                };
            }
        }, 0);
        return;
    }

    // Add contact input at top
    const addSection = document.createElement('div');
    addSection.style.cssText = 'margin-bottom: 16px; display: flex; gap: 8px;';
    addSection.innerHTML = `
        <input type="text" id="newContactInput" placeholder="Add friend..." 
            style="flex: 1; padding: 8px 12px; border: 2px solid var(--lavender-dark); 
            border-radius: 12px; font-family: inherit; font-size: 12px;">
        <button id="addContactBtn" 
            style="padding: 8px 12px; border: none; border-radius: 12px; 
            background: var(--mint); cursor: pointer; font-size: 14px;">➕</button>
    `;
    contactList.appendChild(addSection);

    setTimeout(() => {
        const addBtn = document.getElementById('addContactBtn');
        const input = document.getElementById('newContactInput');
        if (addBtn && input) {
            addBtn.onclick = () => {
                const name = input.value.trim();
                if (name) {
                    addFriend(name);
                    input.value = '';
                }
            };
            input.onkeypress = (e) => {
                if (e.key === 'Enter') {
                    const name = input.value.trim();
                    if (name) {
                        addFriend(name);
                        input.value = '';
                    }
                }
            };
        }
    }, 0);

    allUsers.forEach(user => {
        const div = document.createElement('div');
        div.className = 'contact' + (user === selectedContact ? ' active' : '');
        const vibe = getRandomVibe();
        
        div.innerHTML = `
            <div class="contact-avatar">${getInitials(user)}</div>
            <div class="contact-info">
                <div class="contact-name">${user}</div>
            </div>
            <span class="contact-vibe">${vibe}</span>
        `;
        div.onclick = () => selectContact(user);
        contactList.appendChild(div);
    });
}

async function selectContact(user) {
    selectedContact = user;
    lastMessageId = 0;  // Reset to load all messages for this conversation
    
    updateChatHeader(user);
    
    messagesDiv.style.display = 'flex';
    inputArea.style.display = 'flex';
    messageInput.disabled = false;
    sendBtn.disabled = false;
    renderContacts();
    
    // Load conversation history from backend
    await loadConversationFromBackend(user);
    messageInput.focus();
}

function updateChatHeader(user) {
    const isVerified = localStorage.getItem(`teatime_verified_${currentUser}_${user}`) === 'true';
    chatWith.innerHTML = `
        <div class="chat-header-avatar">${getInitials(user)}</div>
        <div class="chat-header-info">
            <h3>${user}</h3>
        </div>
        <button class="chat-header-security-btn${isVerified ? ' is-verified' : ''}" id="securityBtn" title="Security Verification">
            🔒 ${isVerified ? 'Verified' : 'Encryption'}
        </button>
    `;
    // Attach click handler for security button
    const secBtn = document.getElementById('securityBtn');
    if (secBtn) {
        secBtn.addEventListener('click', () => openSecurityVerification(user));
    }
}

// ============================================================================
// SECURITY VERIFICATION MODAL
// ============================================================================

async function fetchIdentityKeyB64(username) {
    const resp = await fetch(`${API_BASE}/get-identity-key/${encodeURIComponent(username)}`);
    if (resp.ok) {
        const data = await resp.json();
        return data.identity_key_public;
    } else {
        throw new Error(`Failed to fetch identity key for user ${username}, status: ${resp.status}`);
    }
}

/**
 * Open the Security Verification modal for a given contact.
 */
async function openSecurityVerification(contact) {
    // 1. Gather identity keys
    const selfKeyB64 = localStorage.getItem(`teatime_identity_pub_${currentUser}`);
    let peerKeyB64 = null;

    try {
        const resp = await fetch(`${API_BASE}/get-identity-key/${encodeURIComponent(contact)}`);
        if (resp.ok) {
            const data = await resp.json();
            peerKeyB64 = data.identity_key_public;
        }
    } catch (e) {
        console.error('Failed to fetch peer identity key:', e);
    }

    if (!selfKeyB64 || !peerKeyB64) {
        alert('Could not retrieve identity keys for security verification.');
        return;
    }

    // 2. Check current verification state
    const verifiedKey = `teatime_verified_${currentUser}_${contact}`;
    const isVerified = localStorage.getItem(verifiedKey) === 'true';

    // 3. Build and show modal
    const overlay = document.createElement('div');
    overlay.className = 'security-overlay';
    overlay.id = 'securityOverlay';

    overlay.innerHTML = `
        <div class="security-modal">
            <div class="security-modal-header">
                <div class="lock-icon">🔒</div>
                <div class="header-text">
                    <h2>Encryption</h2>
                    <p>Chat with ${escapeHtml(contact)}</p>
                </div>
                <button class="security-modal-close" id="securityModalClose">✕</button>
            </div>
            <div class="security-modal-body">
                <div class="security-info-text">
                    <span class="e2e-badge">🔐 E2E</span>
                    Messages and calls are secured with <strong>end-to-end encryption</strong>.
                    Only you and <strong>${escapeHtml(contact)}</strong> can read or listen to them.
                    Not even the server can access your messages.
                </div>

                <div class="identity-key-section" id="identityKeySection">
                    <button class="key-toggle-btn" id="keyToggleBtn">🔑 Show Identity Keys</button>
                    <div id="identityKeysContainer" style="display:none; flex-direction:column; gap:10px;">
                        <div class="identity-key-card self">
                            <div class="key-card-header">
                                <div class="key-avatar">${getInitials(currentUser)}</div>
                                <span class="key-label">${escapeHtml(currentUser)}</span>
                                <span class="key-tag">You</span>
                            </div>
                            <div class="identity-key-raw">${escapeHtml(selfKeyB64)}</div>
                        </div>
                        <div class="identity-key-card peer">
                            <div class="key-card-header">
                                <div class="key-avatar">${getInitials(contact)}</div>
                                <span class="key-label">${escapeHtml(contact)}</span>
                                <span class="key-tag">Contact</span>
                            </div>
                            <div class="identity-key-raw">${escapeHtml(peerKeyB64)}</div>
                        </div>
                    </div>
                </div>

                <div class="verify-section">
                    <button class="verify-btn ${isVerified ? 'verified' : 'unverified'}" id="verifyIdentityBtn">
                        ${isVerified ? '✅  Identity Verified' : '🛡️  Mark as Verified'}
                    </button>
                    <div class="verify-status-text" id="verifyStatusText">
                        ${isVerified
                            ? 'You have verified this contact\u2019s identity. You will be notified if their security key changes.'
                            : 'Compare the safety numbers above with your contact to verify their identity.'}
                    </div>
                </div>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    // --- Event handlers ---
    // Close
    document.getElementById('securityModalClose').addEventListener('click', closeSecurityModal);
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) closeSecurityModal();
    });

    // Toggle raw keys
    document.getElementById('keyToggleBtn').addEventListener('click', () => {
        const container = document.getElementById('identityKeysContainer');
        const btn = document.getElementById('keyToggleBtn');
        if (container.style.display === 'none') {
            container.style.display = 'flex';
            btn.textContent = '🔑 Hide Identity Keys';
        } else {
            container.style.display = 'none';
            btn.textContent = '🔑 Show Identity Keys';
        }
    });

    // Verify / Unverify button
    document.getElementById('verifyIdentityBtn').addEventListener('click', () => {
        const btn = document.getElementById('verifyIdentityBtn');
        const statusText = document.getElementById('verifyStatusText');
        const currentlyVerified = localStorage.getItem(verifiedKey) === 'true';

        if (currentlyVerified) {
            // Unverify
            localStorage.removeItem(verifiedKey);
            btn.className = 'verify-btn unverified';
            btn.innerHTML = '🛡️  Mark as Verified';
            statusText.textContent = 'Compare the safety numbers above with your contact to verify their identity.';
        } else {
            // Verify
            localStorage.setItem(verifiedKey, 'true');
            btn.className = 'verify-btn verified';
            btn.innerHTML = '✅  Identity Verified';
            statusText.textContent = 'You have verified this contact\u2019s identity. You will be notified if their security key changes.';
        }

        // Update header button state
        updateChatHeader(contact);

        // Re-attach close handler since header was re-rendered
        // (The overlay is still in the DOM, not affected by the header re-render)
    });
}

function closeSecurityModal() {
    const overlay = document.getElementById('securityOverlay');
    if (overlay) {
        overlay.remove();
    }
}

// Helper: Save sent message plaintext locally (since server only has encrypted)
function saveSentMessage(encryptedContent, plaintext) {
    try {
        const key = `teatime_sent_map_${currentUser}`;
        let map = {};
        const stored = localStorage.getItem(key);
        if (stored) {
            map = JSON.parse(stored);
        }
        map[encryptedContent] = plaintext;
        localStorage.setItem(key, JSON.stringify(map));
    } catch (e) {
        console.error("Failed to save sent message plaintext:", e);
    }
}

// Helper: Get sent message plaintext
function getSentMessage(encryptedContent) {
    try {
        const key = `teatime_sent_map_${currentUser}`;
        const stored = localStorage.getItem(key);
        if (stored) {
            const map = JSON.parse(stored);
            return map[encryptedContent];
        }
    } catch (e) {
        return null;
    }
    return null;
}

// Load conversation from backend
async function loadConversationFromBackend(contact) {
    // Ensure username is set in encryption service before rendering/decrypting
    if (window.EncryptionService) {
        window.EncryptionService.setCurrentUsername(currentUser);
    }

    try {
        const response = await fetch(`${API_BASE}/conversation/${currentUser}/${contact}`);
        if (response.ok) {
            const messages = await response.json();
            // Update lastMessageId to track what we've seen
            if (messages.length > 0) {
                lastMessageId = Math.max(...messages.map(m => m.id));
            }
                await renderMessages(messages);
        } else {
            renderMessages([]);
        }
    } catch (error) {
        console.error('Error loading conversation:', error);
        renderMessages([]);
    }
}

// Send message event listeners
sendBtn.addEventListener('click', sendMessage);
messageInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendMessage(); });

async function sendMessage() {
    const content = messageInput.value.trim();
    if (!content || !selectedContact) return;

    try {
        // Encryption service must be loaded
        if (!window.EncryptionService) {
            alert("Encryption service not loaded!");
            return;
        }

        // Set username in encryption service (for per-conversation state management)
        window.EncryptionService.setCurrentUsername(currentUser);

        // Check if this is the first message to this recipient
        const stateKey = `teatime_ratchet_state_${currentUser}_${selectedContact}`;
        const hasRatchetState = !!localStorage.getItem(stateKey);

        if (!hasRatchetState) {
            // FIRST MESSAGE: Perform X3DH initiator flow
            console.log(`[sendMessage] First message to ${selectedContact}, performing X3DH...`);
            
            // Fetch peer's key bundle
            const preKeyBundleResponse = await fetch(`${API_BASE}/get-prekey-bundle/${selectedContact}`);
            if (!preKeyBundleResponse.ok) {
                alert("Failed to get peer's key bundle");
                return;
            }
            const preKeyBundle = await preKeyBundleResponse.json();
            
            // Get our identity keys from localStorage
            const ourIdentityPrivate = localStorage.getItem(`teatime_identity_sec_${currentUser}`);
            const ourIdentityPublic = localStorage.getItem(`teatime_identity_pub_${currentUser}`);
            
            if (!ourIdentityPrivate || !ourIdentityPublic) {
                alert("Your identity keys not found locally!");
                return;
            }

            // Call X3DH initiator via sidecar
            const localApiPort = window.EncryptionService.getLocalApiPort();
            if (!localApiPort) {
                alert("Local encryption sidecar not available");
                return;
            }

            const x3dhInitiatorResp = await fetch(`http://127.0.0.1:${localApiPort}/do-x3dh-by-initiator`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    self_identity_key_b64: ourIdentityPrivate,
                    self_identity_key_public_b64: ourIdentityPublic,
                    peer_identity_key_public_b64: preKeyBundle.identity_key_public,
                    peer_prekey_public_b64: preKeyBundle.prekey_public,
                    peer_prekey_signature_b64: preKeyBundle.prekey_signature_public,
                    peer_onetime_prekey_public_b64: preKeyBundle.onetime_key_public,
                })
            });

            if (!x3dhInitiatorResp.ok) {
                // Try to extract detailed error from sidecar response (JSON.detail or raw text)
                let detailText = '';
                try {
                    const txt = await x3dhInitiatorResp.text();
                    try {
                        const parsed = JSON.parse(txt);
                        detailText = parsed.detail || JSON.stringify(parsed);
                    } catch (e) {
                        detailText = txt;
                    }
                } catch (e) {
                    detailText = String(e);
                }
                console.error('X3DH initiator failed:', detailText);
                status.textContent = `❌ X3DH initiator failed: ${detailText.substring(0,200)}`;
                status.classList.add('error');
                alert('X3DH initiator failed: ' + detailText);
                return;
            }

            const x3dhInitiatorResult = await x3dhInitiatorResp.json();

            // Initialize ratchet as sender
            const sharedSecret = x3dhInitiatorResult.shared_secret_key_b64;
            const ephemeralPublic = x3dhInitiatorResult.self_ephemeral_key_public_b64;
            const associatedData = x3dhInitiatorResult.associated_data_b64;

            const initRatchetSuccess = await window.EncryptionService.initSenderRatchet(
                selectedContact,
                sharedSecret,
                preKeyBundle.prekey_public,  // Receiver's DH public key for sender initialization
            );

            if (!initRatchetSuccess) {
                alert("Ratchet initialization failed");
                return;
            }

            console.log("[sendMessage] Ratchet initialized, proceeding with encryption...");

            // Now encrypt the message with the newly initialized ratchet
            const encryptionResult = await window.EncryptionService.encrypt(content, selectedContact);

            if (!encryptionResult) {
                alert("Failed to encrypt message locally.");
                return;
            }

            // Save plaintext locally for history display
            saveSentMessage(encryptionResult.encrypted_content, content);

            // Send with X3DH ephemeral key and associated data (first message only)
            const messageData = {
                sender: currentUser,
                receiver: selectedContact,
                encrypted_content: encryptionResult.encrypted_content,
                header_b64: encryptionResult.header,
                x3dh_ephemeral_public_b64: ephemeralPublic,
                x3dh_associated_data_b64: associatedData,
                one_time_key_public_b64: preKeyBundle.onetime_key_public
            };
            console.log("[sendMessage] Sending message with X3DH data:", messageData);

            const response = await fetch(`${API_BASE}/send-message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(messageData)
            });

            if (response.ok) {
                const localMsg = {
                    sender: currentUser,
                    receiver: selectedContact,
                    encrypted_content: content,
                    timestamp: new Date().toISOString()
                };
                
                await appendMessage(localMsg);
                messageInput.value = '';
                addUserToList(selectedContact);
                await loadConversationFromBackend(selectedContact);
            } else {
                alert('Failed to send: ' + response.status + ' - ' + response.statusText);
            }

        } else {
            // SUBSEQUENT MESSAGES: Just encrypt with existing ratchet state
            console.log(`[sendMessage] Subsequent message to ${selectedContact}`);

            const encryptionResult = await window.EncryptionService.encrypt(content, selectedContact);

            if (!encryptionResult) {
                alert("Failed to encrypt message locally.");
                return;
            }

            // Save plaintext locally for history display
            saveSentMessage(encryptionResult.encrypted_content, content);

            const messageData = {
                sender: currentUser,
                receiver: selectedContact,
                encrypted_content: encryptionResult.encrypted_content,
                header_b64: encryptionResult.header
            };

            const response = await fetch(`${API_BASE}/send-message`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(messageData)
            });

            if (response.ok) {
                const localMsg = {
                    sender: currentUser,
                    receiver: selectedContact,
                    encrypted_content: content,
                    timestamp: new Date().toISOString()
                };
                
                await appendMessage(localMsg);
                messageInput.value = '';
                addUserToList(selectedContact);
                await loadConversationFromBackend(selectedContact);
            } else {
                const error = await response.json();
                alert('Failed to send: ' + error.detail);
            }
        }

    } catch (error) {
        console.error('Send error:', error);
    }
}
// Poll for new messages
function startMessagePolling() {
    // Poll every 2s as fallback (WebSocket handles real-time)
    pollInterval = setInterval(pollForUpdates, 2000);
    pollForUpdates(); // Fetch immediately
}

// Main polling function - checks for new messages in current conversation
async function pollForUpdates() {
    if (!currentUser) return;

    try {
        // If viewing a conversation, poll that conversation directly
        if (selectedContact) {
            const response = await fetch(`${API_BASE}/conversation/${currentUser}/${selectedContact}`);
            if (response.ok) {
                const messages = await response.json();
                
                // Check if there are new messages (compare count or last message id)
                const newLastId = messages.length > 0 ? Math.max(...messages.map(m => m.id)) : 0;
                
                if (newLastId > lastMessageId) {
                    console.log(`🔔 New messages detected! (last: ${lastMessageId}, new: ${newLastId})`);
                    lastMessageId = newLastId;
                    renderMessages(messages);
                }
            }
        }
        
        // Also check for messages from other users (notifications)
        await checkForNewMessagesFromOthers();
        
    } catch (error) {
        console.error('Polling error:', error);
    }
}

// Check for undelivered messages from users other than current conversation
async function checkForNewMessagesFromOthers() {
    try {
        console.log(`🔍 Checking for new messages for ${currentUser}...`);
        const response = await fetch(`${API_BASE}/fetch-messages/${currentUser}`);
        if (response.ok) {
            const messages = await response.json();
            console.log(`📬 Got ${messages.length} new messages:`, messages);
            
            // Set username in encryption service
            window.EncryptionService.setCurrentUsername(currentUser);
            
            for (const msg of messages) {
                console.log(`📩 Processing message from ${msg.sender}: ${msg.encrypted_content}`);
                
                // Check cache to avoid double decryption/notification
                const cached = getDecryptedMessage(msg.id);
                if (cached) {
                    continue;
                }

                const senderName = msg.sender;
                
                // Check if this is a first message (has X3DH ephemeral key)
                if (msg.x3dh_ephemeral_public_b64) {
                    const success = await handleReceiverX3DH(senderName, msg.x3dh_ephemeral_public_b64, msg.one_time_key_public_b64);
                    if (!success) continue;
                }

                // Decrypt the message (works for both first and subsequent messages after ratchet init)
                const decrypted = await window.EncryptionService.decrypt(
                    msg.header_b64,
                    msg.encrypted_content,
                    senderName,
                );

                if (decrypted) {
                    console.log(`✅ Decrypted message from ${senderName}: ${decrypted}`);
                    saveDecryptedMessage(msg.id, decrypted);
                    showNotification(senderName, decrypted);
                } else {
                    console.log(`⚠️ Could not decrypt message from ${senderName}`);
                    showNotification(senderName, "[Encrypted message]");
                }
            }
            
            if (messages.length > 0) {
                await fetchFriends();
            }
        } else {
            console.error(`❌ Fetch messages failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error('Check messages error:', error);
    }
}


async function renderMessages(messages) {
    messagesDiv.innerHTML = '';
    
    if (messages.length === 0) {
        messagesDiv.innerHTML = `
            <div class="empty-state" style="flex: 1;">
                <div class="empty-state-icon">🌸</div>
                <h3>Start the conversation!</h3>
                <p>Say something nice...</p>
            </div>
        `;
        return;
    }
    
    for (const msg of messages) {
        await appendMessage(msg, false);
    }
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

async function appendMessage(msg, scroll = true) {
    // Remove empty state if present
    const emptyState = messagesDiv.querySelector('.empty-state');
    if (emptyState) emptyState.remove();
    
    const div = document.createElement('div');
    const isSent = msg.sender === currentUser;
    div.className = 'message ' + (isSent ? 'sent' : 'received');
    
    const time = new Date(msg.timestamp);
    const timeStr = time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    // By default show the stored content (may be encrypted)
    let displayText = msg.encrypted_content;

    // If this message is not sent by us, attempt to decrypt using the EncryptionService
    if (!isSent) {
        const cached = getDecryptedMessage(msg.id);
        if (cached) {
            displayText = cached;
        } else if (window.EncryptionService && typeof window.EncryptionService.decrypt === 'function') {
            try {
                // Check if this message carries X3DH initialization data
                if (msg.x3dh_ephemeral_public_b64) {
                    await handleReceiverX3DH(msg.sender, msg.x3dh_ephemeral_public_b64);
                }

                const decrypted = await window.EncryptionService.decrypt(msg.header_b64, msg.encrypted_content, msg.sender);
                if (decrypted) {
                    saveDecryptedMessage(msg.id, decrypted);
                } else {
                    console.log(`⚠️ Could not decrypt message from ${msg.sender}`);
                }
            } catch (e) {
                console.error('Error decrypting message for display:', e);
            }
        }
    } else if (isSent) {
        // For sent messages, try to retrieve the plaintext from local storage
        const storedPlaintext = getSentMessage(msg.encrypted_content);
        if (storedPlaintext) {
            displayText = storedPlaintext;
        }
    }

    div.innerHTML = `
        <div class="sender">${isSent ? 'You' : msg.sender}</div>
        <div class="text">${escapeHtml(displayText)}</div>
        <div class="time">${timeStr}</div>
    `;
    messagesDiv.appendChild(div);
    
    if (scroll) {
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (pollInterval) clearInterval(pollInterval);
    if (ws) ws.close();
});
