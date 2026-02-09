// API Base URL - FastAPI backend (use 127.0.0.1 to match server binding)
const API_BASE = 'http://127.0.0.1:8000';

let currentUser = null;
let selectedContact = null;
let allUsers = [];
let pollInterval = null;
let lastMessageId = 0;  // Track last seen message to detect new ones

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

// Login event listeners
loginBtn.addEventListener('click', login);
usernameInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') login(); });

async function login() {
    const username = usernameInput.value.trim();
    if (!username) return;

    currentUser = username;
    status.textContent = '🔄 Connecting...';
    
    try {
        // Register user with the FastAPI backend
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: currentUser,
                public_key: 'placeholder_key_' + currentUser, // Placeholder for now
                identity_key_public: 'placeholder_key_' + currentUser, // Placeholder for now
                prekey_public: 'placeholder_key_' + currentUser, // Placeholder for now
                prekey_signature_public: 'placeholder_key_' + currentUser, // Placeholder for now
                onetime_keys_public: ['placeholder_key1', 'placeholder_key2'] // Placeholder for now
            })
        });

        if (response.ok) {
            status.textContent = `✨ Connected as ${currentUser}`;
            usernameInput.disabled = true;
            loginBtn.disabled = true;
            loginSection.style.display = 'none';
            app.style.display = 'block';
            currentUserDisplay.textContent = `Logged in as ${currentUser}`;
            
            // Fetch all registered users from backend
            await fetchAllUsers();
            
            // Start polling for new messages
            startMessagePolling();
        } else {
            status.textContent = '❌ Failed to connect';
            status.classList.add('error');
        }
    } catch (error) {
        console.error('Login error:', error);
        status.textContent = '❌ Server not available';
        status.classList.add('error');
    }
}

function getRandomVibe() {
    return vibeEmojis[Math.floor(Math.random() * vibeEmojis.length)];
}

function getInitials(name) {
    return name.charAt(0).toUpperCase();
}

// Fetch all users from backend
async function fetchAllUsers() {
    try {
        const response = await fetch(`${API_BASE}/users`);
        if (response.ok) {
            const users = await response.json();
            allUsers = users.map(u => u.username).filter(u => u !== currentUser);
        }
    } catch (error) {
        console.error('Error fetching users:', error);
    }
    renderContacts();
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
            icon: '🍵'
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
                <input type="text" id="newContactInput" placeholder="Add username" 
                    style="margin-top: 12px; padding: 8px 12px; border: 2px solid var(--lavender-dark); 
                    border-radius: 12px; font-family: inherit; font-size: 12px; width: 100%;">
                <button id="addContactBtn" 
                    style="margin-top: 8px; padding: 8px 16px; border: none; border-radius: 12px; 
                    background: var(--mint); cursor: pointer; font-family: inherit; font-weight: 600;">
                    Add Friend 🌸
                </button>
            </div>
        `;
        
        setTimeout(() => {
            const addBtn = document.getElementById('addContactBtn');
            const input = document.getElementById('newContactInput');
            if (addBtn && input) {
                addBtn.onclick = () => {
                    const name = input.value.trim();
                    if (name) addUserToList(name);
                };
                input.onkeypress = (e) => {
                    if (e.key === 'Enter') {
                        const name = input.value.trim();
                        if (name) addUserToList(name);
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
                    addUserToList(name);
                    input.value = '';
                }
            };
            input.onkeypress = (e) => {
                if (e.key === 'Enter') {
                    const name = input.value.trim();
                    if (name) {
                        addUserToList(name);
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
                <div class="contact-status">
                    <span class="status-dot online"></span>
                    <span style="color: var(--text-secondary);">Available</span>
                </div>
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
    
    chatWith.innerHTML = `
        <div class="chat-header-avatar">${getInitials(user)}</div>
        <div class="chat-header-info">
            <h3>${user}</h3>
            <span>🟢 Available</span>
        </div>
    `;
    
    messagesDiv.style.display = 'flex';
    inputArea.style.display = 'flex';
    messageInput.disabled = false;
    sendBtn.disabled = false;
    renderContacts();
    
    // Load conversation history from backend
    await loadConversationFromBackend(user);
    messageInput.focus();
}

// Load conversation from backend
async function loadConversationFromBackend(contact) {
    try {
        const response = await fetch(`${API_BASE}/conversation/${currentUser}/${contact}`);
        if (response.ok) {
            const messages = await response.json();
            // Update lastMessageId to track what we've seen
            if (messages.length > 0) {
                lastMessageId = Math.max(...messages.map(m => m.id));
            }
            renderMessages(messages);
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
        // --- שינוי: שימוש בשירות ההצפנה הלוקאלי ---
        
        // בדיקה שהשירות קיים (שה-renderer.js נטען)
        if (!window.EncryptionService) {
            alert("Encryption service not loaded!");
            return;
        }

        // הצפנה באמצעות ה-Python הלוקאלי
        const encryptionResult = await window.EncryptionService.encrypt(content, selectedContact);

        if (!encryptionResult) {
            alert("Failed to encrypt message locally.");
            return;
        }

        // השימוש בתוכן המוצפן שחזר מה-Python
        const finalEncryptedContent = encryptionResult.encrypted_content; 
        
        // ------------------------------------------

        // מכאן הכל נשאר אותו דבר - שליחה לשרת המרכזי
        const messageData = {
            sender: currentUser,
            receiver: selectedContact,
            encrypted_content: finalEncryptedContent // שולחים את המוצפן, לא את הטקסט הרגיל
        };

        const response = await fetch(`${API_BASE}/send-message`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(messageData)
        });

        if (response.ok) {
<<<<<<< HEAD
            // ב-UI המקומי אנחנו מציגים את הטקסט המקורי (כדי שהשולח יבין מה הוא כתב)
            const localMsg = {
                sender: currentUser,
                receiver: selectedContact,
                encrypted_content: content, // ב-UI מציגים רגיל
                timestamp: new Date().toISOString()
            };
            
            appendMessage(localMsg);
=======
>>>>>>> dfecb86561c436adaf864a6c016ecae472f8ac89
            messageInput.value = '';
            
            addUserToList(selectedContact);
            
            // Reload conversation to get the message with proper server ID
            await loadConversationFromBackend(selectedContact);
        } else {
            const error = await response.json();
            alert('Failed to send: ' + error.detail);
        }
    } catch (error) {
        console.error('Send error:', error);
    }
}
// Poll for new messages
function startMessagePolling() {
    // Poll every 500ms for near real-time feel
    pollInterval = setInterval(pollForUpdates, 500);
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
            
            for (const msg of messages) {
                console.log(`📩 Processing message from ${msg.sender}: ${msg.encrypted_content}`);
                
                // Add sender to contacts automatically
                addUserToList(msg.sender);
                
                // Show notification for ALL new messages
                console.log(`🔔 Calling showNotification for ${msg.sender}...`);
                showNotification(msg.sender, msg.encrypted_content);
            }
            
            if (messages.length > 0) {
                await fetchAllUsers();
            }
        } else {
            console.error(`❌ Fetch messages failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error('Check messages error:', error);
    }
}


function renderMessages(messages) {
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
    
    messages.forEach(msg => appendMessage(msg, false));
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function appendMessage(msg, scroll = true) {
    // Remove empty state if present
    const emptyState = messagesDiv.querySelector('.empty-state');
    if (emptyState) emptyState.remove();
    
    const div = document.createElement('div');
    const isSent = msg.sender === currentUser;
    div.className = 'message ' + (isSent ? 'sent' : 'received');
    
    const time = new Date(msg.timestamp);
    const timeStr = time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    div.innerHTML = `
        <div class="sender">${isSent ? 'You' : msg.sender}</div>
        <div class="text">${escapeHtml(msg.encrypted_content)}</div>
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
});
