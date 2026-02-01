const express = require('express');
const { WebSocketServer } = require('ws');
const http = require('http');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Simple JSON file database
const DB_FILE = path.join(__dirname, 'database.json');

function loadDB() {
    if (fs.existsSync(DB_FILE)) {
        return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    }
    return { users: [], messages: [] };
}

function saveDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Initialize DB
if (!fs.existsSync(DB_FILE)) {
    saveDB({ users: [], messages: [] });
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Track connected users
const connectedUsers = new Map(); // username -> ws

// WebSocket handling
wss.on('connection', (ws) => {
    let username = null;

    ws.on('message', (data) => {
        const msg = JSON.parse(data);

        if (msg.type === 'login') {
            username = msg.username;
            
            // Register user if new
            const db = loadDB();
            if (!db.users.includes(username)) {
                db.users.push(username);
                saveDB(db);
            }
            
            // Track connection
            connectedUsers.set(username, ws);
            
            // Broadcast updated user list
            broadcastUserList();
        }

        if (msg.type === 'message') {
            const db = loadDB();
            
            const messageData = {
                id: Date.now(),
                from_user: msg.from,
                to_user: msg.to,
                text: msg.text,
                timestamp: new Date().toISOString()
            };
            
            db.messages.push(messageData);
            saveDB(db);

            // Send to recipient if online
            const recipientWs = connectedUsers.get(msg.to);
            if (recipientWs && recipientWs.readyState === 1) {
                recipientWs.send(JSON.stringify({
                    type: 'message',
                    message: messageData
                }));
            }

            // Send confirmation back to sender
            ws.send(JSON.stringify({
                type: 'message',
                message: messageData
            }));
        }

        if (msg.type === 'getHistory') {
            const db = loadDB();
            const messages = db.messages.filter(m => 
                (m.from_user === msg.user1 && m.to_user === msg.user2) ||
                (m.from_user === msg.user2 && m.to_user === msg.user1)
            ).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

            ws.send(JSON.stringify({
                type: 'history',
                messages: messages
            }));
        }
    });

    ws.on('close', () => {
        if (username) {
            connectedUsers.delete(username);
            broadcastUserList();
        }
    });
});

function broadcastUserList() {
    const users = Array.from(connectedUsers.keys());
    const msg = JSON.stringify({ type: 'userList', users });
    
    connectedUsers.forEach((ws) => {
        if (ws.readyState === 1) {
            ws.send(msg);
        }
    });
}

// API to get all registered users
app.get('/api/users', (req, res) => {
    const db = loadDB();
    res.json(db.users);
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
