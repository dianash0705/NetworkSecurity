const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn, execSync } = require('child_process');
const net = require('net');
const fs = require('fs'); 

let mainWindow;
let pythonProcess = null;

const SERVICE_DIR = path.join(__dirname, '../client_service/src');
const VENV_DIR = path.join(SERVICE_DIR, 'venv');

function getFreePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.unref();
        server.on('error', reject);
        server.listen(0, () => {
            const port = server.address().port;
            server.close(() => {
                resolve(port);
            });
        });
    });
}

function setupPythonEnvironment() {
    console.log("Checking Python environment...");
    
    // בדיקה שהתיקייה הראשית קיימת
    if (!fs.existsSync(SERVICE_DIR)) {
        console.error(`❌ Error: Service directory not found at: ${SERVICE_DIR}`);
        return false;
    }

    // create venv if doesnt exist
    if (!fs.existsSync(VENV_DIR)) {
        console.log("⚠️ Virtual environment not found. Creating one...");
        try {
            execSync(`python -m venv "${VENV_DIR}"`, { stdio: 'inherit' }); 
            console.log("✅ Venv created.");
        } catch (error) {
            console.error("❌ Failed to create venv:", error);
            return false;
        }
    }

    // install dependencies
    try {
        const pipPath = process.platform === 'win32' 
            ? path.join(VENV_DIR, 'Scripts', 'pip.exe') 
            : path.join(VENV_DIR, 'bin', 'pip');
            
        const reqPath = path.join(SERVICE_DIR, 'requirements.txt');
        
        if (fs.existsSync(reqPath)) {
            console.log("📦 Checking dependencies...");
            execSync(`"${pipPath}" install -r "${reqPath}"`, { stdio: 'inherit' });
        } else {
            console.warn("⚠️ requirements.txt not found.");
        }
    } catch (error) {
        console.error("❌ Failed to install dependencies:", error);
        return false;
    }

    return true;
}

async function startFastAPIServer() {
    if (!setupPythonEnvironment()) {
        console.error("Cannot start server due to environment error.");
        return null;
    }

    try {
        const port = await getFreePort();
        console.log(`Starting Local FastAPI on port: ${port}`);

        const pythonPath = process.platform === 'win32' ? 'python' : 'python3';
        const pythonFolder = path.join(__dirname, '../client_service/src');
        console.log("Checking folder path:", pythonFolder);

        pythonProcess = spawn(pythonPath, [
            '-m', 'uvicorn', 
            'service:app', 
            '--host', '127.0.0.1', 
            '--port', port.toString() // שימוש בפורט הדינמי
        ], {
            cwd: pythonFolder,
            stdio: ['ignore', 'pipe', 'pipe']
        });

        pythonProcess.stdout.on('data', (data) => console.log(`FastAPI: ${data}`));
        pythonProcess.stderr.on('data', (data) => console.log(`FastAPI Error: ${data}`));

        return port; 

    } catch (err) {
        console.error('Failed to start FastAPI server:', err);
    }
}

function createWindow(localPort) {
    mainWindow = new BrowserWindow({
        width: 1100,
        height: 750,
        minWidth: 800,
        minHeight: 600,
        title: 'TeaTime 🍵',
        icon: path.join(__dirname, 'public', 'icon.png'),
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            sandbox: false,
            preload: path.join(__dirname, 'preload.js')
        },
        backgroundColor: '#E6E6FA',
        titleBarStyle: 'default',
        show: false // Don't show until ready
    });

    // Load the static HTML file directly
    mainWindow.loadFile(path.join(__dirname, 'public', 'index.html'));

    // Send the port to the frontend once the window loads
    mainWindow.webContents.on('did-finish-load', () => {
        mainWindow.webContents.send('set-api-port', localPort);
    });

    // Show window when ready to prevent visual flash
    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

    // Open DevTools in development
    if (process.argv.includes('--dev')) {
        mainWindow.webContents.openDevTools();
    }

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

// This method will be called when Electron has finished initialization
app.whenReady().then(async () => {
    // Start FastAPI backend first
    await startFastAPIServer();
    
    const port = await startFastAPIServer(); // Get the dynamic port
    createWindow(port);

    app.on('activate', () => {
        // On macOS, re-create window when dock icon is clicked
        if (BrowserWindow.getAllWindows().length === 0) {
            createWindow(port);
        }
    });
});

// Quit when all windows are closed (except on macOS)
app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

// Handle app quit - cleanup Python process
app.on('before-quit', () => {
    if (pythonProcess) {
        pythonProcess.kill();
        pythonProcess = null;
    }
});

app.on('quit', () => {
    if (pythonProcess) {
        pythonProcess.kill();
        pythonProcess = null;
    }
});
