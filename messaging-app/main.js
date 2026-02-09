const { app, BrowserWindow, dialog } = require('electron'); // הוספנו את dialog
const path = require('path');
const { spawn, execSync } = require('child_process');
const net = require('net');
const fs = require('fs'); 

let mainWindow;
let pythonProcess = null;

// הגדרת נתיבים
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

function getVenvPythonPath() {
    if (process.platform === 'win32') {
        return path.join(VENV_DIR, 'Scripts', 'python.exe');
    } else {
        return path.join(VENV_DIR, 'bin', 'python');
    }
}

function setupPythonEnvironment() {
    console.log("Checking Python environment...");
    
    if (!fs.existsSync(SERVICE_DIR)) {
        console.error(`Error: Service directory not found at: ${SERVICE_DIR}`);
        return false;
    }

    if (!fs.existsSync(VENV_DIR)) {
        console.log("Virtual environment not found. Creating one...");
        try {
            execSync(`python -m venv "${VENV_DIR}"`, { stdio: 'inherit' }); 
            console.log("Venv created.");
        } catch (error) {
            console.error("Failed to create venv:", error);
            return false;
        }
    }

    try {
        const pipPath = process.platform === 'win32' 
            ? path.join(VENV_DIR, 'Scripts', 'pip.exe') 
            : path.join(VENV_DIR, 'bin', 'pip');
            
        const reqPath = path.join(SERVICE_DIR, 'requirements.txt');
        
        if (fs.existsSync(reqPath)) {
            // שיניתי ל-inherit כדי שתראה שגיאות התקנה בטרמינל אם יש
            execSync(`"${pipPath}" install -r "${reqPath}"`, { stdio: 'inherit' });
            console.log("Dependencies checked/installed.");
        } else {
            console.warn("requirements.txt not found.");
        }
    } catch (error) {
        console.error("Failed to install dependencies:", error);
        return false;
    }

    return true;
}

async function startFastAPIServer() {
    if (!setupPythonEnvironment()) {
        throw new Error("Failed to setup Python environment.");
    }

    const port = await getFreePort();
    console.log(`Starting Local FastAPI on port: ${port}`);

    const pythonExecutable = getVenvPythonPath();
    const scriptPath = path.join(SERVICE_DIR, 'service.py');

    if (!fs.existsSync(pythonExecutable)) {
        throw new Error(`Python executable not found at: ${pythonExecutable}`);
    }

    console.log(`Using Python: ${pythonExecutable}`);

    return new Promise((resolve, reject) => {
        pythonProcess = spawn(pythonExecutable, [
            '-m', 'uvicorn', 
            'service:app', 
            '--app-dir', SERVICE_DIR,
            '--host', '127.0.0.1', 
            '--port', port.toString()
        ], {
            cwd: SERVICE_DIR,
            stdio: ['ignore', 'pipe', 'pipe']
        });

        // === המנגנון החדש: מחכים לראות שהשרת עלה ===
        let startupSuccess = false;

        pythonProcess.stdout.on('data', (data) => {
            const output = data.toString();
            console.log(`FastAPI: ${output}`);
            
            // Uvicorn מדפיס את השורה הזו כשהוא מוכן
            if (output.includes("Application startup complete") || output.includes("Uvicorn running on")) {
                startupSuccess = true;
                resolve(port); // רק עכשיו אנחנו משחררים את ה-Promise!
            }
        });

        pythonProcess.stderr.on('data', (data) => {
            const errorOutput = data.toString();
            console.log(`FastAPI Log: ${errorOutput}`);
            // הערה: רוב הלוגים של uvicorn מגיעים ל-stderr, זה תקין.
            // אנחנו לא עושים reject כאן כי אזהרות לא אמורות להפיל את האפליקציה.
            
            if (errorOutput.includes("Application startup complete") || errorOutput.includes("Uvicorn running on")) {
                 startupSuccess = true;
                 resolve(port);
            }
        });
        
        pythonProcess.on('error', (err) => {
            console.error('Failed to spawn Python process:', err);
            reject(err);
        });

        pythonProcess.on('close', (code) => {
            if (!startupSuccess) {
                // אם התהליך נסגר לפני שהצלחנו לעלות - זו שגיאה קריטית
                const msg = `Python process exited unexpectedly with code ${code}. Check terminal logs for details.`;
                console.error(msg);
                reject(new Error(msg));
            }
        });
    });
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
            preload: path.join(__dirname, 'preload.js')
        },
        backgroundColor: '#E6E6FA',
        titleBarStyle: 'default',
        show: false 
    });

    mainWindow.loadFile(path.join(__dirname, 'public', 'index.html'));

    mainWindow.webContents.on('did-finish-load', () => {
        if (localPort) {
            mainWindow.webContents.send('set-api-port', localPort);
        }
    });

    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
    });

    if (process.argv.includes('--dev')) {
        mainWindow.webContents.openDevTools();
    }

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

app.whenReady().then(async () => {
    try {
        // מנסים להריץ את השרת
        const port = await startFastAPIServer();
        
        // אם הגענו לפה - השרת עלה בהצלחה!
        createWindow(port);
    } catch (error) {
        // אם הייתה שגיאה (כמו חוסר ב-uvicorn), נקפיץ הודעה ונסגור
        console.error("Critical Error:", error);
        dialog.showErrorBox("Startup Failed", `Failed to start local encryption server.\n\nError: ${error.message}`);
        app.quit();
    }

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            // במקרה של הפעלה מחדש במק, נצטרך לטפל בלוגיקה הזו בנפרד, 
            // אבל כרגע זה פחות קריטי כי השרת כבר רץ.
        }
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

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