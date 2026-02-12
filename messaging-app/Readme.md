# 📱 TeeTime Messenger - Desktop App

The desktop frontend for **TeeTime**, built with **Electron**. This app provides the interface for end-to-end encrypted messaging, communicating directly with the TeeTime FastAPI backend and a local Python sidecar for cryptographic operations.

## 🚀 Features
* **Desktop Interface:** Native Windows/Mac/Linux experience.
* **E2EE Integration:** All crypto operations (key generation, X3DH, Double Ratchet, SealedBox decryption) are offloaded to a trusted local sidecar service.
* **Real-time Updates:** WebSocket + polling for new messages and notifications.
* **Secure Key Management:** Private keys remain local; sidecar is the only trusted crypto service.

---

## 🛠️ Setup Instructions

### 1. Prerequisites
- **Node.js** (LTS version recommended) — check with `node -v`
- **Python 3.8+** (required for the local crypto sidecar) — check with `python --version`

### 2. Installation
Navigate to the app directory and install the necessary dependencies:

```bash
# Navigate to the messaging-app folder
cd messaging-app

# Install all dependencies (including Electron)
npm install