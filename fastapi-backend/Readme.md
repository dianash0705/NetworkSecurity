

# 🔒 TeeTime Secure Backend

This is the core messaging infrastructure for **TeeTime**, built with **FastAPI** and **SQLite**. It handles the server-side requirements for End-to-End Encryption (E2EE) by acting as a secure public key directory and an encrypted message relay.

## 🚀 Features
* **TeeTime Key Directory:** Securely stores users' Public Keys.
* **Zero-Knowledge Relay:** Stores and delivers encrypted message blobs. The TeeTime server acts only as a "postman" and cannot read message contents.
* **Automatic API Docs:** Built-in Swagger UI for rapid development and testing.

---

## 🛠️ Setup Instructions

### 1. Prerequisites
Ensure you have **Python 3.8+** installed.

### 2. Installation
Navigate to the project directory and set up your environment:

```bash
# Enter the backend folder
cd fastapi-backend

# Create a virtual environment
python -m venv venv

# Activate the environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt