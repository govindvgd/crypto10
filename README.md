# Secure Messenger — Cryptography & Network Security Project

## 📌 Overview

This project implements a **secure messenger** that allows encrypted communication between two machines over a network. It provides a **128-bit security level** using **AES-CCM** encryption and ensures authentication through **RSA-signed ECDH key exchange**.  

The messenger supports real-time chat while protecting messages from eavesdropping and tampering.

---

## 🔐 Features

- **Authenticated Key Exchange**:  
  Uses **Elliptic Curve Diffie-Hellman (ECDH)** for shared secret derivation, with **RSA signatures** for authentication.

- **Session Encryption**:  
  Messages are encrypted using **AES-CCM** (authenticated encryption), ensuring both confidentiality and integrity.

- **Secure Session Key Derivation**:  
  AES keys are derived from ECDH shared secret using **HKDF + SHA256**.

- **Cross-network communication**:  
  Client and server can run on different machines within the same network.

---

## 🗂️ Project Structure

## 🗂️ Project Structure

```text
Crypto10/
├── crypto/                 # Core Cryptographic Implementations
│   ├── aes_ccm.py          # AES Encryption/Decryption logic
│   ├── ecdh.py             # Elliptic Curve Key Exchange
│   ├── rsa_keys.py         # RSA Key loading/generation
│   ├── secure_session.py   # Session management wrapper
│   └── signature.py        # Digital Signature verification
├── data/                   # RSA Key Storage (Generated keys)
│   ├── alice_priv.pem
│   ├── alice_pub.pem
│   ├── bob_priv.pem
│   └── bob_pub.pem
├── networking/             # Socket Programming logic
│   ├── client.py
│   ├── server.py
│   └── message_handler.py
├── logs/                   # (Optional) Chat logs
├── main.py                 # Application Entry Point
├── requirements.txt        # Dependencies
└── README.md               # Project Documentation
```

---

## 🛠️ Installation & Setup

### 1. Prerequisites
Ensure you have **Python 3.8+** installed.

### 2. Clone the Repository
```bash
git clone <repository_url>
cd Crypto10
```

### 3. Create Virtual Environment (Recommended)
```bash
python3 -m venv venv
# Windows
venv\Scripts\activate
# Mac/Linux
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Generate RSA Keys
Before running, generate the identity keys for the Client (Alice) and Server (Bob).
```bash
# If you have a generation script:
python3 crypto/generate_keys.py
```
*Ensure `data/` folder contains: `alice_priv.pem`, `alice_pub.pem`, `bob_priv.pem`, `bob_pub.pem`.*

---

## 🚀 Usage

### Step 1: Start the Server (Receiver)
The server listens for incoming connections.
```bash
python3 main.py server
```
*Output:*
```text
[🚀] Secure Chat Server Running on 0.0.0.0:5000
[⏳] Waiting for connection...
```

### Step 2: Start the Client (Sender)
Open a new terminal and run the client.
```bash
python3 main.py client
```

### Step 3: Chatting
Once connected, the secure handshake is performed automatically.
```text
[🔑] Shared AES-CCM key derived successfully
[🔐] Secure channel established — AES-CCM enabled
[💬] Type your message and press Enter:
```
You can now type messages in either terminal. The text is encrypted before leaving the machine and decrypted only by the recipient.

---

## 🧪 Security & Logic Details

### 1. The Handshake
1. **RSA Signatures:** Both parties sign their ephemeral ECDH public keys with their long-term RSA private keys.
2. **Verification:** The receiver verifies the signature using the sender's known RSA public key (stored in `data/`).
3. **Establishment:** If verified, ECDH is used to calculate `pre_master_secret`.

### 2. The Session
* We use **HKDF (HMAC-based Key Derivation Function)** to transform the `pre_master_secret` into a 128-bit AES key.
* Messages are encrypted using **AES-CCM**, which generates an authentication tag. If a packet is modified in transit (e.g., a bit flip), the decryption will fail, alerting the user.

---

## 👨‍💻 Group Members

* **Govind**
* **Prashant Mishra**

---
## 📚 References
* [Cryptography.io Documentation](https://cryptography.io/en/latest/)
```