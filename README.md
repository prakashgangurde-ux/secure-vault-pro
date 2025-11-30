# 🛡️ Secure Vault Pro

Secure Vault Pro is a modern, offline file encryption tool designed to protect your sensitive data. Built with Python and military-grade AES encryption (via cryptography.Fernet), it allows users to lock specific files or entire folders, rendering them unreadable to unauthorized users.

Unlike simple "folder hiders," Secure Vault Pro encrypts the binary data of your files — so if someone steals your drive they cannot access your content without the master password.

F.py is the main entry-point for this project.

---

## ✨ Key Features

- 🔒 Military-Grade Encryption: Uses AES (Fernet) encryption to secure file contents.
- 📂 Batch Processing: Lock/Unlock individual files or entire folders recursively.
- 🔑 Master Key System:
  - Secure login with PBKDF2 hashing.
  - Password Recovery: Reset forgotten passwords via security questions without losing data access.
- 📝 Audit Logs: Tracks every encryption and decryption event with timestamps.
- ⏱️ Auto-Lock: Automatically secures the vault after inactivity (default 5 minutes).
- 🎨 Modern UI: Sleek, dark-mode interface built with CustomTkinter.
- ⚡ High Performance: Multi-threaded processing prevents freezing during large folder operations.
- 💣 Factory Reset: Option to wipe all data and keys in case of emergency.

---

## 📸 Screenshots

(Drag and drop screenshots into GitHub to generate URLs, then paste them here.)

- Login Screen  
- Dashboard  
- Audit Logs

---

## 🚀 Download & Usage (Executable)

A standalone .exe is available on Releases for Windows users (no Python required).

Steps:
1. Go to the Releases page.
2. Download SecureVaultPro.exe.
3. Double-click to run.

Note: Unsigned executables may be flagged by Windows Defender as "Unknown"; choose "More info" → "Run anyway." This is open-source software.

---

## 🛠️ Installation (For Developers)

Prerequisites:
- Python 3.10+
- pip

Clone and run locally:
```bash
git clone https://github.com/prakashgangurde-ux/secure-vault-pro.git
cd secure-vault-pro
pip install customtkinter cryptography
python F.py
```

Dependencies:
- customtkinter
- cryptography

---

## 📦 How to Build the EXE

Install PyInstaller:
```bash
pip install pyinstaller
```

Build:
```bash
pyinstaller --noconsole --onefile --name="SecureVaultPro" F.py
```

The single-file executable will be in dist/.

---

## 📖 User Guide

1. Registration
   - Launch the app.
   - Create a Username and a strong Password.
   - Select and answer a Security Question (used for recovery).

2. Locking Files
   - Dashboard → "🔒 Lock File" or "📂 Lock Folder".
   - Files are encrypted and typically the original is securely removed.
   - Encrypted files use a .enc extension.

3. Unlocking Files
   - Dashboard → "🔓 Unlock Item".
   - Select .enc files to decrypt.

4. Forgot Password?
   - Use "Forgot Password?" on login.
   - Enter username and answer the security question.
   - If validated, you may set a new password while keeping file access intact.

---

## 🔐 Security Architecture

- Encryption: Symmetric AES (cryptography.Fernet).
- Key Derivation: PBKDF2HMAC (SHA-256) with 200,000 iterations and per-user salts.
- Master Key: Stored encrypted twice:
  - Once with the user's Password.
  - Once with the Security Answer.
This enables password resets without data loss.

---

## ⚠️ Disclaimer

Use at your own risk. If both your Password and Security Answer are lost, data recovery is impossible. Always back up important data before encrypting.

---

## 🤝 Contributing

Contributions welcome:
1. Fork the project.
2. Create a branch: git checkout -b feature/AmazingFeature
3. Commit and push.
4. Open a pull request.

---

## 📄 License

Distributed under the MIT License. See LICENSE for details.

---

Developed by Prakash Gangurde
