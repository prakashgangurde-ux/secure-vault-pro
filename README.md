🛡️ Secure Vault Pro

Secure Vault Pro is a modern, offline file encryption tool designed to protect your sensitive data. Built with Python and military-grade AES encryption, it allows users to lock specific files or entire folders, rendering them unreadable to unauthorized users.

Unlike simple "folder hiders," Secure Vault Pro actually encrypts the binary data of your files, ensuring that even if someone steals your hard drive, they cannot access your content without the master password.

✨ Key Features

🔒 Military-Grade Encryption: Uses AES (Fernet) encryption to secure file contents.

📂 Batch Processing: Lock/Unlock individual files or entire folders recursively.

🔑 Master Key System:

Secure login with PBKDF2 hashing.

Password Recovery: Reset forgotten passwords via security questions without losing data access.

📝 Audit Logs: Tracks every encryption and decryption event with timestamps.

⏱️ Auto-Lock: Automatically secures the vault after 5 minutes of inactivity.

🎨 Modern UI: Sleek, dark-mode interface built with CustomTkinter.

⚡ High Performance: Multi-threaded processing prevents freezing during large folder operations.

💣 Factory Reset: Option to wipe all data and keys in case of emergency.

📸 Screenshots

(Add your screenshots here. You can drag and drop images into GitHub issues to generate URLs, then paste them here)

Login Screen

Dashboard

Audit Logs







🚀 Download & Usage (Executable)

We provide a standalone .exe application for Windows users. You do not need Python installed to run this version.

Go to the Releases page.

Download SecureVaultPro.exe.

Double-click to run.

First Run: You will be asked to create a Username, Master Password, and Security Question.

Note: Windows Defender may flag the .exe as "Unknown" because it is not digitally signed (which costs money). You can safely click "More Info" -> "Run Anyway" as this is open-source software.

🛠️ Installation (For Developers)

If you want to run the source code or modify it, follow these steps:

Prerequisites

Python 3.10 or higher

pip

Setup

Clone the repository:

git clone [https://github.com/prakashgangurde-ux/secure-vault-pro.git](https://github.com/prakashgangurde-ux/secure-vault-pro.git)
cd secure-vault-pro


Install dependencies:

pip install customtkinter cryptography


Run the application:

python secure_vault_pro.py


📦 How to Build the EXE

If you want to compile the executable yourself (for example, after modifying the code), use PyInstaller.

Install PyInstaller:

pip install pyinstaller


Run the build command:

pyinstaller --noconsole --onefile --name="SecureVaultPro" secure_vault_pro.py


The output file will be in the dist/ folder.

📖 User Guide

1. Registration

Launch the app.

Enter a Username and a Strong Password.

Select a Security Question (e.g., "What was your first pet's name?").

Crucial: Remember this answer. It is the only way to reset your password.

2. Locking Files

Go to the Dashboard.

Click "🔒 Lock File" for single files or "📂 Lock Folder" for bulk encryption.

Select the target. The app will encrypt the data and append a .enc extension.

The original file is securely deleted.

3. Unlocking Files

Click "🔓 Unlock Item".

Select the .enc files you want to restore.

The app decrypts them back to their original state.

4. Forgot Password?

Click "Forgot Password?" on the login screen.

Enter your Username.

Answer your Security Question.

If correct, you can set a new password. Your files remain safe and accessible.

🔐 Security Architecture

Encryption: Symmetric AES-128 (via cryptography.fernet).

Key Derivation: PBKDF2HMAC (SHA-256) with 200,000 iterations and per-user salts.

Master Key: The actual encryption key is stored in the database but is encrypted twice:

Once with your Password.

Once with your Security Answer.
This allows password resets without data loss.

⚠️ Disclaimer

Use at your own risk.
While this application uses strong encryption standards, if you lose your Password AND your Security Answer, your data is mathematically impossible to recover.
Always keep backups of critical data before encrypting.

🤝 Contributing

Contributions are welcome!

Fork the Project

Create your Feature Branch (git checkout -b feature/AmazingFeature)

Commit your Changes (git commit -m 'Add some AmazingFeature')

Push to the Branch (git push origin feature/AmazingFeature)

Open a Pull Request

📄 License

Distributed under the MIT License. See LICENSE for more information.

Developed by Prakash Gangurde
