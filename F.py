# import customtkinter as ctk
# import tkinter as tk
# from tkinter import filedialog, messagebox, simpledialog
# import sqlite3
# import os
# import threading
# import queue
# import time
# from datetime import datetime, timedelta
# from cryptography.fernet import Fernet
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# import base64
# import tempfile
# import secrets
# import concurrent.futures
# import traceback

# # --- CONFIGURATION ---
# ctk.set_appearance_mode("Dark")
# ctk.set_default_color_theme("blue")
# DB_NAME = "vault_data.db"
# KDF_ITERATIONS = 200_000  # High iteration count for security
# LOCKOUT_THRESHOLD = 5
# LOCKOUT_SECONDS = 30
# AUTO_LOCK_SECONDS = 300  # 5 minutes
# THREAD_POOL_WORKERS = 4

# class ModernVaultApp(ctk.CTk):
#     def __init__(self):
#         super().__init__()
#         self.title("Secure Vault Pro")
#         self.geometry("1000x700")
#         self.minsize(900, 650)
        
#         # --- State Variables ---
#         self.current_user = None
#         self.encryption_key = None # This is now the MASTER KEY, decrypted by password/recovery
#         self.last_activity = datetime.now()
#         self.failed_attempts = 0
#         self.locked_until = None
#         self.temp_reg_data = {} # Holds data between registration steps
        
#         # --- Thread Safety Queue ---
#         self.gui_queue = queue.Queue()

#         # --- Database & Thread Pool ---
#         self.init_db()
#         self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_POOL_WORKERS)

#         # --- UI Setup ---
#         self.grid_columnconfigure(0, weight=1)
#         self.grid_rowconfigure(0, weight=1)

#         # Check for existing users
#         if self.any_user_exists():
#             self.show_login_screen()
#         else:
#             self.show_register_screen()

#         # Start periodic tasks
#         self.after(100, self.process_gui_queue)
#         self.after(1000, self._auto_lock_check)

#     # --- CORE: Thread-Safe UI Updates ---
#     def process_gui_queue(self):
#         """Reads tasks from the queue and executes them in the main thread."""
#         try:
#             while True:
#                 task = self.gui_queue.get_nowait()
#                 action = task.get("action")
                
#                 if action == "log":
#                     self._log_to_console_internal(task["text"])
#                 elif action == "progress":
#                     self._update_progress_internal(task["value"])
#                 elif action == "messagebox":
#                     messagebox.showinfo(task["title"], task["message"])
#                 elif action == "errorbox":
#                     messagebox.showerror(task["title"], task["message"])
#                 elif action == "switch_screen":
#                     # Useful for changing screens from threads if needed
#                     pass 
                
#                 self.gui_queue.task_done()
#         except queue.Empty:
#             pass
#         finally:
#             self.after(100, self.process_gui_queue)

#     def safe_log(self, text):
#         self.gui_queue.put({"action": "log", "text": text})

#     def safe_progress(self, value):
#         self.gui_queue.put({"action": "progress", "value": value})

#     def safe_info(self, title, message):
#         self.gui_queue.put({"action": "messagebox", "title": title, "message": message})
        
#     def safe_error(self, title, message):
#         self.gui_queue.put({"action": "errorbox", "title": title, "message": message})

#     # --- DATABASE ---
#     def init_db(self):
#         self.conn = sqlite3.connect(DB_NAME, check_same_thread=False)
#         self.cursor = self.conn.cursor()
        
#         # Updated Schema for Master Key System
#         # enc_master_key: The master key encrypted by the user's password
#         # enc_recovery_key: The master key encrypted by the security answer
#         try:
#             self.cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS users (
#                     username TEXT PRIMARY KEY,
#                     enc_master_key BLOB,
#                     password_salt TEXT,
#                     security_question TEXT,
#                     enc_recovery_key BLOB,
#                     recovery_salt TEXT
#                 )
#             ''')
#             self.cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS logs (
#                     id INTEGER PRIMARY KEY AUTOINCREMENT,
#                     username TEXT,
#                     action TEXT,
#                     filename TEXT,
#                     timestamp TEXT
#                 )
#             ''')
#             self.conn.commit()
#         except sqlite3.OperationalError:
#             # Handle schema migration or corruption by just alerting (Simplification)
#             messagebox.showerror("Database Error", "Database schema mismatch. Please use Factory Reset in settings or delete vault_data.db")

#     def any_user_exists(self):
#         try:
#             self.cursor.execute("SELECT 1 FROM users LIMIT 1")
#             return self.cursor.fetchone() is not None
#         except:
#             return False

#     def log_action(self, action, filename=""):
#         try:
#             time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#             user = self.current_user or "System"
#             with sqlite3.connect(DB_NAME) as conn:
#                 cursor = conn.cursor()
#                 cursor.execute("INSERT INTO logs (username, action, filename, timestamp) VALUES (?, ?, ?, ?)",
#                                (user, action, filename, time_now))
#                 conn.commit()
#         except Exception as e:
#             print(f"Log Error: {e}")

#     # --- CRYPTO HELPER ---
#     def derive_key(self, password: str, salt_hex: str):
#         """Derives a 32-byte key from a password/answer and salt."""
#         salt = bytes.fromhex(salt_hex)
#         kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS)
#         return base64.urlsafe_b64encode(kdf.derive(password.encode()))

#     # --- LOGIC ---
#     def _update_activity(self, event=None):
#         self.last_activity = datetime.now()

#     def _auto_lock_check(self):
#         if self.current_user:
#             elapsed = (datetime.now() - self.last_activity).total_seconds()
#             if elapsed > AUTO_LOCK_SECONDS:
#                 self.perform_logout(auto=True)
#                 return
#         self.after(1000, self._auto_lock_check)

#     # --- GUI: SCREEN MANAGEMENT ---
#     def clear_frame(self):
#         for widget in self.winfo_children():
#             widget.destroy()

#     # ==========================
#     # REGISTRATION FLOW
#     # ==========================
#     def show_register_screen(self):
#         self.clear_frame()
#         self.temp_reg_data = {} # Reset temp data

#         bg_frame = ctk.CTkFrame(self, fg_color="transparent")
#         bg_frame.pack(fill="both", expand=True)

#         card = ctk.CTkFrame(bg_frame, width=450, height=550, corner_radius=20, fg_color=("white", "#2b2b2b"))
#         card.place(relx=0.5, rely=0.5, anchor="center")

#         ctk.CTkLabel(card, text="🛡️", font=("Arial", 60)).pack(pady=(40, 10))
#         ctk.CTkLabel(card, text="Step 1: Credentials", font=("Roboto Medium", 28)).pack(pady=(0, 5))
#         ctk.CTkLabel(card, text="Create your master login", font=("Roboto", 14), text_color="gray").pack(pady=(0, 20))
        
#         input_frame = ctk.CTkFrame(card, fg_color="transparent")
#         input_frame.pack(fill="x", padx=40)

#         uname = ctk.CTkEntry(input_frame, placeholder_text="Choose Username", height=45, width=300, font=("Roboto", 14))
#         uname.pack(pady=10)
        
#         pwd = ctk.CTkEntry(input_frame, placeholder_text="Master Password", show="●", height=45, width=300, font=("Roboto", 14))
#         pwd.pack(pady=10)
        
#         self.strength_bar = ctk.CTkProgressBar(input_frame, width=300, height=8, progress_color="#e74c3c")
#         self.strength_bar.set(0)
#         self.strength_bar.pack(pady=(5, 5))
        
#         self.strength_lbl = ctk.CTkLabel(input_frame, text="Password Strength: Weak", font=("Roboto", 11), text_color="#e74c3c")
#         self.strength_lbl.pack(pady=(0, 20))

#         def check_strength(e):
#             p = pwd.get()
#             score = 0
#             if len(p) >= 8: score += 0.25
#             if any(c.isupper() for c in p): score += 0.25
#             if any(c.isdigit() for c in p): score += 0.25
#             if any(c in "!@#$%^&*" for c in p): score += 0.25
            
#             self.strength_bar.set(score)
#             if score <= 0.25: color, text = "#e74c3c", "Weak"
#             elif score <= 0.5: color, text = "#f39c12", "Moderate"
#             elif score <= 0.75: color, text = "#f1c40f", "Good"
#             else: color, text = "#2ecc71", "Strong"
#             self.strength_bar.configure(progress_color=color)
#             self.strength_lbl.configure(text=f"Password Strength: {text}", text_color=color)

#         pwd.bind("<KeyRelease>", check_strength)

#         def next_step():
#             u, p = uname.get().strip(), pwd.get()
#             if not u or not p: 
#                 messagebox.showwarning("Missing Info", "Please fill in all fields.")
#                 return
            
#             # Basic Username Check
#             try:
#                 self.cursor.execute("SELECT 1 FROM users WHERE username=?", (u,))
#                 if self.cursor.fetchone():
#                     messagebox.showerror("Error", "Username already taken.")
#                     return
#             except: pass

#             if self.strength_bar.get() < 0.5:
#                 if not messagebox.askyesno("Weak Password", "Password is weak. Continue anyway?"): return

#             self.temp_reg_data['username'] = u
#             self.temp_reg_data['password'] = p
#             self.show_security_setup_screen()

#         ctk.CTkButton(card, text="Next Step ➔", command=next_step, width=300, height=45, 
#                       font=("Roboto Medium", 15), fg_color="#3498db", hover_color="#2980b9").pack(pady=20)

#     def show_security_setup_screen(self):
#         self.clear_frame()
        
#         bg_frame = ctk.CTkFrame(self, fg_color="transparent")
#         bg_frame.pack(fill="both", expand=True)

#         card = ctk.CTkFrame(bg_frame, width=450, height=550, corner_radius=20, fg_color=("white", "#2b2b2b"))
#         card.place(relx=0.5, rely=0.5, anchor="center")

#         ctk.CTkLabel(card, text="🔑", font=("Arial", 60)).pack(pady=(40, 10))
#         ctk.CTkLabel(card, text="Step 2: Recovery", font=("Roboto Medium", 28)).pack(pady=(0, 5))
#         ctk.CTkLabel(card, text="Set a question to recover your account", font=("Roboto", 14), text_color="gray").pack(pady=(0, 20))
        
#         input_frame = ctk.CTkFrame(card, fg_color="transparent")
#         input_frame.pack(fill="x", padx=40)

#         # Pre-defined questions or custom
#         questions = [
#             "What was the name of your first pet?",
#             "What is your mother's maiden name?",
#             "What city were you born in?",
#             "What is your favorite food?",
#             "Custom Question..."
#         ]
        
#         q_var = ctk.StringVar(value=questions[0])
#         q_menu = ctk.CTkComboBox(input_frame, values=questions, variable=q_var, height=45, width=300, font=("Roboto", 14))
#         q_menu.pack(pady=10)
        
#         # Entry for custom question (hidden logic simplified here, just allowing edit if needed or just use answer)
#         # For simplicity, we assume they pick one or type in the box if editable (CTkComboBox is editable by default)
        
#         ans_entry = ctk.CTkEntry(input_frame, placeholder_text="Your Answer", height=45, width=300, font=("Roboto", 14))
#         ans_entry.pack(pady=10)
        
#         ctk.CTkLabel(input_frame, text="* This is the ONLY way to recover your password.", font=("Roboto", 10), text_color="orange").pack(pady=5)

#         def finish_registration():
#             question = q_var.get().strip()
#             answer = ans_entry.get().strip().lower() # Normalize answer
            
#             if not question or not answer:
#                 messagebox.showwarning("Missing Info", "Please set a security question and answer.")
#                 return

#             # --- FINALIZATION LOGIC (MASTER KEY SYSTEM) ---
#             try:
#                 username = self.temp_reg_data['username']
#                 password = self.temp_reg_data['password']

#                 # 1. Generate Master Key
#                 master_key = Fernet.generate_key()

#                 # 2. Encrypt Master Key with Password
#                 pwd_salt = secrets.token_bytes(16).hex()
#                 pwd_key = self.derive_key(password, pwd_salt)
#                 enc_master_key_pwd = Fernet(pwd_key).encrypt(master_key)

#                 # 3. Encrypt Master Key with Security Answer
#                 rec_salt = secrets.token_bytes(16).hex()
#                 rec_key = self.derive_key(answer, rec_salt)
#                 enc_master_key_rec = Fernet(rec_key).encrypt(master_key)

#                 # 4. Store in DB
#                 self.cursor.execute("""
#                     INSERT INTO users (username, enc_master_key, password_salt, security_question, enc_recovery_key, recovery_salt) 
#                     VALUES (?, ?, ?, ?, ?, ?)
#                 """, (username, enc_master_key_pwd, pwd_salt, question, enc_master_key_rec, rec_salt))
                
#                 self.conn.commit()
#                 messagebox.showinfo("Success", "Vault Initialized! Please login.")
#                 self.show_login_screen()

#             except Exception as e:
#                 messagebox.showerror("Error", f"Registration failed: {str(e)}")
#                 traceback.print_exc()

#         ctk.CTkButton(card, text="Finish Setup", command=finish_registration, width=300, height=45, 
#                       font=("Roboto Medium", 15), fg_color="#27ae60", hover_color="#2ecc71").pack(pady=20)
        
#         ctk.CTkButton(card, text="Back", command=self.show_register_screen, width=300, fg_color="transparent", text_color="gray").pack()

#     # ==========================
#     # LOGIN FLOW
#     # ==========================
#     def show_login_screen(self):
#         self.clear_frame()
        
#         bg_frame = ctk.CTkFrame(self, fg_color="transparent")
#         bg_frame.pack(fill="both", expand=True)

#         card = ctk.CTkFrame(bg_frame, width=450, height=550, corner_radius=20, fg_color=("white", "#2b2b2b"))
#         card.place(relx=0.5, rely=0.5, anchor="center")

#         ctk.CTkLabel(card, text="🔒", font=("Arial", 60)).pack(pady=(40, 10))
#         ctk.CTkLabel(card, text="Welcome Back", font=("Roboto Medium", 28)).pack(pady=(0, 5))
#         ctk.CTkLabel(card, text="Enter credentials to unlock", font=("Roboto", 14), text_color="gray").pack(pady=(0, 30))
        
#         input_frame = ctk.CTkFrame(card, fg_color="transparent")
#         input_frame.pack(fill="x", padx=40)

#         uname = ctk.CTkEntry(input_frame, placeholder_text="Username", height=45, width=300, font=("Roboto", 14))
#         uname.pack(pady=10)
        
#         pwd = ctk.CTkEntry(input_frame, placeholder_text="Password", show="●", height=45, width=300, font=("Roboto", 14))
#         pwd.pack(pady=10)

#         status_lbl = ctk.CTkLabel(input_frame, text="", font=("Roboto", 12), text_color="#e74c3c")
#         status_lbl.pack(pady=(5, 0))

#         def login(event=None):
#             u, p = uname.get().strip(), pwd.get()
            
#             if self.locked_until and datetime.now() < self.locked_until:
#                 remain = int((self.locked_until - datetime.now()).total_seconds())
#                 status_lbl.configure(text=f"Locked out. Try again in {remain}s")
#                 return

#             self.cursor.execute("SELECT enc_master_key, password_salt FROM users WHERE username=?", (u,))
#             record = self.cursor.fetchone()
            
#             if record:
#                 enc_master, salt = record
#                 try:
#                     # Attempt Decryption
#                     derived_key = self.derive_key(p, salt)
#                     fernet = Fernet(derived_key)
#                     master_key = fernet.decrypt(enc_master)
                    
#                     # Success
#                     status_lbl.configure(text="Access Granted", text_color="#2ecc71")
#                     self.current_user = u
#                     self.encryption_key = master_key # Set the actual master key
#                     self.failed_attempts = 0
#                     self.last_activity = datetime.now()
#                     self.after(500, self.show_main_app)
#                     return
#                 except Exception:
#                     # Decryption failed = Wrong password
#                     pass
            
#             # Failure
#             self.failed_attempts += 1
#             if self.failed_attempts >= LOCKOUT_THRESHOLD:
#                 self.locked_until = datetime.now() + timedelta(seconds=LOCKOUT_SECONDS)
#                 status_lbl.configure(text=f"Locked for {LOCKOUT_SECONDS}s")
#             else:
#                 status_lbl.configure(text="Invalid Credentials")
            
#             self.log_action("Failed Login", u)

#         self.bind("<Return>", login)
        
#         ctk.CTkButton(card, text="Unlock Vault", command=login, width=300, height=45, 
#                       font=("Roboto Medium", 15), fg_color="#2ecc71", hover_color="#27ae60").pack(pady=20)
        
#         # Forgot Password Link
#         ctk.CTkButton(card, text="Forgot Password?", command=self.show_forgot_password_username, 
#                       fg_color="transparent", text_color="#3498db", font=("Roboto", 12)).pack(pady=10)

#     # ==========================
#     # FORGOT PASSWORD FLOW
#     # ==========================
#     def show_forgot_password_username(self):
#         # Step 1: Ask for username to retrieve specific question
#         username = simpledialog.askstring("Account Recovery", "Enter your username:")
#         if not username: return

#         self.cursor.execute("SELECT security_question, recovery_salt, enc_recovery_key FROM users WHERE username=?", (username,))
#         record = self.cursor.fetchone()

#         if not record:
#             messagebox.showerror("Error", "User not found.")
#             return

#         question, rec_salt, enc_rec_key = record
#         self.show_recovery_challenge(username, question, rec_salt, enc_rec_key)

#     def show_recovery_challenge(self, username, question, rec_salt, enc_rec_key):
#         self.clear_frame()
        
#         bg_frame = ctk.CTkFrame(self, fg_color="transparent")
#         bg_frame.pack(fill="both", expand=True)

#         card = ctk.CTkFrame(bg_frame, width=450, height=500, corner_radius=20, fg_color=("white", "#2b2b2b"))
#         card.place(relx=0.5, rely=0.5, anchor="center")

#         ctk.CTkLabel(card, text="❓", font=("Arial", 60)).pack(pady=(40, 10))
#         ctk.CTkLabel(card, text="Security Check", font=("Roboto Medium", 28)).pack(pady=(0, 5))
#         ctk.CTkLabel(card, text=f"Recovering account: {username}", font=("Roboto", 12), text_color="gray").pack()
        
#         input_frame = ctk.CTkFrame(card, fg_color="transparent")
#         input_frame.pack(fill="x", padx=40, pady=20)

#         ctk.CTkLabel(input_frame, text="Security Question:", font=("Roboto", 12, "bold")).pack(anchor="w")
#         ctk.CTkLabel(input_frame, text=question, font=("Roboto", 14), text_color="#3498db", wraplength=350).pack(pady=(5, 20))

#         ans_entry = ctk.CTkEntry(input_frame, placeholder_text="Your Answer", height=45, width=300, font=("Roboto", 14))
#         ans_entry.pack(pady=10)

#         def verify_recovery():
#             answer = ans_entry.get().strip().lower()
#             if not answer: return

#             try:
#                 # 1. Derive recovery key from answer
#                 rec_key = self.derive_key(answer, rec_salt)
                
#                 # 2. Try to decrypt the Master Key
#                 fernet = Fernet(rec_key)
#                 master_key = fernet.decrypt(enc_rec_key)

#                 # If we are here, answer is correct!
#                 # Now we ask for a NEW Password
#                 new_pwd = simpledialog.askstring("Reset Password", "Enter your NEW Master Password:", show='*')
#                 if not new_pwd or len(new_pwd) < 4:
#                     messagebox.showerror("Error", "Invalid password.")
#                     return

#                 # 3. Re-encrypt Master Key with NEW password
#                 new_pwd_salt = secrets.token_bytes(16).hex()
#                 new_pwd_key = self.derive_key(new_pwd, new_pwd_salt)
#                 new_enc_master = Fernet(new_pwd_key).encrypt(master_key)

#                 # 4. Update DB
#                 self.cursor.execute("UPDATE users SET enc_master_key=?, password_salt=? WHERE username=?", 
#                                     (new_enc_master, new_pwd_salt, username))
#                 self.conn.commit()

#                 messagebox.showinfo("Success", "Password reset successfully! You can now login.")
#                 self.show_login_screen()

#             except Exception:
#                 messagebox.showerror("Error", "Incorrect Answer. Access Denied.")

#         ctk.CTkButton(card, text="Verify & Reset", command=verify_recovery, width=300, height=45, 
#                       font=("Roboto Medium", 15), fg_color="#e67e22", hover_color="#d35400").pack(pady=20)
        
#         ctk.CTkButton(card, text="Cancel", command=self.show_login_screen, fg_color="transparent", text_color="gray").pack()

#     def perform_logout(self, auto=False):
#         self.current_user = None
#         self.encryption_key = None
#         self.unbind("<Return>")
#         if auto:
#             messagebox.showinfo("Auto-Lock", "Vault locked due to inactivity.")
#         self.show_login_screen()

#     def show_main_app(self):
#         self.clear_frame()
#         self.bind("<Any-KeyPress>", self._update_activity)
#         self.bind("<Any-ButtonPress>", self._update_activity)

#         self.tab_view = ctk.CTkTabview(self)
#         self.tab_view.pack(fill="both", expand=True, padx=20, pady=20)
        
#         self.tab_dash = self.tab_view.add("Dashboard")
#         self.tab_logs = self.tab_view.add("Audit Logs")
#         self.tab_settings = self.tab_view.add("Settings")
        
#         self.setup_dashboard()
#         self.setup_logs()
#         self.setup_settings()

#     # --- DASHBOARD TAB ---
#     def setup_dashboard(self):
#         top_frame = ctk.CTkFrame(self.tab_dash, fg_color="transparent")
#         top_frame.pack(fill="x", pady=10)
#         ctk.CTkLabel(top_frame, text=f"Welcome, {self.current_user}", font=("Roboto", 20, "bold")).pack(side="left")
#         ctk.CTkButton(top_frame, text="Logout", width=100, fg_color="#c0392b", hover_color="#e74c3c", 
#                       command=self.perform_logout).pack(side="right")

#         btn_frame = ctk.CTkFrame(self.tab_dash, fg_color="transparent")
#         btn_frame.pack(pady=20)

#         btn_config = [
#             ("🔒 Lock File", self.thread_lock_file, "#2980b9"),
#             ("📂 Lock Folder", self.thread_lock_folder, "#d35400"),
#             ("🔓 Unlock Item", self.thread_unlock, "#27ae60")
#         ]

#         for text, cmd, color in btn_config:
#             ctk.CTkButton(btn_frame, text=text, command=cmd, width=200, height=50, 
#                           font=("Roboto", 16), fg_color=color).pack(side="left", padx=10)

#         self.progress_bar = ctk.CTkProgressBar(self.tab_dash, width=600)
#         self.progress_bar.set(0)
#         self.progress_bar.pack(pady=10)

#         self.console = ctk.CTkTextbox(self.tab_dash, width=700, height=300, font=("Consolas", 12))
#         self.console.pack(fill="both", expand=True, pady=10)
#         self.console.insert("1.0", f"[{datetime.now().strftime('%H:%M:%S')}] Vault Unlocked. Master Key Active.\n")

#     def _log_to_console_internal(self, text):
#         self.console.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
#         self.console.see("end")

#     def _update_progress_internal(self, value):
#         self.progress_bar.set(value)

#     # --- LOGS TAB ---
#     def setup_logs(self):
#         ctk.CTkButton(self.tab_logs, text="Refresh Logs", command=self.refresh_logs).pack(pady=10)
#         self.log_frame = ctk.CTkScrollableFrame(self.tab_logs, width=800, height=500)
#         self.log_frame.pack(fill="both", expand=True)
#         self.refresh_logs()

#     def refresh_logs(self):
#         for w in self.log_frame.winfo_children(): w.destroy()
#         self.cursor.execute("SELECT timestamp, action, filename FROM logs ORDER BY id DESC LIMIT 100")
#         for ts, act, file in self.cursor.fetchall():
#             row = ctk.CTkFrame(self.log_frame)
#             row.pack(fill="x", pady=2)
#             c = "#e74c3c" if "Lock" in act else "#2ecc71"
#             ctk.CTkLabel(row, text=ts, width=150, font=("Consolas", 11)).pack(side="left")
#             ctk.CTkLabel(row, text=act, width=100, text_color=c, font=("Roboto", 12, "bold")).pack(side="left")
#             ctk.CTkLabel(row, text=file, font=("Roboto", 11)).pack(side="left", padx=10)

#     # --- SETTINGS TAB ---
#     def setup_settings(self):
#         # Change Password Section
#         frame = ctk.CTkFrame(self.tab_settings)
#         frame.pack(pady=20, padx=20, fill="x")
        
#         ctk.CTkLabel(frame, text="Change Password", font=("Roboto", 16, "bold")).pack(pady=10)
#         self.new_pass_entry = ctk.CTkEntry(frame, placeholder_text="New Password", show="*", width=300)
#         self.new_pass_entry.pack(pady=5)
#         ctk.CTkButton(frame, text="Update Password", command=self.change_password).pack(pady=10)

#         # FACTORY RESET SECTION
#         danger_frame = ctk.CTkFrame(self.tab_settings, fg_color="#571d1d") # Reddish background
#         danger_frame.pack(pady=40, padx=20, fill="x")
        
#         ctk.CTkLabel(danger_frame, text="DANGER ZONE", font=("Roboto", 16, "bold"), text_color="#e74c3c").pack(pady=10)
#         ctk.CTkLabel(danger_frame, text="Factory Reset will wipe all user data, keys, and logs.\nAny currently locked files will be PERMANENTLY inaccessible.", 
#                      text_color="white", font=("Roboto", 12)).pack(pady=5)
        
#         ctk.CTkButton(danger_frame, text="⚠️ FACTORY RESET VAULT ⚠️", command=self.factory_reset, 
#                       fg_color="#c0392b", hover_color="#a93226").pack(pady=20)

#     def change_password(self):
#         new_pw = self.new_pass_entry.get()
#         if len(new_pw) < 4:
#             messagebox.showerror("Error", "Password too short")
#             return
        
#         try:
#             # Re-encrypt MASTER KEY with NEW password
#             # We don't need to touch the recovery key here
#             new_salt = secrets.token_bytes(16).hex()
#             new_key = self.derive_key(new_pw, new_salt)
            
#             # The encryption_key variable currently holds the RAW decrypted Master Key
#             new_enc_master = Fernet(new_key).encrypt(self.encryption_key)
            
#             self.cursor.execute("UPDATE users SET enc_master_key=?, password_salt=? WHERE username=?", 
#                                 (new_enc_master, new_salt, self.current_user))
#             self.conn.commit()
            
#             messagebox.showinfo("Success", "Password Updated successfully.")
#             self.new_pass_entry.delete(0, 'end')
#         except Exception as e:
#             messagebox.showerror("Error", str(e))

#     def factory_reset(self):
#         confirm = messagebox.askyesno("CONFIRM RESET", "Are you absolute sure?\n\nThis will DELETE the database.\nAll files currently locked will remain encrypted forever (unrecoverable).\n\nProceed?")
#         if confirm:
#             try:
#                 self.conn.close()
#                 os.remove(DB_NAME)
#                 messagebox.showinfo("Reset", "Vault has been reset. Restarting...")
#                 # Re-init DB
#                 self.init_db()
#                 self.perform_logout()
#                 self.show_register_screen()
#             except Exception as e:
#                 messagebox.showerror("Error", f"Failed to reset: {e}")

#     # --- WORKER THREADS ---
#     def thread_lock_file(self):
#         threading.Thread(target=self._lock_file_logic, daemon=True).start()

#     def thread_lock_folder(self):
#         threading.Thread(target=self._lock_folder_logic, daemon=True).start()

#     def thread_unlock(self):
#         threading.Thread(target=self._unlock_logic, daemon=True).start()

#     # --- CRYPTO LOGIC ---
#     def _lock_file_logic(self):
#         path = filedialog.askopenfilename()
#         if not path: return
#         self.safe_log(f"Starting encryption: {os.path.basename(path)}")
#         self.safe_progress(0.1)
#         self._encrypt_single_file(path)
#         self.safe_progress(1.0)
#         self.safe_log("File encryption complete.")

#     def _lock_folder_logic(self):
#         folder = filedialog.askdirectory()
#         if not folder: return
        
#         self.safe_log(f"Scanning folder: {folder}...")
#         files_to_process = []
#         for root, _, files in os.walk(folder):
#             for f in files:
#                 if not f.endswith(".enc"):
#                     files_to_process.append(os.path.join(root, f))
        
#         total = len(files_to_process)
#         if total == 0:
#             self.safe_log("Folder empty or already encrypted.")
#             return

#         self.safe_log(f"Found {total} files. Starting batch encryption...")
        
#         completed = 0
#         futures = []
        
#         for fpath in files_to_process:
#             future = self.executor.submit(self._encrypt_single_file, fpath)
#             futures.append(future)

#         for future in concurrent.futures.as_completed(futures):
#             completed += 1
#             progress = completed / total
#             self.safe_progress(progress)
        
#         self.safe_log(f"Folder encryption finished. {total} files secured.")
#         self.safe_info("Complete", f"Securely locked {total} files.")

#     def _encrypt_single_file(self, file_path):
#         try:
#             with open(file_path, 'rb') as f:
#                 data = f.read()
            
#             # Use Master Key for encryption
#             fernet = Fernet(self.encryption_key)
#             encrypted_data = fernet.encrypt(data)
            
#             temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(file_path))
#             with os.fdopen(temp_fd, 'wb') as tf:
#                 tf.write(encrypted_data)
            
#             final_path = file_path + ".enc"
#             os.replace(temp_path, final_path)
            
#             with open(file_path, 'wb') as f:
#                 f.write(secrets.token_bytes(len(data))) 
#             os.remove(file_path)
            
#             self.safe_log(f"Locked: {os.path.basename(file_path)}")
#             self.log_action("Lock", os.path.basename(file_path))
            
#         except Exception as e:
#             self.safe_log(f"Error locking {os.path.basename(file_path)}: {e}")

#     def _unlock_logic(self):
#         files = filedialog.askopenfilenames(filetypes=[("Encrypted", "*.enc")])
#         if not files: return
        
#         total = len(files)
#         completed = 0
#         self.safe_log(f"Unlocking {total} items...")
        
#         for path in files:
#             try:
#                 with open(path, 'rb') as f:
#                     data = f.read()
                
#                 fernet = Fernet(self.encryption_key)
#                 decrypted_data = fernet.decrypt(data)
                
#                 orig_path = path[:-4] 
                
#                 temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(path))
#                 with os.fdopen(temp_fd, 'wb') as tf:
#                     tf.write(decrypted_data)
                
#                 os.replace(temp_path, orig_path)
#                 os.remove(path)
                
#                 self.safe_log(f"Unlocked: {os.path.basename(orig_path)}")
#                 self.log_action("Unlock", os.path.basename(orig_path))
                
#             except Exception as e:
#                 self.safe_log(f"Failed {os.path.basename(path)}: Bad Key or Corrupt")
            
#             completed += 1
#             self.safe_progress(completed / total)

#         self.safe_log("Unlock sequence finished.")
#         self.safe_info("Complete", "Selected files have been unlocked.")

# if __name__ == '__main__':
#     app = ModernVaultApp()
#     app.mainloop()

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import sqlite3
import os
import threading
import queue
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import tempfile
import secrets
import concurrent.futures
import traceback

# --- CONFIGURATION ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")
DB_NAME = "vault_data.db"
KDF_ITERATIONS = 200_000  # High iteration count for security
LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 30
AUTO_LOCK_SECONDS = 300  # 5 minutes
THREAD_POOL_WORKERS = 4

class ModernVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure Vault Pro")
        self.geometry("1000x700")
        self.minsize(900, 650)
        
        # --- State Variables ---
        self.current_user = None
        self.encryption_key = None # This is now the MASTER KEY, decrypted by password/recovery
        self.last_activity = datetime.now()
        self.failed_attempts = 0
        self.locked_until = None
        self.temp_reg_data = {} # Holds data between registration steps
        
        # --- Thread Safety Queue ---
        self.gui_queue = queue.Queue()

        # --- Database & Thread Pool ---
        self.init_db()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=THREAD_POOL_WORKERS)

        # --- UI Setup ---
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Check for existing users
        if self.any_user_exists():
            self.show_login_screen()
        else:
            self.show_register_screen()

        # Start periodic tasks
        self.after(100, self.process_gui_queue)
        self.after(1000, self._auto_lock_check)

    # --- CORE: Thread-Safe UI Updates ---
    def process_gui_queue(self):
        """Reads tasks from the queue and executes them in the main thread."""
        try:
            while True:
                task = self.gui_queue.get_nowait()
                action = task.get("action")
                
                if action == "log":
                    self._log_to_console_internal(task["text"])
                elif action == "progress":
                    self._update_progress_internal(task["value"])
                elif action == "messagebox":
                    messagebox.showinfo(task["title"], task["message"])
                elif action == "errorbox":
                    messagebox.showerror(task["title"], task["message"])
                elif action == "switch_screen":
                    # Useful for changing screens from threads if needed
                    pass 
                
                self.gui_queue.task_done()
        except queue.Empty:
            pass
        finally:
            self.after(100, self.process_gui_queue)

    def safe_log(self, text):
        self.gui_queue.put({"action": "log", "text": text})

    def safe_progress(self, value):
        self.gui_queue.put({"action": "progress", "value": value})

    def safe_info(self, title, message):
        self.gui_queue.put({"action": "messagebox", "title": title, "message": message})
        
    def safe_error(self, title, message):
        self.gui_queue.put({"action": "errorbox", "title": title, "message": message})

    # --- DATABASE ---
    def init_db(self):
        self.conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Updated Schema for Master Key System
        # enc_master_key: The master key encrypted by the user's password
        # enc_recovery_key: The master key encrypted by the security answer
        try:
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    enc_master_key BLOB,
                    password_salt TEXT,
                    security_question TEXT,
                    enc_recovery_key BLOB,
                    recovery_salt TEXT
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    action TEXT,
                    filename TEXT,
                    timestamp TEXT
                )
            ''')
            self.conn.commit()
        except sqlite3.OperationalError:
            # Handle schema migration or corruption by just alerting (Simplification)
            messagebox.showerror("Database Error", "Database schema mismatch. Please use Factory Reset in settings or delete vault_data.db")

    def any_user_exists(self):
        try:
            self.cursor.execute("SELECT 1 FROM users LIMIT 1")
            return self.cursor.fetchone() is not None
        except:
            return False

    def log_action(self, action, filename=""):
        try:
            time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            user = self.current_user or "System"
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO logs (username, action, filename, timestamp) VALUES (?, ?, ?, ?)",
                               (user, action, filename, time_now))
                conn.commit()
        except Exception as e:
            print(f"Log Error: {e}")

    # --- CRYPTO HELPER ---
    def derive_key(self, password: str, salt_hex: str):
        """Derives a 32-byte key from a password/answer and salt."""
        salt = bytes.fromhex(salt_hex)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # --- LOGIC ---
    def _update_activity(self, event=None):
        self.last_activity = datetime.now()

    def _auto_lock_check(self):
        if self.current_user:
            elapsed = (datetime.now() - self.last_activity).total_seconds()
            if elapsed > AUTO_LOCK_SECONDS:
                self.perform_logout(auto=True)
                return
        self.after(1000, self._auto_lock_check)

    # --- GUI: SCREEN MANAGEMENT ---
    def clear_frame(self):
        for widget in self.winfo_children():
            widget.destroy()

    # ==========================
    # REGISTRATION FLOW
    # ==========================
    def show_register_screen(self):
        self.clear_frame()
        self.temp_reg_data = {} # Reset temp data

        bg_frame = ctk.CTkFrame(self, fg_color="transparent")
        bg_frame.pack(fill="both", expand=True)

        card = ctk.CTkFrame(bg_frame, width=450, height=550, corner_radius=20, fg_color=("white", "#2b2b2b"))
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="🛡️", font=("Arial", 60)).pack(pady=(40, 10))
        ctk.CTkLabel(card, text="Step 1: Credentials", font=("Roboto Medium", 28)).pack(pady=(0, 5))
        ctk.CTkLabel(card, text="Create your master login", font=("Roboto", 14), text_color="gray").pack(pady=(0, 20))
        
        input_frame = ctk.CTkFrame(card, fg_color="transparent")
        input_frame.pack(fill="x", padx=40)

        uname = ctk.CTkEntry(input_frame, placeholder_text="Choose Username", height=45, width=300, font=("Roboto", 14))
        uname.pack(pady=10)
        
        pwd = ctk.CTkEntry(input_frame, placeholder_text="Master Password", show="●", height=45, width=300, font=("Roboto", 14))
        pwd.pack(pady=10)
        
        self.strength_bar = ctk.CTkProgressBar(input_frame, width=300, height=8, progress_color="#e74c3c")
        self.strength_bar.set(0)
        self.strength_bar.pack(pady=(5, 5))
        
        self.strength_lbl = ctk.CTkLabel(input_frame, text="Password Strength: Weak", font=("Roboto", 11), text_color="#e74c3c")
        self.strength_lbl.pack(pady=(0, 20))

        def check_strength(e):
            p = pwd.get()
            score = 0
            if len(p) >= 8: score += 0.25
            if any(c.isupper() for c in p): score += 0.25
            if any(c.isdigit() for c in p): score += 0.25
            if any(c in "!@#$%^&*" for c in p): score += 0.25
            
            self.strength_bar.set(score)
            if score <= 0.25: color, text = "#e74c3c", "Weak"
            elif score <= 0.5: color, text = "#f39c12", "Moderate"
            elif score <= 0.75: color, text = "#f1c40f", "Good"
            else: color, text = "#2ecc71", "Strong"
            self.strength_bar.configure(progress_color=color)
            self.strength_lbl.configure(text=f"Password Strength: {text}", text_color=color)

        pwd.bind("<KeyRelease>", check_strength)

        def next_step():
            u, p = uname.get().strip(), pwd.get()
            if not u or not p: 
                messagebox.showwarning("Missing Info", "Please fill in all fields.")
                return
            
            # Basic Username Check
            try:
                self.cursor.execute("SELECT 1 FROM users WHERE username=?", (u,))
                if self.cursor.fetchone():
                    messagebox.showerror("Error", "Username already taken.")
                    return
            except: pass

            if self.strength_bar.get() < 0.5:
                if not messagebox.askyesno("Weak Password", "Password is weak. Continue anyway?"): return

            self.temp_reg_data['username'] = u
            self.temp_reg_data['password'] = p
            self.show_security_setup_screen()

        ctk.CTkButton(card, text="Next Step ➔", command=next_step, width=300, height=45, 
                      font=("Roboto Medium", 15), fg_color="#3498db", hover_color="#2980b9").pack(pady=20)

    def show_security_setup_screen(self):
        self.clear_frame()
        
        bg_frame = ctk.CTkFrame(self, fg_color="transparent")
        bg_frame.pack(fill="both", expand=True)

        card = ctk.CTkFrame(bg_frame, width=450, height=550, corner_radius=20, fg_color=("white", "#2b2b2b"))
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="🔑", font=("Arial", 60)).pack(pady=(40, 10))
        ctk.CTkLabel(card, text="Step 2: Recovery", font=("Roboto Medium", 28)).pack(pady=(0, 5))
        ctk.CTkLabel(card, text="Set a question to recover your account", font=("Roboto", 14), text_color="gray").pack(pady=(0, 20))
        
        input_frame = ctk.CTkFrame(card, fg_color="transparent")
        input_frame.pack(fill="x", padx=40)

        # Pre-defined questions or custom
        questions = [
            "What was the name of your first pet?",
            "What is your mother's maiden name?",
            "What city were you born in?",
            "What is your favorite food?",
            "Custom Question..."
        ]
        
        q_var = ctk.StringVar(value=questions[0])
        q_menu = ctk.CTkComboBox(input_frame, values=questions, variable=q_var, height=45, width=300, font=("Roboto", 14))
        q_menu.pack(pady=10)
        
        # Entry for custom question (hidden logic simplified here, just allowing edit if needed or just use answer)
        # For simplicity, we assume they pick one or type in the box if editable (CTkComboBox is editable by default)
        
        ans_entry = ctk.CTkEntry(input_frame, placeholder_text="Your Answer", height=45, width=300, font=("Roboto", 14))
        ans_entry.pack(pady=10)
        
        ctk.CTkLabel(input_frame, text="* This is the ONLY way to recover your password.", font=("Roboto", 10), text_color="orange").pack(pady=5)

        def finish_registration():
            question = q_var.get().strip()
            answer = ans_entry.get().strip().lower() # Normalize answer
            
            if not question or not answer:
                messagebox.showwarning("Missing Info", "Please set a security question and answer.")
                return

            # --- FINALIZATION LOGIC (MASTER KEY SYSTEM) ---
            try:
                username = self.temp_reg_data['username']
                password = self.temp_reg_data['password']

                # 1. Generate Master Key
                master_key = Fernet.generate_key()

                # 2. Encrypt Master Key with Password
                pwd_salt = secrets.token_bytes(16).hex()
                pwd_key = self.derive_key(password, pwd_salt)
                enc_master_key_pwd = Fernet(pwd_key).encrypt(master_key)

                # 3. Encrypt Master Key with Security Answer
                rec_salt = secrets.token_bytes(16).hex()
                rec_key = self.derive_key(answer, rec_salt)
                enc_master_key_rec = Fernet(rec_key).encrypt(master_key)

                # 4. Store in DB
                self.cursor.execute("""
                    INSERT INTO users (username, enc_master_key, password_salt, security_question, enc_recovery_key, recovery_salt) 
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (username, enc_master_key_pwd, pwd_salt, question, enc_master_key_rec, rec_salt))
                
                self.conn.commit()
                messagebox.showinfo("Success", "Vault Initialized! Please login.")
                self.show_login_screen()

            except Exception as e:
                messagebox.showerror("Error", f"Registration failed: {str(e)}")
                traceback.print_exc()

        ctk.CTkButton(card, text="Finish Setup", command=finish_registration, width=300, height=45, 
                      font=("Roboto Medium", 15), fg_color="#27ae60", hover_color="#2ecc71").pack(pady=20)
        
        ctk.CTkButton(card, text="Back", command=self.show_register_screen, width=300, fg_color="transparent", text_color="gray").pack()

    # ==========================
    # LOGIN FLOW
    # ==========================
    def show_login_screen(self):
        self.clear_frame()
        
        bg_frame = ctk.CTkFrame(self, fg_color="transparent")
        bg_frame.pack(fill="both", expand=True)

        card = ctk.CTkFrame(bg_frame, width=450, height=550, corner_radius=20, fg_color=("white", "#2b2b2b"))
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="🔒", font=("Arial", 60)).pack(pady=(40, 10))
        ctk.CTkLabel(card, text="Welcome Back", font=("Roboto Medium", 28)).pack(pady=(0, 5))
        ctk.CTkLabel(card, text="Enter credentials to unlock", font=("Roboto", 14), text_color="gray").pack(pady=(0, 30))
        
        input_frame = ctk.CTkFrame(card, fg_color="transparent")
        input_frame.pack(fill="x", padx=40)

        uname = ctk.CTkEntry(input_frame, placeholder_text="Username", height=45, width=300, font=("Roboto", 14))
        uname.pack(pady=10)
        
        pwd = ctk.CTkEntry(input_frame, placeholder_text="Password", show="●", height=45, width=300, font=("Roboto", 14))
        pwd.pack(pady=10)

        status_lbl = ctk.CTkLabel(input_frame, text="", font=("Roboto", 12), text_color="#e74c3c")
        status_lbl.pack(pady=(5, 0))

        def login(event=None):
            u, p = uname.get().strip(), pwd.get()
            
            if self.locked_until and datetime.now() < self.locked_until:
                remain = int((self.locked_until - datetime.now()).total_seconds())
                status_lbl.configure(text=f"Locked out. Try again in {remain}s")
                return

            self.cursor.execute("SELECT enc_master_key, password_salt FROM users WHERE username=?", (u,))
            record = self.cursor.fetchone()
            
            if record:
                enc_master, salt = record
                try:
                    # Attempt Decryption
                    derived_key = self.derive_key(p, salt)
                    fernet = Fernet(derived_key)
                    master_key = fernet.decrypt(enc_master)
                    
                    # Success
                    status_lbl.configure(text="Access Granted", text_color="#2ecc71")
                    self.current_user = u
                    self.encryption_key = master_key # Set the actual master key
                    self.failed_attempts = 0
                    self.last_activity = datetime.now()
                    self.after(500, self.show_main_app)
                    return
                except Exception:
                    # Decryption failed = Wrong password
                    pass
            
            # Failure
            self.failed_attempts += 1
            if self.failed_attempts >= LOCKOUT_THRESHOLD:
                self.locked_until = datetime.now() + timedelta(seconds=LOCKOUT_SECONDS)
                status_lbl.configure(text=f"Locked for {LOCKOUT_SECONDS}s")
            else:
                status_lbl.configure(text="Invalid Credentials")
            
            self.log_action("Failed Login", u)

        self.bind("<Return>", login)
        
        ctk.CTkButton(card, text="Unlock Vault", command=login, width=300, height=45, 
                      font=("Roboto Medium", 15), fg_color="#2ecc71", hover_color="#27ae60").pack(pady=20)
        
        # Forgot Password Link
        ctk.CTkButton(card, text="Forgot Password?", command=self.show_forgot_password_username, 
                      fg_color="transparent", text_color="#3498db", font=("Roboto", 12)).pack(pady=10)

    # ==========================
    # FORGOT PASSWORD FLOW
    # ==========================
    def show_forgot_password_username(self):
        # New UI implementation replacing simpledialog
        self.clear_frame()
        
        bg_frame = ctk.CTkFrame(self, fg_color="transparent")
        bg_frame.pack(fill="both", expand=True)

        card = ctk.CTkFrame(bg_frame, width=450, height=400, corner_radius=20, fg_color=("white", "#2b2b2b"))
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="🔍", font=("Arial", 60)).pack(pady=(40, 10))
        ctk.CTkLabel(card, text="Find Account", font=("Roboto Medium", 28)).pack(pady=(0, 5))
        ctk.CTkLabel(card, text="Enter your username to continue", font=("Roboto", 12), text_color="gray").pack()

        input_frame = ctk.CTkFrame(card, fg_color="transparent")
        input_frame.pack(fill="x", padx=40, pady=20)
        
        uname_entry = ctk.CTkEntry(input_frame, placeholder_text="Username", height=45, width=300, font=("Roboto", 14))
        uname_entry.pack(pady=10)

        def attempt_find():
            username = uname_entry.get().strip()
            if not username: return
            
            self.cursor.execute("SELECT security_question, recovery_salt, enc_recovery_key FROM users WHERE username=?", (username,))
            record = self.cursor.fetchone()

            if not record:
                messagebox.showerror("Error", "User not found.")
                return

            question, rec_salt, enc_rec_key = record
            self.show_recovery_challenge(username, question, rec_salt, enc_rec_key)

        ctk.CTkButton(card, text="Next", command=attempt_find, width=300, height=45, 
                      font=("Roboto Medium", 15), fg_color="#3498db", hover_color="#2980b9").pack(pady=10)
        
        ctk.CTkButton(card, text="Cancel", command=self.show_login_screen, fg_color="transparent", text_color="gray").pack()

    def show_recovery_challenge(self, username, question, rec_salt, enc_rec_key):
        self.clear_frame()
        
        bg_frame = ctk.CTkFrame(self, fg_color="transparent")
        bg_frame.pack(fill="both", expand=True)

        # Increased height for extra fields
        card = ctk.CTkFrame(bg_frame, width=450, height=600, corner_radius=20, fg_color=("white", "#2b2b2b"))
        card.place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(card, text="🔐", font=("Arial", 60)).pack(pady=(30, 10))
        ctk.CTkLabel(card, text="Reset Password", font=("Roboto Medium", 28)).pack(pady=(0, 5))
        ctk.CTkLabel(card, text=f"Account: {username}", font=("Roboto", 12), text_color="gray").pack()
        
        input_frame = ctk.CTkFrame(card, fg_color="transparent")
        input_frame.pack(fill="x", padx=40, pady=10)

        # Q & A Section
        ctk.CTkLabel(input_frame, text="Security Question:", font=("Roboto", 12, "bold")).pack(anchor="w")
        ctk.CTkLabel(input_frame, text=question, font=("Roboto", 14), text_color="#3498db", wraplength=350).pack(pady=(5, 15))

        ans_entry = ctk.CTkEntry(input_frame, placeholder_text="Security Answer", height=45, width=300, font=("Roboto", 14))
        ans_entry.pack(pady=(0, 15))

        # New Password Section
        ctk.CTkLabel(input_frame, text="Set New Password:", font=("Roboto", 12, "bold")).pack(anchor="w")
        new_pwd_entry = ctk.CTkEntry(input_frame, placeholder_text="New Master Password", show="●", height=45, width=300, font=("Roboto", 14))
        new_pwd_entry.pack(pady=(5, 10))

        def verify_and_reset():
            answer = ans_entry.get().strip().lower()
            new_pwd = new_pwd_entry.get()
            
            if not answer or not new_pwd:
                messagebox.showwarning("Missing Info", "Please fill in all fields.")
                return

            if len(new_pwd) < 4:
                messagebox.showerror("Weak Password", "Password must be at least 4 characters.")
                return

            try:
                # 1. Derive recovery key from answer
                rec_key = self.derive_key(answer, rec_salt)
                
                # 2. Try to decrypt the Master Key (Verification Step)
                fernet = Fernet(rec_key)
                master_key = fernet.decrypt(enc_rec_key)

                # 3. Re-encrypt Master Key with NEW password
                new_pwd_salt = secrets.token_bytes(16).hex()
                new_pwd_key = self.derive_key(new_pwd, new_pwd_salt)
                new_enc_master = Fernet(new_pwd_key).encrypt(master_key)

                # 4. Update DB
                self.cursor.execute("UPDATE users SET enc_master_key=?, password_salt=? WHERE username=?", 
                                    (new_enc_master, new_pwd_salt, username))
                self.conn.commit()

                messagebox.showinfo("Success", "Password reset successfully! Login with your new password.")
                self.show_login_screen()

            except Exception:
                # This usually means decryption failed due to wrong answer
                messagebox.showerror("Error", "Incorrect Security Answer. Cannot reset.")

        ctk.CTkButton(card, text="Reset Password", command=verify_and_reset, width=300, height=45, 
                      font=("Roboto Medium", 15), fg_color="#e67e22", hover_color="#d35400").pack(pady=20)
        
        ctk.CTkButton(card, text="Cancel", command=self.show_login_screen, fg_color="transparent", text_color="gray").pack()

    def perform_logout(self, auto=False):
        self.current_user = None
        self.encryption_key = None
        self.unbind("<Return>")
        if auto:
            messagebox.showinfo("Auto-Lock", "Vault locked due to inactivity.")
        self.show_login_screen()

    def show_main_app(self):
        self.clear_frame()
        self.bind("<Any-KeyPress>", self._update_activity)
        self.bind("<Any-ButtonPress>", self._update_activity)

        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.tab_dash = self.tab_view.add("Dashboard")
        self.tab_logs = self.tab_view.add("Audit Logs")
        self.tab_settings = self.tab_view.add("Settings")
        
        self.setup_dashboard()
        self.setup_logs()
        self.setup_settings()

    # --- DASHBOARD TAB ---
    def setup_dashboard(self):
        top_frame = ctk.CTkFrame(self.tab_dash, fg_color="transparent")
        top_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(top_frame, text=f"Welcome, {self.current_user}", font=("Roboto", 20, "bold")).pack(side="left")
        ctk.CTkButton(top_frame, text="Logout", width=100, fg_color="#c0392b", hover_color="#e74c3c", 
                      command=self.perform_logout).pack(side="right")

        btn_frame = ctk.CTkFrame(self.tab_dash, fg_color="transparent")
        btn_frame.pack(pady=20)

        btn_config = [
            ("🔒 Lock File", self.thread_lock_file, "#2980b9"),
            ("📂 Lock Folder", self.thread_lock_folder, "#d35400"),
            ("🔓 Unlock Item", self.thread_unlock, "#27ae60")
        ]

        for text, cmd, color in btn_config:
            ctk.CTkButton(btn_frame, text=text, command=cmd, width=200, height=50, 
                          font=("Roboto", 16), fg_color=color).pack(side="left", padx=10)

        self.progress_bar = ctk.CTkProgressBar(self.tab_dash, width=600)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=10)

        self.console = ctk.CTkTextbox(self.tab_dash, width=700, height=300, font=("Consolas", 12))
        self.console.pack(fill="both", expand=True, pady=10)
        self.console.insert("1.0", f"[{datetime.now().strftime('%H:%M:%S')}] Vault Unlocked. Master Key Active.\n")

    def _log_to_console_internal(self, text):
        self.console.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
        self.console.see("end")

    def _update_progress_internal(self, value):
        self.progress_bar.set(value)

    # --- LOGS TAB ---
    def setup_logs(self):
        ctk.CTkButton(self.tab_logs, text="Refresh Logs", command=self.refresh_logs).pack(pady=10)
        self.log_frame = ctk.CTkScrollableFrame(self.tab_logs, width=800, height=500)
        self.log_frame.pack(fill="both", expand=True)
        self.refresh_logs()

    def refresh_logs(self):
        for w in self.log_frame.winfo_children(): w.destroy()
        self.cursor.execute("SELECT timestamp, action, filename FROM logs ORDER BY id DESC LIMIT 100")
        for ts, act, file in self.cursor.fetchall():
            row = ctk.CTkFrame(self.log_frame)
            row.pack(fill="x", pady=2)
            c = "#e74c3c" if "Lock" in act else "#2ecc71"
            ctk.CTkLabel(row, text=ts, width=150, font=("Consolas", 11)).pack(side="left")
            ctk.CTkLabel(row, text=act, width=100, text_color=c, font=("Roboto", 12, "bold")).pack(side="left")
            ctk.CTkLabel(row, text=file, font=("Roboto", 11)).pack(side="left", padx=10)

    # --- SETTINGS TAB ---
    def setup_settings(self):
        # Change Password Section
        frame = ctk.CTkFrame(self.tab_settings)
        frame.pack(pady=20, padx=20, fill="x")
        
        ctk.CTkLabel(frame, text="Change Password", font=("Roboto", 16, "bold")).pack(pady=10)
        self.new_pass_entry = ctk.CTkEntry(frame, placeholder_text="New Password", show="*", width=300)
        self.new_pass_entry.pack(pady=5)
        ctk.CTkButton(frame, text="Update Password", command=self.change_password).pack(pady=10)

        # FACTORY RESET SECTION
        danger_frame = ctk.CTkFrame(self.tab_settings, fg_color="#571d1d") # Reddish background
        danger_frame.pack(pady=40, padx=20, fill="x")
        
        ctk.CTkLabel(danger_frame, text="DANGER ZONE", font=("Roboto", 16, "bold"), text_color="#e74c3c").pack(pady=10)
        ctk.CTkLabel(danger_frame, text="Factory Reset will wipe all user data, keys, and logs.\nAny currently locked files will be PERMANENTLY inaccessible.", 
                     text_color="white", font=("Roboto", 12)).pack(pady=5)
        
        ctk.CTkButton(danger_frame, text="⚠️ FACTORY RESET VAULT ⚠️", command=self.factory_reset, 
                      fg_color="#c0392b", hover_color="#a93226").pack(pady=20)

    def change_password(self):
        new_pw = self.new_pass_entry.get()
        if len(new_pw) < 4:
            messagebox.showerror("Error", "Password too short")
            return
        
        try:
            # Re-encrypt MASTER KEY with NEW password
            # We don't need to touch the recovery key here
            new_salt = secrets.token_bytes(16).hex()
            new_key = self.derive_key(new_pw, new_salt)
            
            # The encryption_key variable currently holds the RAW decrypted Master Key
            new_enc_master = Fernet(new_key).encrypt(self.encryption_key)
            
            self.cursor.execute("UPDATE users SET enc_master_key=?, password_salt=? WHERE username=?", 
                                (new_enc_master, new_salt, self.current_user))
            self.conn.commit()
            
            messagebox.showinfo("Success", "Password Updated successfully.")
            self.new_pass_entry.delete(0, 'end')
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def factory_reset(self):
        confirm = messagebox.askyesno("CONFIRM RESET", "Are you absolute sure?\n\nThis will DELETE the database.\nAll files currently locked will remain encrypted forever (unrecoverable).\n\nProceed?")
        if confirm:
            try:
                self.conn.close()
                os.remove(DB_NAME)
                messagebox.showinfo("Reset", "Vault has been reset. Restarting...")
                # Re-init DB
                self.init_db()
                self.perform_logout()
                self.show_register_screen()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to reset: {e}")

    # --- WORKER THREADS ---
    def thread_lock_file(self):
        threading.Thread(target=self._lock_file_logic, daemon=True).start()

    def thread_lock_folder(self):
        threading.Thread(target=self._lock_folder_logic, daemon=True).start()

    def thread_unlock(self):
        threading.Thread(target=self._unlock_logic, daemon=True).start()

    # --- CRYPTO LOGIC ---
    def _lock_file_logic(self):
        path = filedialog.askopenfilename()
        if not path: return
        self.safe_log(f"Starting encryption: {os.path.basename(path)}")
        self.safe_progress(0.1)
        self._encrypt_single_file(path)
        self.safe_progress(1.0)
        self.safe_log("File encryption complete.")

    def _lock_folder_logic(self):
        folder = filedialog.askdirectory()
        if not folder: return
        
        self.safe_log(f"Scanning folder: {folder}...")
        files_to_process = []
        for root, _, files in os.walk(folder):
            for f in files:
                if not f.endswith(".enc"):
                    files_to_process.append(os.path.join(root, f))
        
        total = len(files_to_process)
        if total == 0:
            self.safe_log("Folder empty or already encrypted.")
            return

        self.safe_log(f"Found {total} files. Starting batch encryption...")
        
        completed = 0
        futures = []
        
        for fpath in files_to_process:
            future = self.executor.submit(self._encrypt_single_file, fpath)
            futures.append(future)

        for future in concurrent.futures.as_completed(futures):
            completed += 1
            progress = completed / total
            self.safe_progress(progress)
        
        self.safe_log(f"Folder encryption finished. {total} files secured.")
        self.safe_info("Complete", f"Securely locked {total} files.")

    def _encrypt_single_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Use Master Key for encryption
            fernet = Fernet(self.encryption_key)
            encrypted_data = fernet.encrypt(data)
            
            temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(file_path))
            with os.fdopen(temp_fd, 'wb') as tf:
                tf.write(encrypted_data)
            
            final_path = file_path + ".enc"
            os.replace(temp_path, final_path)
            
            with open(file_path, 'wb') as f:
                f.write(secrets.token_bytes(len(data))) 
            os.remove(file_path)
            
            self.safe_log(f"Locked: {os.path.basename(file_path)}")
            self.log_action("Lock", os.path.basename(file_path))
            
        except Exception as e:
            self.safe_log(f"Error locking {os.path.basename(file_path)}: {e}")

    def _unlock_logic(self):
        files = filedialog.askopenfilenames(filetypes=[("Encrypted", "*.enc")])
        if not files: return
        
        total = len(files)
        completed = 0
        self.safe_log(f"Unlocking {total} items...")
        
        for path in files:
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                
                fernet = Fernet(self.encryption_key)
                decrypted_data = fernet.decrypt(data)
                
                orig_path = path[:-4] 
                
                temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(path))
                with os.fdopen(temp_fd, 'wb') as tf:
                    tf.write(decrypted_data)
                
                os.replace(temp_path, orig_path)
                os.remove(path)
                
                self.safe_log(f"Unlocked: {os.path.basename(orig_path)}")
                self.log_action("Unlock", os.path.basename(orig_path))
                
            except Exception as e:
                self.safe_log(f"Failed {os.path.basename(path)}: Bad Key or Corrupt")
            
            completed += 1
            self.safe_progress(completed / total)

        self.safe_log("Unlock sequence finished.")
        self.safe_info("Complete", "Selected files have been unlocked.")

if __name__ == '__main__':
    app = ModernVaultApp()
    app.mainloop()