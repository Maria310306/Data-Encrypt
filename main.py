import streamlit as st
import json
import os
import time
import base64
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# --- Constants ---
DATA_FILE = "data_store.json"
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 60  # seconds

# --- Helper: Load existing data ---
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# --- Helper: Save data ---
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Load data on startup
if 'data_store' not in st.session_state:
    st.session_state.data_store = load_data()
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = {}
if 'locked_until' not in st.session_state:
    st.session_state.locked_until = {}
if 'authenticated_users' not in st.session_state:
    st.session_state.authenticated_users = set()

# --- Password Hashing using PBKDF2 ---
def hash_passkey(passkey, salt):
    return base64.b64encode(pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)).decode()

# --- Encryption Key (static or stored) ---
if 'encryption_key' not in st.session_state:
    st.session_state.encryption_key = Fernet.generate_key()
cipher = Fernet(st.session_state.encryption_key)

# --- Encrypt/Decrypt Functions ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- UI Pages ---
def home():
    st.title("🔒 Secure Multi-User Encryption System")
    st.markdown("Store and retrieve encrypted data **safely** using a personal passkey.")

def store_data():
    st.header("📂 Store Encrypted Data")
    username = st.text_input("Username:")
    data = st.text_area("Data to store:")
    passkey = st.text_input("Passkey (secret key):", type="password")

    if st.button("Encrypt & Save"):
        if username and data and passkey:
            salt = username  # For simplicity, use username as salt
            encrypted = encrypt_data(data)
            hashed = hash_passkey(passkey, salt)
            st.session_state.data_store[encrypted] = {
                "cipher": encrypted,
                "passkey_hash": hashed,
                "username": username
            }
            save_data(st.session_state.data_store)
            st.success("✅ Data encrypted and saved.")
            st.code(encrypted)
        else:
            st.error("⚠️ Please fill all fields.")

def retrieve_data():
    st.header("🔍 Retrieve Encrypted Data")
    username = st.text_input("Username:")
    encrypted_input = st.text_area("Paste Encrypted Text:")
    passkey = st.text_input("Your passkey:", type="password")

    now = time.time()
    locked_until = st.session_state.locked_until.get(username, 0)
    if now < locked_until:
        remaining = int(locked_until - now)
        st.warning(f"⏳ Locked out. Try again in {remaining} seconds.")
        return

    if st.button("Decrypt"):
        if username and encrypted_input and passkey:
            user_attempts = st.session_state.failed_attempts.get(username, 0)
            entry = st.session_state.data_store.get(encrypted_input)
            if entry and entry["username"] == username:
                salt = username
                if entry["passkey_hash"] == hash_passkey(passkey, salt):
                    decrypted = decrypt_data(encrypted_input)
                    st.success("🔓 Decrypted Data:")
                    st.write(decrypted)
                    st.session_state.failed_attempts[username] = 0
                else:
                    st.session_state.failed_attempts[username] = user_attempts + 1
                    if st.session_state.failed_attempts[username] >= MAX_ATTEMPTS:
                        st.session_state.locked_until[username] = time.time() + LOCKOUT_DURATION
                        st.error("🚫 Too many failed attempts. Temporary lockout.")
                    else:
                        remaining = MAX_ATTEMPTS - st.session_state.failed_attempts[username]
                        st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")
            else:
                st.error("❗No matching data found or username mismatch.")
        else:
            st.error("⚠️ All fields required.")

# --- Navigation ---
menu = ["Home", "Store Data", "Retrieve Data"]
choice = st.sidebar.radio("📁 Navigation", menu)

if choice == "Home":
    home()
elif choice == "Store Data":
    store_data()
elif choice == "Retrieve Data":
    retrieve_data()
