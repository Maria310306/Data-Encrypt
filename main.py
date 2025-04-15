import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# --- Load environment variables ---
load_dotenv()
FERNET_KEY = os.getenv("FERNET_KEY")
cipher = Fernet(FERNET_KEY.encode())

DATA_FILE = "data_store.json"
MASTER_PASSWORD = "admin123"  # For demo. You can also store this in .env

# --- Session State Initialization ---
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = True

# --- Utility Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data_store):
    with open(DATA_FILE, "w") as f:
        json.dump(data_store, f, indent=4)

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- Pages ---
def home():
    st.title("🔒 Secure Data Encryption System")
    st.write("Use this app to **securely store and retrieve encrypted data** using your passkey.")

def store_data():
    st.header("📂 Store Data")
    data = st.text_area("Enter data to store:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Encrypt & Store"):
        if data and passkey:
            encrypted = encrypt_data(data)
            hashed = hash_passkey(passkey)
            data_store = load_data()
            data_store[encrypted] = {"passkey_hash": hashed}
            save_data(data_store)
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted, language="text")
            st.info("⚠️ Save this encrypted string. You'll need it to retrieve your data.")
        else:
            st.error("❗Please enter both data and passkey.")

def retrieve_data():
    if not st.session_state.authenticated:
        login_page()
        return

    st.header("🔍 Retrieve Data")
    encrypted_input = st.text_area("Enter encrypted text:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            data_store = load_data()
            entry = data_store.get(encrypted_input)
            if entry and entry["passkey_hash"] == hash_passkey(passkey):
                try:
                    decrypted = decrypt_data(encrypted_input)
                    st.success("✅ Decryption Successful!")
                    st.code(decrypted, language="text")
                    st.session_state.failed_attempts = 0
                except:
                    st.error("❌ Decryption failed. Data may be corrupted.")
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey or encrypted text. Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authenticated = False
                    st.warning("🔐 Too many failed attempts. Please reauthorize.")
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required.")

def login_page():
    st.title("🔐 Reauthorization Required")
    password = st.text_input("Enter master password to continue:", type="password")

    if st.button("Login"):
        if password == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authenticated = True
            st.success("✅ Reauthorized successfully! Redirecting...")
            
            # ✅ Delay before rerun so user sees success message
            time.sleep(2)
            st.rerun()
        else:
            st.error("❌ Incorrect password.")


# --- Navigation ---
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("📁 Navigation", menu)

if choice == "Home":
    home()
elif choice == "Store Data":
    store_data()
elif choice == "Retrieve Data":
    retrieve_data()
elif choice == "Login":
    login_page()
