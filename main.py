import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json

# --- Initialization ---
if 'data_store' not in st.session_state:
    st.session_state.data_store = {}  # Initialize data_store as an empty dictionary if not already initialized
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = True  # Assume true initially unless failed 3x

# --- Encryption Setup ---
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# --- Utilities ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- Pages ---
def home():
    st.title("🔒 Secure Data Encryption System")
    st.write("Use this app to **store and retrieve encrypted data** with your own passkey.")

def store_data():
    st.header("📂 Store Data")
    data = st.text_area("Enter data to store:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Encrypt & Store"):
        if data and passkey:
            encrypted = encrypt_data(data)
            hashed = hash_passkey(passkey)
            st.session_state.data_store[encrypted] = {
                "cipher": encrypted,
                "passkey_hash": hashed
            }

            # Save the data_store to a JSON file
            with open("data_store.json", "w") as f:
                json.dump(st.session_state.data_store, f)

            st.success("✅ Data encrypted and stored successfully!")
            st.write("Encrypted Key: ", encrypted)
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
            stored = st.session_state.data_store.get(encrypted_input)
            if stored and stored["passkey_hash"] == hash_passkey(passkey):
                decrypted = decrypt_data(encrypted_input)
                st.success(f"🔓 Decrypted Data: {decrypted}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey or data. Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authenticated = False
                    st.warning("🔐 Too many failed attempts. Please reauthorize.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required.")

def login_page():
    st.title("🔐 Reauthorization Required")
    password = st.text_input("Enter master password to continue:", type="password")
    if st.button("Login"):
        if password == "admin123":  # Replace this with environment variable or secure store in real apps
            st.success("✅ Reauthorized successfully.")
            st.session_state.failed_attempts = 0
            st.session_state.authenticated = True
            st.experimental_rerun()
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


