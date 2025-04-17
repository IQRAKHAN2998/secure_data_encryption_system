import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# --- Generate or Load Encryption Key ---
def load_or_create_key():
    key_file = "key.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            return f.read()
    else:
        new_key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(new_key)
        return new_key

KEY = load_or_create_key()
cipher = Fernet(KEY)

# --- Global Variables ---
stored_data = {}
DATA_FILE = "data_store.json"

# --- Initialize Session State ---
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "menu" not in st.session_state:
    st.session_state.menu = "Home"

# --- Load data from file ---
def load_data_from_file():
    global stored_data
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            stored_data = json.load(f)
    else:
        stored_data = {}

# --- Save data to file ---
def save_data_to_file():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

# --- Hashing passkey ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# --- Encrypting data ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# --- Decrypting data ---
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# --- Load data on app start ---
load_data_from_file()

# --- Streamlit UI ---
st.set_page_config(page_title="Secure Encryption App", layout="centered")
st.title("🛡️ Secure Data Encryption System")

# --- Top Menu ---
menu = st.selectbox(
    "📁 Select Page",
    ["Home", "Store Data", "Retrieve Data", "Login"],
    index=["Home", "Store Data", "Retrieve Data", "Login"].index(st.session_state.menu)
)

# --- HOME ---
if menu == "Home":
    st.session_state.menu = "Home"
    st.subheader("🏠 Welcome")
    st.write("This app allows you to **securely store and retrieve data** using encryption + passkeys.")

# --- STORE DATA ---
elif menu == "Store Data":
    st.session_state.menu = "Store Data"
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Data to Encrypt:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_pass = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed_pass
            }
            save_data_to_file()
            st.success("✅ Data encrypted and saved successfully!")
            st.text_area("🔒 Encrypted Text (Copy this to decrypt):", encrypted, height=100)
        else:
            st.error("⚠️ Please fill in both fields.")

# --- RETRIEVE DATA ---
elif menu == "Retrieve Data":
    st.session_state.menu = "Retrieve Data"
    st.subheader("🔍 Retrieve Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            attempts_left = 3 - st.session_state.failed_attempts
            if result:
                st.success("✅ Data decrypted successfully!")
                st.text_area("🔓 Decrypted Data:", result, height=100)
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Redirecting to login...")
                    st.session_state.menu = "Login"
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required.")

# --- LOGIN PAGE ---
elif menu == "Login":
    st.session_state.menu = "Login"
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Admin Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Temporary admin password
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully!")
            st.session_state.menu = "Retrieve Data"
            st.experimental_rerun()
        else:
            st.error("❌ Wrong admin password.")
