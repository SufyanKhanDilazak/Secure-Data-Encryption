import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Store the encryption key in session_state to persist across reruns
if "encryption_key" not in st.session_state:
    st.session_state.encryption_key = Fernet.generate_key()

cipher = Fernet(st.session_state.encryption_key)

# In-memory storage (persisted across reruns in session_state)
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Utility: Hash the passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Utility: Encrypt text
def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

# Utility: Decrypt text
def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Home Page
def home():
    st.title("🔒 Secure Data System")
    st.write("Welcome! Use the sidebar to store or retrieve your data securely.")

# Store Page
def store_data():
    st.header("📦 Store Data")
    text = st.text_area("Enter Data")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Save"):
        if text and passkey:
            encrypted_text = encrypt(text)
            hashed_passkey = hash_passkey(passkey)

            if hashed_passkey not in st.session_state.stored_data:
                st.session_state.stored_data[hashed_passkey] = []

            st.session_state.stored_data[hashed_passkey].append(encrypted_text)
            st.success("✅ Data stored securely!")
        else:
            st.error("❌ Please fill all fields.")

# Retrieve Page
def retrieve_data():
    st.header("🔍 Retrieve Data")

    if st.session_state.failed_attempts >= 3:
        st.warning("🔐 Too many failed attempts. Please login to reset.")
        return

    passkey_input = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt My Data"):
        hashed = hash_passkey(passkey_input)

        if hashed in st.session_state.stored_data:
            st.success("✅ Here is your decrypted data:")
            for i, enc_text in enumerate(st.session_state.stored_data[hashed], 1):
                try:
                    decrypted = decrypt(enc_text)
                    st.code(decrypted, language="text")
                except Exception:
                    st.error(f"❌ Error decrypting item {i}.")
            st.session_state.failed_attempts = 0
        else:
            st.session_state.failed_attempts += 1
            attempts_left = 3 - st.session_state.failed_attempts
            st.error(f"❌ No data found for this passkey. Attempts left: {attempts_left}")

# Login Page to reset failed attempts
def login():
    st.header("🔐 Login to Reauthorize")
    master = st.text_input("Master Password", type="password")

    if st.button("Login"):
        if master == "admin123":  # For demo only
            st.session_state.failed_attempts = 0
            st.success("✅ Logged in! You can try again now.")
        else:
            st.error("❌ Incorrect master password.")

# Sidebar Navigation
pages = {
    "🏠 Home": home,
    "📦 Store Data": store_data,
    "🔍 Retrieve Data": retrieve_data,
    "🔐 Login": login,
}

selected = st.sidebar.selectbox("Navigate", list(pages.keys()))
pages[selected]()
