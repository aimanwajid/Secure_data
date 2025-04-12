import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# 🔐 Generate encryption key (should be saved securely in real app)
# 🔐 Generate encryption key only once and save in session
if "KEY" not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.KEY)

cipher = st.session_state.cipher

# ✅ Initialize session state variables
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# 🔐 Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# 🔏 Encrypt function
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# 🔓 Decrypt function
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

# 🖼️ Streamlit App UI
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# 🏠 Home
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure System")
    st.write("Yahan aap apna data securely store aur retrieve kar sakte hain using passkeys.")

# 💾 Store Data
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
            st.write("🔐 Encrypted Data:")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Dono fields bharna zaroori hai!")

# 🔍 Retrieve Data
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success("✅ Decrypted Text:")
                st.code(result)
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Please login again.")
        else:
            st.error("⚠️ Dono fields bharna zaroori hai!")

# 🔐 Login Page
elif choice == "Login":
    st.subheader("🔑 Admin Login")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Login successful. You can now try decrypting again.")
        else:
            st.error("❌ Incorrect master password.")