import streamlit as st
import hashlib
import os
import json
import time
import base64
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
# -------------------------------
# Global Constants and File Paths
# -------------------------------
USERS_FILE = "users.json"
DATA_FILE = "data_store.json"

# Lockout settings
LOCKOUT_THRESHOLD = 3      # maximum allowed failed attempts
LOCKOUT_DURATION = 30      # seconds to lock out if threshold exceeded



FERNET_KEY = os.getenv("FERNET_KEY").encode()
cipher = Fernet(FERNET_KEY)


# -------------------------------
# Utility Functions: File I/O
# -------------------------------
def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    else:
        return {}

def save_json(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=4)

# Load persistent storage
users_db = load_json(USERS_FILE)
data_db = load_json(DATA_FILE)

# -------------------------------
# Utility Functions: PBKDF2 Hashing
# -------------------------------
def generate_salt():
    return base64.b64encode(os.urandom(16)).decode('utf-8')

def pbkdf2_hash(password, salt, iterations=100000):
    # salt must be bytes; if provided as string, convert to bytes
    salt_bytes = salt.encode() if isinstance(salt, str) else salt
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_bytes, iterations)
    return dk.hex()

def verify_password(password, salt, stored_hash, iterations=100000):
    return pbkdf2_hash(password, salt, iterations) == stored_hash

# -------------------------------
# User Management: Registration & Login
# -------------------------------
def register_user(username, password):
    if username in users_db:
        return False, "Username already exists."
    salt = generate_salt()
    password_hash = pbkdf2_hash(password, salt)
    users_db[username] = {
        "password_hash": password_hash,
        "salt": salt,
        "failed_attempts": 0,
        "lockout_until": 0
    }
    save_json(USERS_FILE, users_db)
    # Also initialize the user's data list
    data_db[username] = []
    save_json(DATA_FILE, data_db)
    return True, "User registered successfully!"

def login_user(username, password):
    if username not in users_db:
        return False, "Username not found."
    user_info = users_db[username]
    # Check for lockout
    if time.time() < user_info.get("lockout_until", 0):
        wait_time = int(user_info["lockout_until"] - time.time())
        return False, f"Account locked. Try again in {wait_time} seconds."
    if verify_password(password, user_info["salt"], user_info["password_hash"]):
        # Reset failed attempts on success
        users_db[username]["failed_attempts"] = 0
        users_db[username]["lockout_until"] = 0
        save_json(USERS_FILE, users_db)
        return True, "Login successful!"
    else:
        # Increase failed attempts and possibly set lockout
        users_db[username]["failed_attempts"] = user_info.get("failed_attempts", 0) + 1
        if users_db[username]["failed_attempts"] >= LOCKOUT_THRESHOLD:
            users_db[username]["lockout_until"] = time.time() + LOCKOUT_DURATION
        save_json(USERS_FILE, users_db)
        remaining = max(0, LOCKOUT_THRESHOLD - users_db[username]["failed_attempts"])
        return False, f"Incorrect password. {remaining} attempts remaining."

# -------------------------------
# Data Encryption and Decryption
# -------------------------------
def encrypt_data(plain_text):
    return cipher.encrypt(plain_text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# When storing data, we also need to securely hash the encryption passkey:
def store_user_data(username, plain_text, enc_passkey):
    # Generate a salt specific for this encryption passkey
    enc_salt = generate_salt()
    enc_pass_hash = pbkdf2_hash(enc_passkey, enc_salt)
    encrypted_text = encrypt_data(plain_text)
    # Create an entry with a unique id (using current timestamp)
    record = {
        "id": str(int(time.time()*1000)),
        "encrypted_text": encrypted_text,
        "enc_salt": enc_salt,
        "enc_pass_hash": enc_pass_hash
    }
    data_db[username].append(record)
    save_json(DATA_FILE, data_db)
    return record

def verify_and_decrypt(username, record_id, provided_passkey):
    # Find the record for the current user
    for record in data_db.get(username, []):
        if record["id"] == record_id:
            if verify_password(provided_passkey, record["enc_salt"], record["enc_pass_hash"]):
                return True, decrypt_data(record["encrypted_text"])
            else:
                return False, "Incorrect encryption passkey."
    return False, "Record not found."

# -------------------------------
# Streamlit Session State Initialization
# -------------------------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "username" not in st.session_state:
    st.session_state["username"] = ""
if "retrieval_failed_attempts" not in st.session_state:
    st.session_state["retrieval_failed_attempts"] = 0
if "lockout_until_retrieval" not in st.session_state:
    st.session_state["lockout_until_retrieval"] = 0

# -------------------------------
# Streamlit App: Navigation
# -------------------------------

st.title("🔐 Secure Data Encryption System")

# Sidebar Navigation options based on login state
if st.session_state["logged_in"]:
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
else:
    menu = ["Home", "Register", "Login"]

choice = st.sidebar.selectbox("Navigation", menu)

# -------------------------------
# Home Page
# -------------------------------
if choice == "Home":
    st.subheader("Welcome to the Secure Data System")
    if st.session_state["logged_in"]:
        st.write(f"Hello, **{st.session_state['username']}**! Use the options on the sidebar to store or retrieve data.")
    else:
        st.write("Use the sidebar to register or login to the system.")

# -------------------------------
# Registration Page
# -------------------------------
elif choice == "Register":
    st.subheader("User Registration")
    username = st.text_input("Choose a Username:")
    password = st.text_input("Choose a Password:", type="password")
    if st.button("Register"):
        if username and password:
            success, msg = register_user(username, password)
            if success:
                st.success(msg)
                st.info("You can now log in using your credentials.")
            else:
                st.error(msg)
        else:
            st.error("Please enter both username and password.")

# -------------------------------
# Login Page
# -------------------------------
elif choice == "Login":
    st.subheader("User Login")
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")
    if st.button("Login"):
        if username and password:
            success, msg = login_user(username, password)
            if success:
                st.session_state["logged_in"] = True
                st.session_state["username"] = username
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)
        else:
            st.error("Please enter both username and password.")

# -------------------------------
# Store Data Page (for logged in users)
# -------------------------------
elif choice == "Store Data":
    if not st.session_state["logged_in"]:
        st.error("Please log in to store data.")
    else:
        st.subheader("Store Data Securely")
        plain_text = st.text_area("Enter Data to Encrypt:")
        enc_passkey = st.text_input("Enter a Unique Encryption Passkey:", type="password")
        if st.button("Encrypt & Save"):
            if plain_text and enc_passkey:
                record = store_user_data(st.session_state["username"], plain_text, enc_passkey)
                st.success(f"Data stored securely! Record ID: {record['id']}")
            else:
                st.error("Both data and encryption passkey are required.")

# -------------------------------
# Retrieve Data Page (for logged in users)
# -------------------------------
elif choice == "Retrieve Data":
    if not st.session_state["logged_in"]:
        st.error("Please log in to retrieve data.")
    else:
        st.subheader("Retrieve Your Data")
        user_records = data_db.get(st.session_state["username"], [])
        if not user_records:
            st.info("No records found. Please store some data first!")
        else:
            # Show available records with their IDs
            record_options = {f"Record {r['id']}": r["id"] for r in user_records}
            selected_record_id = st.selectbox("Select Record", list(record_options.keys()))
            # Retrieve the actual id value
            record_id = record_options[selected_record_id]
            
            # Handle lockout for retrieval attempts
            current_time = time.time()
            if current_time < st.session_state["lockout_until_retrieval"]:
                remaining = int(st.session_state["lockout_until_retrieval"] - current_time)
                st.warning(f"Too many failed attempts. Try again in {remaining} seconds.")
            else:
                enc_passkey = st.text_input("Enter Encryption Passkey for the selected record:", type="password")
                if st.button("Decrypt"):
                    if enc_passkey:
                        success, result = verify_and_decrypt(st.session_state["username"], record_id, enc_passkey)
                        if success:
                            st.success(f"Decrypted Data: {result}")
                            st.session_state["retrieval_failed_attempts"] = 0
                        else:
                            st.error(result)
                            st.session_state["retrieval_failed_attempts"] += 1
                            attempts_left = LOCKOUT_THRESHOLD - st.session_state["retrieval_failed_attempts"]
                            st.info(f"Attempts remaining: {attempts_left}")
                            if st.session_state["retrieval_failed_attempts"] >= LOCKOUT_THRESHOLD:
                                st.warning("Too many failed attempts! Temporarily locked out for retrieval.")
                                st.session_state["lockout_until_retrieval"] = time.time() + LOCKOUT_DURATION
                    else:
                        st.error("Encryption passkey is required.")

# -------------------------------
# Logout Functionality
# -------------------------------
elif choice == "Logout":
    st.session_state["logged_in"] = False
    st.session_state["username"] = ""
    st.success("Logged out successfully.")
    st.rerun()
