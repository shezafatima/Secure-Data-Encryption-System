# 🔐 Secure Data Encryption System

This is a modern **Streamlit-based** web application designed to securely **encrypt and decrypt sensitive data**, protect user information, and manage encrypted records using a simple UI. It was built as part of the [Panaverse: Learn Modern AI with Python](https://github.com/panaversity/learn-modern-ai-python) course.

---

## 🚀 Features

- 🔑 **AES Encryption & Decryption** using Fernet from the `cryptography` library
- 👤 **User Authentication** (Sign Up / Login) with password hashing
- 🔒 **Auto Logout** and session security
- 🔁 **Rerun mechanism** for seamless logout or data refresh

---

## 🧪 Technologies Used

| Component         | Tech Stack       |
|------------------|------------------|
| UI Framework      | Streamlit        |
| Encryption        | `cryptography` (Fernet AES) |
| Auth Management   | Hashed passwords using `bcrypt` or `cryptography` |
| Utility Tools     |  Time |

---



## 💻 Getting Started

Follow the steps below to run the project locally.

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/secure_data_encryption.git
cd secure_data_encryption
2. (Optional) Create a Virtual Environment
bash
Copy
Edit
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
3. Install Required Packages
bash
Copy
Edit
pip install -r requirements.txt
4. Run the App
bash
Copy
Edit
streamlit run main.py
🌐 Deployment
🔸 Deploy on Streamlit Cloud
Push your project to GitHub

Go to Streamlit Cloud

Click “New App” → Connect to your GitHub repo

Add your main.py as the entry point

Click Deploy

🧾 Don’t Forget:
Make sure requirements.txt is up to date

Add any encryption key handling inside the app securely

Ensure .streamlit/secrets.toml is configured if needed



🎓 Learning Outcomes
Build full-stack apps with Python + Streamlit

Implement secure encryption and user authentication


Understand session and rerun handling in Streamlit



🙌 Acknowledgments
Inspired by the Panaverse Learn Modern AI with Python course:
📚 Panaverse AI Python Projects

---

