import streamlit as st
import firebase_admin
from firebase_admin import credentials, auth
import requests
import json

# Load API key and service account path from environment variables (Streamlit secrets)
WEB_API_KEY = st.secrets["FIREBASE_API_KEY"]

# Initialize Firebase app only if not already initialized
if not firebase_admin._apps:
    cred = credentials.Certificate("ample-firebase-ai-app-a51d5-fb4cd6e72cfd.json")
    firebase_admin.initialize_app(cred)

def authenticate_user(email, password):
    """
    Authenticate a user using Firebase REST API.
    """
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={WEB_API_KEY}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    response = requests.post(url, json=payload)
    return response.json()

def app():
    st.title("My New Authentication App")

    choice = st.selectbox('Login/Signup', ['Login', 'Sign up'])

    if choice == 'Login':
        email = st.text_input('Enter your email')
        password = st.text_input('Enter your password', type='password')

        if st.button('Login'):
            if email and password:
                result = authenticate_user(email, password)
                if "idToken" in result:
                    st.success("Logged in successfully")
                else:
                    error_message = result.get('error', {}).get('message', 'Unknown error')
                    st.error(f"Login failed: {error_message}")
            else:
                st.warning("Please provide both email and password.")
    else:
        email = st.text_input('Enter your email')
        password = st.text_input('Enter your password', type='password')
        username = st.text_input('Enter your username')

        if st.button("Create New Account"):
            try:
                user = auth.create_user(
                    email=email,
                    password=password,
                    uid=username
                )
                st.success("Account created successfully")
            except Exception as e:
                st.error(f"Error creating account: {e}")

if __name__ == "__main__":
    app()
