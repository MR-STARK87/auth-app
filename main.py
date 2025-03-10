import streamlit as st
import firebase_admin
from firebase_admin import credentials, auth
import requests
import json

# Load API key and service account path from environment variables (Streamlit secrets)
WEB_API_KEY = st.secrets["FIREBASE_API_KEY"]
firebase_secrets = st.secrets["FIREBASE_ADMIN"]

service_account_info = {
    "type": firebase_secrets["type"],
    "project_id": firebase_secrets["project_id"],
    "private_key_id": firebase_secrets["private_key_id"],
    "private_key": firebase_secrets["private_key"],
    "client_email": firebase_secrets["client_email"],
    "client_id": firebase_secrets["client_id"],
    "auth_uri": firebase_secrets["auth_uri"],
    "token_uri": firebase_secrets["token_uri"],
    "auth_provider_x509_cert_url": firebase_secrets["auth_provider_x509_cert_url"],
    "client_x509_cert_url": firebase_secrets["client_x509_cert_url"],
    "universe_domain": firebase_secrets["universe_domain"],
}


# Initialize Firebase app only if not already initialized
if not firebase_admin._apps:
    cred = credentials.Certificate(service_account_info)
    firebase_admin.initialize_app(WEB_API_KEY)

def authenticate_user(email, password):
    try:
        user = auth.get_user_by_email(email)
        st.success("Login Successful")

    except:
        st.warning("Login Failed")

def app():
    st.title("My New Authentication App")

    choice = st.selectbox('Login/Signup', ['Login', 'Sign up'])

    if choice == 'Login':
        email = st.text_input('Enter your email')
        password = st.text_input('Enter your password', type='password')

        if st.button('Login'):
            if email and password:
                authenticate_user(email, password)
            else:
                error_message = result.get('error', {}).get('message', 'Unknown error')
                st.error(f"Login failed: {error_message}")
        #else:
            #st.warning("Please provide both email and password.")
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
