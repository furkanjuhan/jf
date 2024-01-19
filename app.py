import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# Define your functions here (generate_keys, encrypt_message, decrypt_message)

# Initialize or load keys
if 'juhan_keys' not in st.session_state:
    st.session_state.juhan_keys = generate_keys()

if 'furkan_keys' not in st.session_state:
    st.session_state.furkan_keys = generate_keys()

# Streamlit UI
st.title("RSA Encryption/Decryption App")

user = st.radio("Who are you?", ('Juhan', 'Furkan'))

action = st.radio("Choose your action", ('Encrypt', 'Decrypt', 'View Keys'))

if user == 'Juhan':
    private_key, public_key = st.session_state.juhan_keys
elif user == 'Furkan':
    private_key, public_key = st.session_state.furkan_keys

if action == 'Encrypt':
    message = st.text_area("Enter your message to encrypt:")
    if st.button('Encrypt Message'):
        encrypted_msg = encrypt_message(message, public_key)
        st.text_area("Encrypted Message:", encrypted_msg, height=100)

elif action == 'Decrypt':
    encrypted_msg = st.text_area("Enter the encrypted message:")
    if st.button('Decrypt Message'):
        decrypted_msg = decrypt_message(encrypted_msg, private_key)
        st.text_area("Decrypted Message:", decrypted_msg, height=100)

elif action == 'View Keys':
    st.write("Private Key:")
    st.text(private_key.decode())
    st.write("Public Key:")
    st.text(public_key.decode())

# Run the app: streamlit run your_script.py
