import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import hashlib


"""
Function to decrypt messages
"""
# Function to generate a secret key (Use the same key for encryption & decryption)
def generate_key(password: str, key_size=32):
    """Generates a fixed-size key using SHA-256."""
    return hashlib.sha256(password.encode()).digest()[:key_size]

def decrypt_message(encrypted_text, password):
    key = generate_key(password)
    
    # Decode Base64
    encrypted_data = base64.b64decode(encrypted_text.strip())

    # Extract IV (first 16 bytes) and ciphertext (remaining bytes)
    iv = encrypted_data[:16]
    encrypted_message = encrypted_data[16:]

    # AES Decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    return decrypted.decode()



def receive_messages(client):
    while True:
        try:
            msg = client.recv(1024).decode()
            
            if not msg:
                print("[Error]: Server connection lost. Press enter to exit client...")
                client.close()
                break
            
            # Detect encrypted messages
            if msg.startswith("[ENCRYPTED]"):
                print("\n" + msg)
                encrypted_text = msg.rsplit(": ", 1)[1]  # Splits only from the last ": "
                           
                key = input("Enter decryption key: ")  # Ask user for key
                try:
                    decrypted_message = decrypt_message(encrypted_text, key)
                    print(f"[Decrypted Message]: {decrypted_message}")
                except:
                    print("[Error]: Incorrect decryption key!")

            else:
                print(msg)  # Normal messages
        except:
            print("Disconnected from server.")
            client.close()
            break

def client_program():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = input("Enter server IP: ")
    
    try:
        client.connect((server_ip, 12345))
    except:
        print("Failed to connect to the server.")
        return

    # Start receiving messages in a separate thread
    threading.Thread(target=receive_messages, args=(client,), daemon=True).start()

    while True:
        try:
            msg = input()

            if msg.startswith("@quit"):
                print("Disconnecting from server...")
                client.close()
                break
            
            client.send(msg.encode())

        except:
            print("Error sending message. Connection might be closed.")
            client.close()
            break

client_program()