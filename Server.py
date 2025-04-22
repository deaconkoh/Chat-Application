import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import hashlib

"""
Function to send encrypted messages & decrypt messages
"""
# Function to generate a secret key (Use the same key for encryption & decryption)
def generate_key(password: str, key_size=32):
    """Generates a fixed-size key using SHA-256."""
    return hashlib.sha256(password.encode()).digest()[:key_size]

# Encrypt a message with a given key
def encrypt_message(plain_text, password):
    key = generate_key(password)
    iv = os.urandom(16)  # Random Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad message to 16 bytes
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    # Encrypt
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    # Combine IV and encrypted message, then encode to Base64
    return base64.b64encode(iv + encrypted).decode()


# Store connected clients
clients = {}  # {username: (conn, addr)}
groups = {}   # {group_name: [usernames]}
user_status = {}

# Broadcast message to all clients
def broadcast(message, sender=None):
    for user, (conn, _) in clients.items():
        if sender is None or user != sender:
            conn.send(message.encode())

# Handle private messaging
# def private_message(target_user, message, sender):
#     if target_user in clients:
#         conn, _ = clients[target_user]
#         conn.send(f"[Private from {sender}]: {message}".encode())
#     else:
#         conn, _ = clients[sender]
#         conn.send("[Server]: User not found.".encode())
def private_message(target_user, message, sender):
    print(f"DEBUG: {sender} is sending '{message}' to {target_user}")
    print(f"DEBUG: Active users: {list(clients.keys())}")  
    message = ' '.join(message)
    sender_conn, _ = clients[sender]
    
    try:
        conn_data = clients[target_user]  # Retrieve recipient's connection data
        print(f"DEBUG: Retrieved connection data for {target_user}: {conn_data}")
        conn, _ = conn_data  # Extract connection object
    except KeyError:
        print(f"ERROR: User '{target_user}' not found in clients dictionary!")
        sender_conn.send(f"[Server]: User '{target_user}' not found.".encode())
        return
    except Exception as e:
        print(f"ERROR: Unexpected error while retrieving {target_user}: {e}")
        sender_conn.send(f"[Server]: Error sending message to {target_user}: {e}".encode())
        return 
    
    # Prevent self-messaging
    if target_user == sender:
        sender_conn.send(f"[Server]: Please send your private message to a valid recipient.".encode())
        return
    
    # ✅ Fix: Ensure the target user has a status (defaults to "normal" if missing)
    target_status = user_status.get(target_user, "normal")

    # ✅ Handle "Do Not Disturb" mode
    if target_status == "dnd":
        sender_conn, _ = clients[sender]
        sender_conn.send(f"[Server]: {target_user} is in 'Do Not Disturb' mode and will not receive messages.".encode())
        return  

    # ✅ Send the private message
    try:
        conn.send(f"[Private from {sender}]: {message}".encode())
        print(f"DEBUG: Private message from {sender} to {target_user} sent successfully.")

        # ✅ Notify sender if recipient is "Away"
        if target_status == "away":
            sender_conn, _ = clients[sender]
            sender_conn.send(f"[Server]: {target_user} is 'Away' and may not respond.".encode())

    except Exception as e:
        print(f"ERROR: Failed to send message to {target_user}: {e}")
        sender_conn, _ = clients[sender]
        sender_conn.send(f"[Server]: Failed to send message to {target_user}. They may have disconnected.".encode())

# Handle group messaging
def group_message(group_name, message, sender):
    if group_name not in groups:
        conn, _ = clients[sender]
        conn.send(f"[Server]: Group '{group_name}' not found.".encode())
        return
    
    print(f"DEBUG: Sending message to group '{group_name}': {message}")  # ✅ Debugging output

    for user in groups[group_name]:
        if user != sender and user in clients:
            conn, _ = clients[user]
            conn.send(f"[Group {group_name} - {sender}]: {message}".encode())

# Handle client communication
def handle_client(conn, addr):
    try:
        conn.send("Enter your username: ".encode())
        username = conn.recv(1024).decode()

        # Ensure unique username
        while username in clients:
            conn.send("Username already taken. Enter a new one: ".encode())
            username = conn.recv(1024).decode()

        clients[username] = (conn, addr)
        user_status[username] = "normal"
        broadcast(f"[Server]: {username} has joined the chat!", sender=username)
        conn.send("[Server]: Welcome to the chat!".encode())

        while True:
            msg = conn.recv(1024).decode()
            if not msg:
                break

            # Command Handling
            if msg.startswith("@quit"):
                broadcast(f"[Server]: {username} has left the chat.")
                del clients[username]
                break

            elif msg.startswith("@names"):
                conn.send(f"Connected users: {', '.join(clients.keys())}".encode())

            elif msg.startswith("@status"):
                parts = msg.split(" ")

                if len(parts) == 1:  # Display current status
                    conn.send(f"[Server]: Your current status is '{user_status[username]}'.".encode())

                elif parts[1] in ["normal", "dnd", "away"]:
                    user_status[username] = parts[1]
                    conn.send(f"[Server]: Your status has been changed to '{parts[1]}'.".encode())
                    broadcast(f"[Server]: {username} is now '{parts[1]}'.", sender=username)

                else:
                    conn.send("[Server]: Invalid status. Use '@status normal', '@status dnd', or '@status away'.".encode())

            # Send encrypted messages
            elif msg.startswith("@secret"):
                parts = msg.split(" ", 3)

                # Check if the format is correct
                if len(parts) < 4:
                    conn.send("[Server]: Invalid format. Use '@secret username key message'.".encode())
                    continue

                target_user = parts[1]
                key = parts[2]
                message = " ".join(parts[3:])

                # Ensure user dont send secret message to themself
                if target_user == username:
                    conn.send("[Server]: You cannot send an encrypted message to yourself.".encode())
                    continue

                # Ensure that message is not empty
                if not message.strip():
                    conn.send("[Server]: You must enter a message.".encode())
                    continue

                # Encrypt message before sending
                encrypted_text = encrypt_message(message, key)

                # Check if users are connected to server
                if target_user in clients:
                    target_conn, _ = clients[target_user]

                    try:
                        target_conn.send(f"[ENCRYPTED] {username} sent you a secret message. Enter a decryption key: {encrypted_text}".encode())
                        #target_conn.send("\n\nPress Enter to acknowledge".encode())
                    except Exception as e:
                        print(f"ERROR: Failed to send encrypted message to {target_user}: {e}")
                        conn.send(f"[Server]: Failed to send message to {target_user}. They may have disconnected.".encode())

                else:
                    conn.send(f"[Server]: User '{target_user}' not found.".encode())
            
            elif msg.startswith("@"):
                parts = msg.split(" ", 2)
                command = parts[0]

                if command.startswith("@group"):
                    parts = msg.split(" ", 3)  # ✅ Fix: Ensure the group name and users stay separate
                    group_commands(username, parts, conn)

                else:
                    if len(parts) < 2:  # Ensure that user's dont just send @username without the message
                        conn.send("[Server]: Invalid private message format. Use '@username message'.".encode())
                    else:
                        target_user = command[1:]  # Extract username (remove '@')
                        private_message(target_user, parts[1:], username)  # 

            else:
                broadcast(f"{username}: {msg}", sender=username)
    except:
        pass
    finally:
        conn.close()
        if username in clients: 
            del clients[username]
            broadcast(f"[Server]: {username} has disconnected.")

# Handle group commands
def group_commands(username, parts, conn):
    global groups  

    print(f"DEBUG: Received parts -> {parts}")  # Debugging output

    if len(parts) < 3:  # Ensure we have enough arguments for "leave" and "delete"
        conn.send("[Server]: Invalid format. Use '@group leave <group_name>'.".encode())
        return

    command = parts[0]
    action = parts[1]

    print(f"DEBUG: Before command '{command} {action}', existing groups: {groups}")

    if action == "set":
        # Ensure correct format
        if len(parts) < 4:
            conn.send("[Server]: Invalid format. Use '@group set <group_name> user1, user2, ...'.".encode())
            return
        
        # The rest of the logic for "set" remains the same
        group_name = parts[2]
        users_raw = " ".join(parts[3:])
        
        # Split users, remove spaces, and filter out empty values
        users = [u.strip() for u in users_raw.split(",") if u.strip()]

        if group_name in groups:
            conn.send("[Server]: Group name already exists.".encode())
            return
        else:
            groups[group_name] = list(set(users + [username])) # Add users into group using a set to prevent being added twice
            conn.send(f"[Server]: Group {group_name} created with members {', '.join(groups[group_name])}.".encode())
            
            # Notify other members
            for user in users:
                if user in clients and user != username:  # Ensure the user is online and not the creator
                    try:
                        conn, _ = clients[user]
                        conn.send(f"[Server]: You have been added to group '{group_name}' by {username}.".encode())
                    except:
                        print(f"DEBUG: Failed to notify {user}.")
            
    elif action == "send":
        if len(parts) < 4:
            conn.send("[Server]: Invalid message format. Use '@group send <group> <message>'.".encode())
            return

        group_name = parts[2]
        message = " ".join(parts[3:]) 
        if group_name not in groups:
            conn.send(f"[Server]: Group '{group_name}' does not exist.".encode())
            return

        if username not in groups[group_name]:  # Prevent outsiders from sending messages
            conn.send(f"[Server]: You are not a member of '{group_name}', so you cannot send messages.".encode())
            return

        group_message(group_name, message, username)

    elif action == "leave":
        group_name = parts[2]
        print(f"DEBUG: Trying to leave group '{group_name}'")

        if group_name in groups:
            if username in groups[group_name]:
                groups[group_name].remove(username)
                print(f"DEBUG: {username} left group '{group_name}'")

                conn.send(f"[Server]: You left group {group_name}.".encode())

                if len(groups[group_name]) == 0:
                    del groups[group_name]
                    print(f"DEBUG: Group '{group_name}' deleted because it has no members.")
                    broadcast(f"[Server]: Group {group_name} has been deleted as it has no members.")
            else:
                conn.send(f"[Server]: You are not a member of group {group_name}.".encode())
        else:
            conn.send(f"[Server]: Group {group_name} does not exist.".encode())

    elif action == "delete":
        group_name = parts[2]
        print(f"DEBUG: Trying to delete group '{group_name}'")
        
        if group_name in groups:
            members = groups[group_name]  # Store members in temporary variable
            
            if username not in members:
                conn.send("[Server]: Only the members in the group can delete this group.".encode())
                return

            for user in members:  # Send a message to all members in previously in the group
                if user in clients:
                    conn, _ = clients[user]
                    conn.send(f"[Server]: Group {group_name} has been deleted.".encode())
            del groups[group_name]
            print(f"DEBUG: Group '{group_name}' deleted and users notified.")
        else:
            conn.send(f"[Server]: Group {group_name} does not exist.".encode())

    print(f"DEBUG: After command '{command} {action}', existing groups: {groups}")

# Start the server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 12345))
    server.listen(5)
    print("Server is running...")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

start_server()