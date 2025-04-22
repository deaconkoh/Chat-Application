# Encrypted Client-Server Chat Application
## Overview
This project is a secure client-server chat application developed as part of our Computer Networks coursework, aimed at providing a hands-on understanding of the Transport Layer in the TCP/IP model.

Using Python’s socket library and the TCP protocol, the application enables users to exchange private, encrypted messages, participate in group chats, and communicate reliably in real time. To handle multiple clients simultaneously, the server implementation leverages threading, ensuring smooth and concurrent message delivery across all active users.

## Features Implemented

### **General Chat Features**
- **User Authentication**: Unique usernames are enforced upon connection.
- **Broadcasting Messages**: Messages are broadcasted to all connected clients when new users connect/disconnect.
- **Private Messaging (`@username message`)**: Send **private** messages to specific users.

### **Client Status Management**
- **Checking Current Status (`@status`)**: Users can check their current status.
- **Updating Status (`@status <status>`)**: Clients can set their availability status.
  - **Available statuses**: `normal` (Default), `dnd` (Do Not Disturb), `away`.
  - **Effect of Statuses**:
    - **`dnd` (Do Not Disturb)**: The user will **not receive private messages**.
    - **`away`**: The sender will be notified that the recipient **may not respond**.
- **Broadcast Status Updates**: When a user updates their status, all clients are notified.

### **Encrypted Messaging**
- **AES Encrypted Messaging (`@secret username key message`)**: 
  - Encrypt messages using **AES encryption** with a custom key.
  - The recipient **must enter the correct key** to decrypt and receive the message.
  - Incorrect keys result in decryption failure.

### **Group Chat Management**
- **Group Creation (`@group set groupname user1,user2`)**: Creates a **group chat** with sepcified members.
- **Group Messaging (`@group send groupname message`)**: Sends a message **only to group members**.
- **Leaving a Group (`@group leave groupname`)**: Removes a user from a group.
- **Group Deletion (`@group delete groupname`)**: Deletes a group and **notifies all members**.

---

## Instructions to Run Application

### **Install Python & Dependencies**
Ensure you have **Python 3** installed. Install dependencies using:
```bash
pip install cryptography
```
### **Run the Server**
1. Open a terminal and navigate to the folder containing `Server.py`.
2. Start the server by running:
   ```bash
   python Server.py
   ```
3. The server will now start listening for incoming client connections.

### **Run a Client**
1. Open a terminal and navigate to the folder containing `Client.py`.
2. Run the client using:
   ```bash
   python Client.py
   ```
3. When prompted, enter the server's IP address to connect.
4. Choose a unique username to join the chat.
---
### **Usage Commands**
| **Command** | **Function** |
|------------|-------------|
| `@quit` | Disconnects from the server. |
| `@names` | Lists all connected users. |
| `@username message` | Sends a **private message** to a user. |
| `@secret username key message` | Sends an **AES-encrypted message** to a user. |
| `@group set groupname user1,user2` | Creates a **group chat**. |
| `@group send groupname message` | Sends a message **to the group**. |
| `@group leave groupname` | Leaves a group. |
| `@group delete groupname` | Deletes a group and **notifies all members**. |

---
### **Acknowledgement**
* Developed as a group project for our Computer Network Assignement
* Special thanks to our lecturer and teaching assistants for their support and feedback
* Gratitude to all team members for their contributions and collaboration throughout the project
