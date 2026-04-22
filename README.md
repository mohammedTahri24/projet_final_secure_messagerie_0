# Secure Messaging System – Hybrid Encryption (RSA + AES)

This project implements a **secure messaging system** designed to protect digital communications using a **hybrid cryptographic approach** that combines asymmetric and symmetric encryption.

The system ensures **confidentiality, integrity, and authenticity** of messages by leveraging strong cryptographic algorithms such as **RSA-3072, AES-256-CBC, SHA-256, and HMAC-SHA256**.

## Key Features

- RSA key pair generation for each user
- Secure exchange of AES session keys using RSA encryption
- Message encryption and decryption using AES-256-CBC
- Digital signatures using RSA-PSS
- Message integrity verification using SHA-256 and HMAC
- Graphical User Interface (GUI) for user interaction
- Command Line Interface (CLI) for advanced usage

## Cryptographic Architecture

The system follows a **hybrid encryption model**:

1. A random **AES session key** is generated to encrypt the message.
2. The AES key is encrypted using the **recipient's RSA public key**.
3. The sender signs the message using their **RSA private key**.
4. The encrypted message, encrypted AES key, and signature are sent to the recipient.
5. The recipient decrypts the AES key using their private RSA key and verifies the signature.

This approach combines:
- **RSA security for key exchange**
- **AES performance for message encryption**

## Technologies Used

- Python
- Cryptography libraries
- AES-256-CBC
- RSA-3072
- SHA-256
- HMAC
- GUI messaging interface

## Project Structure
keys/ # RSA key storage
crypto.py # Encryption and decryption functions
keygen.py # Key generation module
utils.py # Utility functions
gui_messenger.py # Graphical messaging interface

## Security Objectives

The system aims to guarantee:

- **Confidentiality**: Only authorized recipients can read messages
- **Integrity**: Messages cannot be modified during transmission
- **Authenticity**: Sender identity can be verified

## Future Improvements

- Secure network communication between users
- End-to-end encrypted messaging over sockets
- Group encrypted messaging
- Enhanced graphical interface
- Key management improvements

## Authors

- Mohamed Chanak
- Ilyas Meziani
- Mohammed Tahri
