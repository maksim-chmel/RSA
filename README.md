# Digital Signature Application

This project is a graphical user interface (GUI) application built using Python and the `tkinter` library. It allows users to perform the following cryptographic operations:

- **Generate RSA Key Pairs**: Create a pair of RSA public and private keys with password-based encryption for the private key.
- **Sign Documents**: Use the private key to sign a document, creating a digital signature.
- **Verify Signatures**: Verify a document's authenticity using its signature and the public key.

The application is ideal for users who want to secure their files and ensure the integrity of their data through digital signatures.

---

## Features

### 1. **Key Generation**
- Generates a 2048-bit RSA key pair.
- Saves the private and public keys as `.pem` files in a user-selected directory.
- Secures the private key with a password for encryption.

### 2. **Document Signing**
- Allows users to select a file to sign.
- Uses the private key (protected by a password) to generate a digital signature.
- Saves the signature as a binary file.

### 3. **Signature Verification**
- Verifies the integrity and authenticity of a document using:
  - The document file.
  - The corresponding signature file.
  - The public key file.
 


## How to Use

1. Generate RSA Keys
	•	Click the Generate Keys button.
	•	Select a directory to save the key files.
	•	Enter a password to encrypt the private key.

2. Sign a Document
	•	Click the Sign Document button.
	•	Select the document to sign.
	•	Specify a location to save the signature file.
	•	Enter the password for the private key.

3. Verify a Signature
	•	Click the Verify Signature button.
	•	Select the document to verify.
	•	Select the corresponding signature file.
	•	Select the public key file.
	•	The application will indicate if the signature is valid or invalid.


This project is open-source and licensed under the Apache License Version 2.0.
