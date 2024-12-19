import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
private_key_path = None
public_key_path = None


def generate_keys(key_path=None, password=None):
    global private_key_path, public_key_path
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    if key_path:
        private_key_path = os.path.join(key_path, "private_key.pem")
        public_key_path = os.path.join(key_path, "public_key.pem")
    else:
        private_key_path = PRIVATE_KEY_FILE
        public_key_path = PUBLIC_KEY_FILE


    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    with open(private_key_path, "wb") as f:
        f.write(private_key_bytes)

    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    messagebox.showinfo("Keys Generated", "Keys generated successfully.")


def load_private_key(file_path, password):
    try:
        with open(file_path, "rb") as f:
            private_key_data = f.read()
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=password.encode(),
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load private key: {e}")
        return None


def sign_document(document_path, output_path, password):
    try:
        private_key = load_private_key(private_key_path, password)
        if not private_key:
            return

        with open(document_path, 'rb') as f:
            document = f.read()

        signature = private_key.sign(
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        with open(output_path, 'wb') as f:
            f.write(signature)

        messagebox.showinfo("Success", "Document signed successfully.")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to sign document: {e}")


def verify_signature(document_path, signature_path, public_key_path):
    try:
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load public key: {e}")
        return

    try:
        with open(document_path, 'rb') as f:
            document = f.read()

        with open(signature_path, 'rb') as f:
            signature = f.read()

        public_key.verify(
            signature,
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        messagebox.showinfo("Success", "Signature is valid.")
    except Exception as e:
        messagebox.showerror("Error", f"Signature verification failed: {e}")


def validate_document(document_path):
    if not os.path.exists(document_path):
        messagebox.showerror("Error", "Document does not exist.")
        return False

    file_size = os.path.getsize(document_path)
    if file_size == 0:
        messagebox.showerror("Error", "Document is empty.")
        return False

    return True


def ask_for_password(prompt="Enter password"):
    password = simpledialog.askstring("Password", prompt, show='*')
    return password


def generate_keys_command():
    key_path = filedialog.askdirectory(title="Select Directory to Save Keys")
    if not key_path:
        return

    password = ask_for_password("Enter a password for key encryption: ")
    if password:
        generate_keys(key_path, password)


def sign_document_command():
    document_path = filedialog.askopenfilename(title="Select Document to Sign")
    if not document_path or not validate_document(document_path):
        return

    output_path = filedialog.asksaveasfilename(title="Save Signature As")
    if not output_path:
        return

    password = ask_for_password("Enter the password for private key decryption: ")
    if password:
        sign_document(document_path, output_path, password)


def verify_signature_command():
    document_path = filedialog.askopenfilename(title="Select Document")
    if not document_path or not validate_document(document_path):
        return

    signature_path = filedialog.askopenfilename(title="Select Signature")
    if not signature_path:
        return


    public_key_path = filedialog.askopenfilename(
        title="Select Public Key",
        filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")]
    )
    if not public_key_path:
        return

    verify_signature(document_path, signature_path, public_key_path)


def main():
    root = tk.Tk()
    root.title("Digital Signature")

    generate_keys_button = tk.Button(root, text="Generate Keys", command=generate_keys_command)
    generate_keys_button.pack(pady=5)

    sign_document_button = tk.Button(root, text="Sign Document", command=sign_document_command)
    sign_document_button.pack(pady=5)

    verify_signature_button = tk.Button(root, text="Verify Signature", command=verify_signature_command)
    verify_signature_button.pack(pady=5)

    root.mainloop()


if __name__ == "__main__":
    main()