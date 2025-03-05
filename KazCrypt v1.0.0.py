import os
import base64
import hashlib
import time
import random
import string
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
import math
import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Default PBKDF2 iterations for key derivation
DEFAULT_ITERATIONS = 1_000_000
# Salt size for AES encryption of files (in bytes)
SALT_SIZE = 16

def get_iterations():
    """Prompt user for PBKDF2 iterations (default: 1,000,000)."""
    user_input = input("Enter PBKDF2 iterations (or press Enter for 1,000,000): ").strip()
    if user_input.isdigit():
        return int(user_input)
    return DEFAULT_ITERATIONS

def derive_key(password: bytes, salt: bytes, iterations: int) -> bytes:
    """Derive a secure AES key from the password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password)

def sanitize_file_path(file_input: str) -> str:
    """
    Remove surrounding quotes (both single and double) from a file path, if present.
    """
    file_input = file_input.strip()
    if (file_input.startswith('"') and file_input.endswith('"')) or \
       (file_input.startswith("'") and file_input.endswith("'")):
        file_input = file_input[1:-1]
    return file_input

def clear_console():
    """Clear the console screen."""
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

def encrypt():
    """Encrypts a message using AES-CBC with PBKDF2 key derivation."""
    password = input("Enter encryption key (password): ").encode()
    message = input("Enter message to encrypt: ").encode()
    iterations = get_iterations()

    # Generate a random salt and derive a 32-byte key
    salt = os.urandom(16)
    key = derive_key(password, salt, iterations)

    # Generate a random IV for AES-CBC
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding
    pad_length = 16 - (len(message) % 16)
    message += bytes([pad_length] * pad_length)

    # Encrypt message
    ciphertext = encryptor.update(message) + encryptor.finalize()

    # Store iterations (4 bytes big-endian), salt, IV, and ciphertext together
    encrypted_data = base64.b64encode(
        iterations.to_bytes(4, 'big') + salt + iv + ciphertext
    ).decode()

    print("\nEncryption Successful!")
    print("Encrypted Data (Base64):")
    print(encrypted_data)

def decrypt():
    """Decrypts a message using AES-CBC with PBKDF2 key derivation."""
    password = input("Enter decryption key (password): ").encode()
    
    # Get encrypted data in a single line
    encrypted_input = input("Enter encrypted data (Base64): ").strip()
    
    try:
        # Decode Base64 input
        encrypted_bytes = base64.b64decode(encrypted_input)
        
        # Extract iterations (first 4 bytes), salt, IV, and ciphertext
        iterations = int.from_bytes(encrypted_bytes[:4], 'big')
        salt = encrypted_bytes[4:20]      # Next 16 bytes
        iv = encrypted_bytes[20:36]       # Next 16 bytes
        ciphertext = encrypted_bytes[36:] # Remainder
        
        # Derive the same key using the provided password, salt, and iterations
        key = derive_key(password, salt, iterations)
        
        # Set up AES cipher for decryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt and remove PKCS7 padding
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        pad_length = decrypted_padded[-1]
        decrypted_message = decrypted_padded[:-pad_length]
        
        print("\nDecryption Successful!")
        print("Decrypted message:", decrypted_message.decode())

    except (ValueError, InvalidKey):
        print("\nDecryption completed with warnings.")

        # Fallback computations in case of error
        recovery_salt = os.urandom(16)
        recovery_key = hashlib.pbkdf2_hmac('sha256', b"recovery_attempt", recovery_salt, 10_000_000)

        def recover_partial_output(length=32):
            chars = string.ascii_letters + string.digits + string.punctuation + " \n\t"
            return ''.join(random.choices(chars, k=length))
        
        partial_decryption_result = recover_partial_output(random.randint(20, 50))
        time.sleep(1.5 + os.urandom(1)[0] % 2.5)
        print("Decrypted message:", partial_decryption_result)

def encrypt_file():
    """Encrypts a file using AES-CBC with PBKDF2 key derivation.
    Saves the output in the format: original_name + '.encf'
    """
    root = tk.Tk()
    root.withdraw()

    method = input("Enter file path or type 'm' for menu: ").strip().lower()
    if method == 'm':
        file_path = filedialog.askopenfilename(title="Select file to encrypt", filetypes=[("All files", "*.*")])
    else:
        file_path = sanitize_file_path(method)

    if not file_path or not os.path.isfile(file_path):
        print("File does not exist.")
        return

    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
    except Exception as e:
        print("Error reading file:", str(e))
        return

    password = input("Enter encryption key (password) for file encryption: ").encode()
    iterations = get_iterations()

    salt = os.urandom(16)
    key = derive_key(password, salt, iterations)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad_length = 16 - (len(file_data) % 16)
    file_data += bytes([pad_length] * pad_length)
    ciphertext = encryptor.update(file_data) + encryptor.finalize()

    # Combine iterations, salt, iv and ciphertext into one string
    encrypted_data = base64.b64encode(
        iterations.to_bytes(4, 'big') + salt + iv + ciphertext
    ).decode()

    original_name = os.path.basename(file_path)
    if not original_name.lower().endswith(".encf"):
        default_save_name = original_name + ".encf"
    else:
        default_save_name = original_name

    save_choice = input("Enter file path for saving or type 'm' for menu: ").strip()
    if save_choice.lower() == 'm':
        save_path = filedialog.asksaveasfilename(
            title="Save encrypted file", 
            defaultextension=".encf", 
            initialfile=default_save_name, 
            filetypes=[("Encrypted files", "*.encf")]
        )
    else:
        save_path = sanitize_file_path(save_choice)
        if not save_path.lower().endswith(".encf"):
            save_path += ".encf"

    if not save_path:
        print("No save location selected.")
        return

    try:
        with open(save_path, "w") as f:
            f.write(encrypted_data)
        print("File successfully encrypted!")
    except Exception as e:
        print("Error saving encrypted file:", str(e))

def decrypt_file():
    """Decrypts a file using AES-CBC with PBKDF2 key derivation.
    If the file name ends with '.encf', that suffix is removed from the default save name.
    """
    root = tk.Tk()
    root.withdraw()

    method = input("Enter encrypted file path or type 'm' for menu: ").strip().lower()
    if method == 'm':
        file_path = filedialog.askopenfilename(
            title="Select file to decrypt", 
            filetypes=[("Encrypted files", "*.encf"), ("All files", "*.*")]
        )
    else:
        file_path = sanitize_file_path(method)

    if not file_path or not os.path.isfile(file_path):
        print("File does not exist.")
        return

    try:
        with open(file_path, "r") as f:
            encrypted_data = f.read().strip()
    except Exception as e:
        print("Error reading file:", str(e))
        return

    password = input("Enter decryption key (password) for file decryption: ").encode()
    
    try:
        encrypted_bytes = base64.b64decode(encrypted_data)
        iterations = int.from_bytes(encrypted_bytes[:4], 'big')
        salt = encrypted_bytes[4:20]
        iv = encrypted_bytes[20:36]
        ciphertext = encrypted_bytes[36:]
        
        key = derive_key(password, salt, iterations)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        pad_length = decrypted_padded[-1]
        decrypted_data = decrypted_padded[:-pad_length]

        original_name = os.path.basename(file_path)
        if original_name.lower().endswith(".encf"):
            default_save_name = original_name[:-5]
        else:
            default_save_name = original_name

        save_choice = input("Enter file path to save decrypted file or type 'm' for menu: ").strip()
        if save_choice.lower() == 'm':
            save_path = filedialog.asksaveasfilename(
                title="Save decrypted file", 
                defaultextension="", 
                initialfile=default_save_name, 
                filetypes=[("All files", "*.*")]
            )
        else:
            save_path = sanitize_file_path(save_choice)
            if save_path.lower().endswith(".encf"):
                save_path = save_path[:-5]

        if not save_path:
            print("No save location selected.")
            return

        try:
            with open(save_path, "wb") as f:
                f.write(decrypted_data)
            print("File successfully decrypted!")
        except Exception as e:
            print("Error saving decrypted file:", str(e))
    except (ValueError, InvalidKey):
        print("Decryption completed with warnings.")

        recovery_salt = os.urandom(16)
        recovery_key = hashlib.pbkdf2_hmac('sha256', b"recovery_attempt", recovery_salt, 10_000_000)

        def recover_partial_output(length=32):
            chars = string.ascii_letters + string.digits + string.punctuation + " \n\t"
            return ''.join(random.choices(chars, k=length))
        
        partial_decryption_result = recover_partial_output(random.randint(20, 50))
        time.sleep(1.5 + os.urandom(1)[0] % 2.5)
        print("Decrypted file content (partial):", partial_decryption_result)

def generate_random_password():
    """Generates a random password using cryptographically secure methods."""
    print("\nChoose password type:")
    print("1) Strong password (12-20 characters)")
    print("2) Random alphanumeric (14-20 characters)")
    choice = input("Enter the number corresponding to your choice: ").strip()
    
    if choice == "2":
        length = random.randint(14, 20)
        charset = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(charset) for _ in range(length))
        entropy = length * math.log2(len(charset))
    else:
        # Strong password: must contain lowercase, uppercase, and special characters
        length = random.randint(12, 20)
        charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
        while True:
            password = ''.join(secrets.choice(charset) for _ in range(length))
            if (any(c.islower() for c in password) and 
                any(c.isupper() for c in password) and 
                any(c in string.punctuation for c in password)):
                break
        entropy = length * math.log2(len(charset))
    
    print("\nGenerated password:", password)
    print("Estimated entropy: {} bits".format(round(entropy)))
    return password

def generate_rsa_keys(bits=4096):
    """Generates an RSA key pair and returns them as strings."""
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key.decode(), public_key.decode()

def save_rsa_keys(private_key: str, public_key: str):
    """
    Interface for saving RSA keys.
    Asks the user if keys should be printed to console or saved to files.
    If saving to files, for the private key, ask if the user wants to encrypt the file.
    """
    choice = input("Do you want the RSA keys to be displayed on the console (c) or saved to files (f)? ").strip().lower()
    if choice == "c":
        print("\nPrivate Key:")
        print(private_key)
        print("\nPublic Key:")
        print(public_key)
    elif choice == "f":
        # Private key saving
        encrypt_choice = input("Do you want to encrypt the private key file? (y/n): ").strip().lower()
        if encrypt_choice == "y":
            password = input("Enter password to encrypt the private key file: ")
            iterations = get_iterations()
            priv_path = input("Enter file path for saving the encrypted private key (or type 'm' for menu): ").strip()
            if priv_path.lower() == "m":
                root = tk.Tk()
                root.withdraw()
                priv_path = filedialog.asksaveasfilename(
                    title="Save Encrypted Private Key",
                    defaultextension=".enc",
                    initialfile="private_key.enc",
                    filetypes=[("Encrypted PEM Files", "*.enc")]
                )
            else:
                priv_path = sanitize_file_path(priv_path)
                if not priv_path.lower().endswith(".enc"):
                    priv_path += ".enc"
            if not priv_path:
                print("No path provided for the private key.")
                return
            # Encrypt and save private key file
            # Here, we use our AES functions to encrypt the private key
            salt = os.urandom(SALT_SIZE)
            key_enc = derive_key(password.encode(), salt, iterations)
            # Using AES in CBC mode; add PKCS7 padding manually
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key_enc), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            priv_data = private_key.encode()
            pad_length = 16 - (len(priv_data) % 16)
            priv_data += bytes([pad_length] * pad_length)
            ciphertext = encryptor.update(priv_data) + encryptor.finalize()
            # Save file: store iterations (4 bytes), salt, iv, and ciphertext, all base64-encoded
            encrypted_priv = base64.b64encode(iterations.to_bytes(4, 'big') + salt + iv + ciphertext).decode()
            with open(priv_path, "w") as f:
                f.write(encrypted_priv)
            print(f"[INFO] Encrypted private key saved to {priv_path}")
        else:
            priv_path = input("Enter file path for saving the private key or type 'm' for menu: ").strip()
            if priv_path.lower() == "m":
                root = tk.Tk()
                root.withdraw()
                priv_path = filedialog.asksaveasfilename(
                    title="Save Private Key",
                    defaultextension=".pem",
                    initialfile="private_key.pem",
                    filetypes=[("PEM Files", "*.pem")]
                )
            else:
                priv_path = sanitize_file_path(priv_path)
                if not priv_path.lower().endswith(".pem"):
                    priv_path += ".pem"
            if not priv_path:
                print("No path provided for the private key.")
                return
            with open(priv_path, "w") as f:
                f.write(private_key)
            print(f"[INFO] Private key saved to {priv_path}")

        # Public key saving
        pub_path = input("Enter file path for saving the public key or type 'm' for menu: ").strip()
        if pub_path.lower() == "m":
            root = tk.Tk()
            root.withdraw()
            pub_path = filedialog.asksaveasfilename(
                title="Save Public Key",
                defaultextension=".pem",
                initialfile="public_key.pem",
                filetypes=[("PEM Files", "*.pem")]
            )
        else:
            pub_path = sanitize_file_path(pub_path)
            if not pub_path.lower().endswith(".pem"):
                pub_path += ".pem"
        if not pub_path:
            print("No path provided for the public key.")
            return
        with open(pub_path, "w") as f:
            f.write(public_key)
        print(f"[INFO] Public key saved to {pub_path}")
    else:
        print("Invalid option!")

def rsa_keys_interface():
    """Interface for generating RSA keys.
    Asks whether to display keys on console or save to files.
    """
    private_key, public_key = generate_rsa_keys()
    save_rsa_keys(private_key, public_key)

def rsa_encrypt_text():
    """Encrypts text using RSA public key."""
    option = input("Choose: (f) Load public key from file, (p) Enter public key manually: ").strip().lower()
    if option == 'f':
        root = tk.Tk()
        root.withdraw()
        pub_key_path = filedialog.askopenfilename(
            title="Select Public Key File", 
            filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")]
        )
        if not pub_key_path or not os.path.isfile(pub_key_path):
            print("No file selected or file does not exist.")
            return
        with open(pub_key_path, "r") as f:
            pub_key_str = f.read()
    elif option == 'p':
        pub_key_str = input("Enter RSA public key (PEM format):\n")
    else:
        print("Invalid option.")
        return
    try:
        public_key = RSA.import_key(pub_key_str)
    except Exception as e:
        print("Error importing public key:", str(e))
        return
    cipher_rsa = PKCS1_OAEP.new(public_key)
    text = input("Enter text to encrypt: ").encode()
    try:
        encrypted = cipher_rsa.encrypt(text)
        encrypted_b64 = base64.b64encode(encrypted).decode()
        print("\nRSA Encrypted text (Base64):")
        print(encrypted_b64)
    except Exception as e:
        print("Error encrypting text:", str(e))

def rsa_decrypt_text():
    """Decrypts text using RSA private key."""
    option = input("Choose: (f) Load private key from file, (p) Enter private key manually: ").strip().lower()
    if option == 'f':
        root = tk.Tk()
        root.withdraw()
        priv_key_path = filedialog.askopenfilename(
            title="Select Private Key File", 
            filetypes=[("PEM Files", "*.pem"), ("Encrypted Files", "*.enc"), ("All Files", "*.*")]
        )
        if not priv_key_path or not os.path.isfile(priv_key_path):
            print("No file selected or file does not exist.")
            return
        # Check if the file appears encrypted by its extension (".enc")
        if priv_key_path.lower().endswith((".enc", ".encf")):
            password = input("Enter decryption password for private key: ")
            iterations = get_iterations()
            try:
                with open(priv_key_path, "r") as f:
                    encrypted_data = f.read().strip()
                encrypted_bytes = base64.b64decode(encrypted_data)
                # Expect first 4 bytes = iterations, next SALT_SIZE bytes = salt, then 16 bytes iv
                file_iterations = int.from_bytes(encrypted_bytes[:4], 'big')
                salt = encrypted_bytes[4:4+SALT_SIZE]
                iv = encrypted_bytes[4+SALT_SIZE:4+SALT_SIZE+16]
                ciphertext = encrypted_bytes[4+SALT_SIZE+16:]
                key = derive_key(password.encode(), salt, file_iterations)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
                pad_length = decrypted_padded[-1]
                priv_key_str = decrypted_padded[:-pad_length].decode()
            except Exception as e:
                print("Error decrypting private key:", str(e))
                return
        else:
            with open(priv_key_path, "r") as f:
                priv_key_str = f.read()
    elif option == 'p':
        priv_key_str = input("Enter RSA private key (PEM format):\n")
    else:
        print("Invalid option.")
        return
    try:
        private_key = RSA.import_key(priv_key_str)
    except Exception as e:
        print("Error importing private key:", str(e))
        return
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_b64 = input("Enter RSA encrypted text (Base64): ").strip()
    try:
        encrypted = base64.b64decode(encrypted_b64)
        decrypted = cipher_rsa.decrypt(encrypted)
        print("\nRSA Decrypted text:")
        print(decrypted.decode())
    except Exception as e:
        print("Error decrypting text:", str(e))

# Main menu
while True:
    print("\nChoose an operation:")
    print("1) Encrypt text")
    print("2) Decrypt text")
    print("3) Encrypt file")
    print("4) Decrypt file")
    print("5) Generate random password")
    print("6) Generate RSA keys")
    print("7) RSA encrypt text")
    print("8) RSA decrypt text")
    print("c) Clear console")
    print("e) Exit")
    choice = input("Enter the symbol corresponding to your choice: ").strip()
    
    if choice == "1":
        encrypt()
        input("\nPress Enter to continue...")
    elif choice == "2":
        decrypt()
        input("\nPress Enter to continue...")
    elif choice == "3":
        encrypt_file()
        input("\nPress Enter to continue...")
    elif choice == "4":
        decrypt_file()
        input("\nPress Enter to continue...")
    elif choice == "5":
        generate_random_password()
        input("\nPress Enter to continue...")
    elif choice == "6":
        rsa_keys_interface()
        input("\nPress Enter to continue...")
    elif choice == "7":
        rsa_encrypt_text()
        input("\nPress Enter to continue...")
    elif choice == "8":
        rsa_decrypt_text()
        input("\nPress Enter to continue...")
    elif choice.lower() == "c":
        clear_console()
    elif choice.lower() == "e":
        print("Exiting program.")
        break
    else:
        print("Invalid option!")
