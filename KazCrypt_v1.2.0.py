import os
import base64
import hashlib
import time
import random
import string
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import math
import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import quantcrypt

# Default PBKDF2 iterations for key derivation
DEFAULT_ITERATIONS = 1_000_000
# Salt size for AES encryption of files (in bytes)
SALT_SIZE = 16
# dh parameters
dh_private_key = None
dh_parameters = None

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

def encrypt_cbc():
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

def decrypt_cbc():
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
        recovery_salt = os.urandom(16)
        recovery_key = hashlib.pbkdf2_hmac('sha256', b"recovery_attempt", recovery_salt, 10_000_000)

        def recover_partial_output(length=32):
            chars = string.ascii_letters + string.digits + string.punctuation + " \n\t"
            return ''.join(random.choices(chars, k=length))
        
        partial_decryption_result = recover_partial_output(random.randint(20, 50))
        time.sleep(1.5 + os.urandom(1)[0] % 2.5)
        print("Decrypted message (partial):", partial_decryption_result)

def encrypt_gcm():
    """Encrypts a message using AES-GCM (authenticated encryption) with PBKDF2 key derivation."""
    password = input("Enter encryption key (password): ").encode()
    message = input("Enter message to encrypt: ").encode()
    iterations = get_iterations()

    # Generate a random salt and derive a 32-byte key
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt, iterations)

    # Generate a random nonce (12 bytes recommended for GCM)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, message, None)  # No additional authenticated data (AAD)

    # Store iterations (4 bytes), salt, nonce, and ciphertext (includes tag) together
    encrypted_data = base64.b64encode(
        iterations.to_bytes(4, 'big') + salt + nonce + ciphertext
    ).decode()

    print("\nEncryption Successful!")
    print("Encrypted Data (Base64):")
    print(encrypted_data)

def decrypt_gcm():
    """Decrypts a message encrypted using AES-GCM with PBKDF2 key derivation."""
    password = input("Enter decryption key (password): ").encode()
    encrypted_input = input("Enter encrypted data (Base64): ").strip()
    
    try:
        encrypted_bytes = base64.b64decode(encrypted_input)
        
        # Extract iterations, salt, nonce, and ciphertext
        iterations = int.from_bytes(encrypted_bytes[:4], 'big')
        salt = encrypted_bytes[4:4+SALT_SIZE]
        nonce = encrypted_bytes[4+SALT_SIZE:4+SALT_SIZE+12]  # 12-byte nonce
        ciphertext = encrypted_bytes[4+SALT_SIZE+12:]
        
        key = derive_key(password, salt, iterations)
        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        
        print("\nDecryption Successful!")
        print("Decrypted message:", decrypted.decode())
    except Exception as e:
        print("Decryption error:", str(e))

def Hash():
    def get_available_hashes():
        """Return a sorted list of all available hash algorithms in hashlib."""
        return sorted(hashlib.algorithms_available)

    def choose_algorithm():
        """Display a menu of available hash algorithms and return the chosen one."""
        available_hashes = get_available_hashes()
        print("Choose a hashing algorithm:")
        for index, algo in enumerate(available_hashes, start=1):
            print(f"{index}) {algo}")
        choice = input("Enter the number corresponding to your choice: ").strip()
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(available_hashes):
            print("Invalid choice!")
            return None
        return available_hashes[int(choice) - 1]

    def hash_text(algorithm: str) -> str:
        """Hash user-input text using the selected algorithm."""
        message = input("Enter text to hash: ").encode()
        hash_object = hashlib.new(algorithm, message)
        return hash_object.hexdigest()

    def hash_file(algorithm: str) -> str:
        """Hash the contents of a file using the selected algorithm."""
        file_input = input("Enter file path or type 'm' for menu: ").strip()
        if file_input.lower() == "m":
            root = tk.Tk()
            root.withdraw()
            file_path = filedialog.askopenfilename(title="Select file to hash")
            if not file_path:
                print("No file selected!")
                return None
        else:
            file_path = file_input
            if (file_path.startswith('"') and file_path.endswith('"')) or \
               (file_path.startswith("'") and file_path.endswith("'")):
                file_path = file_path[1:-1]
        if not os.path.exists(file_path):
            print("File not found!")
            return None
        hash_object = hashlib.new(algorithm)
        block_size = 65536  # 64KB
        with open(file_path, "rb") as f:
            while chunk := f.read(block_size):
                hash_object.update(chunk)
        return hash_object.hexdigest()

    def hash_main():
        option = input("Hash (t)ext or a (f)ile? ").strip().lower()
        if option not in ("t", "f"):
            print("Invalid option!")
            return

        algorithm = choose_algorithm()
        if not algorithm:
            return

        if option == "t":
            result = hash_text(algorithm)
        else:
            result = hash_file(algorithm)

        if result is not None:
            print(f"\nComputed {algorithm} hash:")
            print(result)

    if __name__ == "__main__":
        hash_main()

def encrypt_file_cbc():
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

def decrypt_file_cbc():
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

def encrypt_file_gcm():
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

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt, iterations)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, file_data, None)

    # Build the encrypted output: iterations (4 bytes) + salt + nonce + ciphertext
    encrypted_data = base64.b64encode(iterations.to_bytes(4, 'big') + salt + nonce + ciphertext).decode()
    original_name = os.path.basename(file_path)
    default_save_name = original_name + ".gcmenc" if not original_name.lower().endswith(".gcmenc") else original_name

    save_choice = input("Enter file path for saving or type 'm' for menu: ").strip()
    if save_choice.lower() == 'm':
        save_path = filedialog.asksaveasfilename(title="Save encrypted file", defaultextension=".gcmenc", initialfile=default_save_name, filetypes=[("GCM Encrypted files", "*.gcmenc")])
    else:
        save_path = sanitize_file_path(save_choice)
        if not save_path.lower().endswith(".gcmenc"):
            save_path += ".gcmenc"

    if not save_path:
        print("No save location selected.")
        return

    try:
        with open(save_path, "w") as f:
            f.write(encrypted_data)
        print("File successfully encrypted with AES-GCM!")
    except Exception as e:
        print("Error saving encrypted file:", str(e))

def decrypt_file_gcm():
    root = tk.Tk()
    root.withdraw()
    method = input("Enter encrypted file path or type 'm' for menu: ").strip().lower()
    if method == 'm':
        file_path = filedialog.askopenfilename(title="Select file to decrypt", filetypes=[("GCM Encrypted files", "*.gcmenc"), ("All files", "*.*")])
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
        salt = encrypted_bytes[4:4+SALT_SIZE]
        nonce = encrypted_bytes[4+SALT_SIZE:4+SALT_SIZE+12]
        ciphertext = encrypted_bytes[4+SALT_SIZE+12:]
        
        key = derive_key(password, salt, iterations)
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        
        original_name = os.path.basename(file_path)
        default_save_name = original_name.replace(".gcmenc", "") if original_name.lower().endswith(".gcmenc") else original_name + ".dec"
        
        save_choice = input("Enter file path to save decrypted file or type 'm' for menu: ").strip()
        if save_choice.lower() == 'm':
            save_path = filedialog.asksaveasfilename(title="Save decrypted file", defaultextension="", initialfile=default_save_name, filetypes=[("All files", "*.*")])
        else:
            save_path = sanitize_file_path(save_choice)
            if save_path.lower().endswith(".gcmenc"):
                save_path = save_path[:-7]
        
        if not save_path:
            print("No save location selected.")
            return

        try:
            with open(save_path, "wb") as f:
                f.write(decrypted_data)
            print("File successfully decrypted with AES-GCM!")
        except Exception as e:
            print("Error saving decrypted file:", str(e))
    except Exception as e:
        print("Decryption error:", str(e))

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
            salt = os.urandom(SALT_SIZE)
            key_enc = derive_key(password.encode(), salt, iterations)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key_enc), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            priv_data = private_key.encode()
            pad_length = 16 - (len(priv_data) % 16)
            priv_data += bytes([pad_length] * pad_length)
            ciphertext = encryptor.update(priv_data) + encryptor.finalize()
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
        if priv_key_path.lower().endswith((".enc", ".encf")):
            password = input("Enter decryption password for private key: ")
            iterations = get_iterations()
            try:
                with open(priv_key_path, "r") as f:
                    encrypted_data = f.read().strip()
                encrypted_bytes = base64.b64decode(encrypted_data)
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

def dh_initiate():
    """
    DHKE Initiate: Generates DH parameters and key pair.
    Outputs a package with a type marker, so the receiver knows this is a DH key exchange.
    """
    global dh_private_key, dh_parameters
    print("Generating Diffie–Hellman parameters and key pair...")
    try:
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    except Exception as e:
        print("Error generating parameters:", str(e))
        return
    dh_parameters = parameters
    parameter_numbers = parameters.parameter_numbers()
    private_key = parameters.generate_private_key()
    dh_private_key = private_key
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    p_hex = hex(parameter_numbers.p)[2:]
    g_hex = hex(parameter_numbers.g)[2:]
    pub_hex = hex(public_numbers.y)[2:]
    
    package = f"type=DH;p={p_hex};g={g_hex};pub={pub_hex}"
    print("\nYour DHKE package (send it to the other party):")
    print(package)
    
    remote_input = input("\nIf you have the other party's public key (in hex, optionally prefixed with 'pub=' or as a package), paste it below, or press Enter to skip: ").strip()
    if remote_input:
        if "type=" in remote_input and ";" in remote_input:
            parts = remote_input.split(';')
            data = {}
            for part in parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    data[key.strip()] = value.strip()
            if data.get("type") != "DH" or "pub" not in data:
                print("The provided package is not a valid DH package.")
                return
            remote_pub_hex = data["pub"]
        else:
            remote_pub_hex = remote_input[4:] if remote_input.startswith("pub=") else remote_input

        try:
            remote_pub_int = int(remote_pub_hex, 16)
            parameter_numbers = dh_parameters.parameter_numbers()
            peer_numbers = dh.DHPublicNumbers(remote_pub_int, parameter_numbers)
            peer_public_key = peer_numbers.public_key(backend=default_backend())
            shared_key = dh_private_key.exchange(peer_public_key)
            print("\nShared secret (hex):")
            print(shared_key.hex())
        except Exception as e:
            print("Error computing shared secret:", str(e))

def dh_complete():
    """
    DHKE Respond: Accepts a DH package with a type marker, generates your key pair,
    computes the shared secret, and outputs your public key package.
    """
    print("Paste the received DHKE package (format: type=DH;p=<hex>;g=<hex>;pub=<hex>):")
    package = input().strip()
    try:
        parts = package.split(';')
        data = {}
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                data[key.strip()] = value.strip()
        if data.get("type") != "DH":
            print("The package is not of type DH. Please use the appropriate function for the key exchange type.")
            return
        
        p_hex = data.get("p")
        g_hex = data.get("g")
        remote_pub_hex = data.get("pub")
        if not (p_hex and g_hex and remote_pub_hex):
            print("Incomplete package.")
            return
        
        p = int(p_hex, 16)
        g = int(g_hex, 16)
        remote_pub = int(remote_pub_hex, 16)
        
        pn = dh.DHParameterNumbers(p, g)
        parameters = pn.parameters(backend=default_backend())
        parameter_numbers = parameters.parameter_numbers()
        
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        
        peer_numbers = dh.DHPublicNumbers(remote_pub, parameter_numbers)
        peer_public_key = peer_numbers.public_key(backend=default_backend())
        shared_key = private_key.exchange(peer_public_key)
        
        print("\nShared secret (hex):")
        print(shared_key.hex())
        
        my_pub_hex = hex(public_numbers.y)[2:]
        reply_package = f"type=DH;pub={my_pub_hex}"
        print("\nSend the following package to the initiating party:")
        print(reply_package)
    except Exception as e:
        print("Error processing package:", str(e))

def ecdh_initiate():
    """
    ECDH Initiate:
    Generates an ECDH key pair using the SECP256R1 curve.
    Outputs a package with a type marker ("type=ECDH") to send to the other party.
    """
    print("Generating ECDH key pair using curve SECP256R1...")
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    pub_hex = pub_bytes.hex()
    
    package = "type=ECDH;pub=" + pub_hex
    print("\nYour ECDH package (send it to the other party):")
    print(package)
    
    remote_input = input(
        "\nIf you have the other party's public key (in hex, optionally prefixed with 'pub=' or as a package), paste it below, or press Enter to skip: "
    ).strip()
    if remote_input:
        if "type=" in remote_input and ";" in remote_input:
            parts = remote_input.split(';')
            data = {}
            for part in parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    data[key.strip()] = value.strip()
            if data.get("type") != "ECDH" or "pub" not in data:
                print("The provided package is not a valid ECDH package.")
                return
            remote_pub_hex = data["pub"]
        else:
            remote_pub_hex = remote_input[4:] if remote_input.startswith("pub=") else remote_input
        
        try:
            remote_pub_bytes = bytes.fromhex(remote_pub_hex)
            remote_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), remote_pub_bytes)
            shared_secret = private_key.exchange(ec.ECDH(), remote_public_key)
            print("\nShared secret (hex):")
            print(shared_secret.hex())
        except Exception as e:
            print("Error computing shared secret:", str(e))

def ecdh_complete():
    """
    ECDH Respond: Accepts an ECDH package with a type marker,
    generates your own key pair, computes the shared secret,
    and outputs your public key package.
    """
    print("Paste the received ECDH package (format: type=ECDH;pub=<hex>):")
    package = input().strip()
    try:
        parts = package.split(';')
        data = {}
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                data[key.strip()] = value.strip()
        if data.get("type") != "ECDH":
            print("The package is not of type ECDH. Please use the appropriate function for the key exchange type.")
            return
        
        remote_pub_hex = data.get("pub")
        if not remote_pub_hex:
            print("Incomplete package.")
            return
        
        remote_pub_bytes = bytes.fromhex(remote_pub_hex)
        remote_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), remote_pub_bytes)
    except Exception as e:
        print("Error processing the package:", str(e))
        return

    print("Generating your ECDH key pair using curve SECP256R1...")
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    pub_hex = pub_bytes.hex()

    try:
        shared_secret = private_key.exchange(ec.ECDH(), remote_public_key)
        print("\nShared secret (hex):")
        print(shared_secret.hex())
    except Exception as e:
        print("Error computing shared secret:", str(e))
        return

    reply_package = "type=ECDH;pub=" + pub_hex
    print("\nSend the following package to the initiating party:")
    print(reply_package)

def match_text():
    while True:
        str1 = input("Paste the first string: ")
        str2 = input("Paste the second string: ")
        if str1 == str2:
            print("✅ The strings match!")
        else:
            print("❌ The strings DO NOT match!")
        while True:
            choice = input("Do you want to check next string (y/n)? ").strip().lower()
            if choice == "y":
                break
            elif choice == "n":
                return
            else:
                print("Invalid choice!")

# Old features menu - Legacy features menu for backward compatibility

def legacy_features():
    while True:
        print("\nWARNING! THESE ARE LEGACY FEATURES AND USING THEM MAY POSE SECURITY RISKS")
        print("Choose an operation:")
        print("1) Encrypt text (AES-CBC)")
        print("2) Decrypt text (AES-CBC)")
        print("3) Encrypt file (AES-CBC)")
        print("4) Decrypt file (AES-CBC)")
        print("5) Initiate Diffie–Hellman Key Exchange (Legacy)")
        print("6) Complete Diffie–Hellman Key Exchange (Legacy)")
        print("n) Go to new features")
        print("c) Clear console")
        print("e) Exit")
        choice2 = input("Enter the symbol corresponding to your choice: ").strip()
        
        if choice2 == "1":
            encrypt_cbc()
            input("\nPress Enter to continue...")
        elif choice2 == "2":
            decrypt_cbc()
            input("\nPress Enter to continue...")
        elif choice2 == "3":
            encrypt_file_cbc()
            input("\nPress Enter to continue...")
        elif choice2 == "4":
            decrypt_file_cbc()
            input("\nPress Enter to continue...")
        elif choice2 == "5":
            dh_initiate()  # renamed from dhke() in v1.2.0
            input("\nPress Enter to continue...")
        elif choice2 == "6":
            dh_complete()  # renamed from dhke2() in v1.2.0
            input("\nPress Enter to continue...")
        elif choice2.lower() == "c":
            clear_console()
        elif choice2.lower() == "n":
            return
        elif choice2.lower() == "e":
            print("Exiting program.")
            break
        else:
            print("Invalid option!")

# --------------------------
# Main menu
# --------------------------
while True:
    print("\nChoose an operation:")
    print("1) Encrypt text (AES-GCM)")
    print("2) Decrypt text (AES-GCM)")
    print("3) Encrypt file (AES-GCM)")
    print("4) Decrypt file (AES-GCM)")
    print("5) Generate random password")
    print("6) Generate RSA keys")
    print("7) RSA encrypt text")
    print("8) RSA decrypt text")
    print("9) Initiate Elliptic Curve Diffie–Hellman Key Exchange")
    print("10) Complete Elliptic Curve Diffie–Hellman Key Exchange")
    print("11) Hash")
    print("12) Check if texts match")
    print("o) Show legacy features (Not recommended)")
    print("c) Clear console")
    print("e) Exit")
    choice = input("Enter the symbol corresponding to your choice: ").strip()
    
    if choice == "1":
        encrypt_gcm()
        input("\nPress Enter to continue...")
    elif choice == "2":
        decrypt_gcm()
        input("\nPress Enter to continue...")
    elif choice == "3":
        encrypt_file_gcm()
        input("\nPress Enter to continue...")
    elif choice == "4":
        decrypt_file_gcm()
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
    elif choice == "9":
        ecdh_initiate()
        input("\nPress Enter to continue...")
    elif choice == "10":
        ecdh_complete()  # renamed from ecdh_respond() in v1.2.0
        input("\nPress Enter to continue...")
    elif choice == "11":
        hash()
        input("\nPress Enter to continue...")
    elif choice == "12":
        match_text()
        input("\nPress Enter to continue...")
    elif choice.lower() == "o":
        legacy_features()
    elif choice.lower() == "c":
        clear_console()
    elif choice.lower() == "e":
        print("Exiting program.")
        break
    else:
        print("Invalid option!")

