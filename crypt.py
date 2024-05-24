import os
import configparser
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def load_public_keys_directories_from_config(config_file="crypt.config"):
    config = configparser.ConfigParser()
    config.read(config_file)
    public_keys_dirs = config.get("Keys", "Public_Keys_Directories", fallback="")
    
    if not public_keys_dirs:
        raise ValueError("Public keys directories not configured in crypt.config")
    
    return public_keys_dirs.split(',')

def list_public_keys(keys_dirs):
    public_keys = []
    for keys_dir in keys_dirs:
        for filename in os.listdir(keys_dir):
            if filename.endswith("_public.pem"):
                key_id = filename.split("_")[0]
                public_keys.append((key_id, os.path.join(keys_dir, filename)))
    return public_keys

def encrypt_file(input_file, output_file, public_key):
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    with open(output_file, 'wb') as f:
        f.write(ciphertext)

def main():
    try:
        public_keys_dirs = load_public_keys_directories_from_config()
    except ValueError as e:
        print(f"Error: {e}")
        return
    
    public_keys = list_public_keys(public_keys_dirs)
    
    if not public_keys:
        print("No public keys found.")
        return
    
    print("Available public keys:")
    for idx, (key_id, key_path) in enumerate(public_keys):
        print(f"{idx + 1}. {key_id}")

    choice = int(input("Enter the number of the public key to use: ")) - 1
    
    if choice < 0 or choice >= len(public_keys):
        print("Invalid choice.")
        return
    
    public_key_path = public_keys[choice][1]
    
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    input_file = input("Enter the path of the file to encrypt: ")
    output_file = input("Enter the path for the encrypted file: ")

    encrypt_file(input_file, output_file, public_key)
    print("File encrypted successfully.")

if __name__ == "__main__":
    main()
