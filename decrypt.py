import os
import configparser

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def load_host_private_key_from_config(config_file="crypt.config"):
    config = configparser.ConfigParser()
    config.read(config_file)
    host_keys_dir = config.get("Keys", "Host_Keys_Directory", fallback="")
    
    if not host_keys_dir:
        raise ValueError("Host keys directory not configured in crypt.config")
    
    private_key_file = os.path.join(host_keys_dir, "example_private.pem")
    if not os.path.exists(private_key_file):
        raise FileNotFoundError(f"Private key file '{private_key_file}' not found")
    
    return private_key_file

def decrypt_file(input_file, output_file, private_key_file):
    with open(input_file, 'rb') as f:
        ciphertext = f.read()
    
    with open(private_key_file, "rb") as f:
        private_key_data = f.read()
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None,
            backend=default_backend()
        )

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_file, 'wb') as f:
        f.write(plaintext)

def main():
    try:
        private_key_file = load_host_private_key_from_config()
    except (ValueError, FileNotFoundError) as e:
        print(f"Error: {e}")
        return

    input_file = input("Enter the path of the file to decrypt: ")
    output_file = input("Enter the path for the decrypted file: ")

    decrypt_file(input_file, output_file, private_key_file)
    print("File decrypted successfully.")

if __name__ == "__main__":
    main()
