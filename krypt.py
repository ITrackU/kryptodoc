import os
import configparser
import shutil
import subprocess

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

def initialize_keys_directory(keys_dir):
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)
        print(f"Keys directory '{keys_dir}' created successfully.")

def load_keys_directories_from_config(config_file="crypt.config"):
    config = configparser.ConfigParser()
    config.read(config_file)
    
    host_keys_dir = config.get("Keys", "Host_Keys_Directory", fallback="")
    public_keys_dirs = config.get("Keys", "Public_Keys_Directories", fallback="")
    
    public_keys_dirs = public_keys_dirs.split(',') if public_keys_dirs else []
    
    return host_keys_dir, public_keys_dirs

def save_keys_directories_to_config(host_keys_dir, public_keys_dirs, config_file="crypt.config"):
    config = configparser.ConfigParser()
    config["Keys"] = {
        "Host_Keys_Directory": host_keys_dir,
        "Public_Keys_Directories": ','.join(public_keys_dirs)
    }
    with open(config_file, "w") as configfile:
        config.write(configfile)
    print(f"Host keys directory '{host_keys_dir}' and public keys directories '{public_keys_dirs}' saved to {config_file}.")

def list_keys(keys_dirs, key_type="public"):
    keys = []
    for keys_dir in keys_dirs:
        print(f"Keys directory: {keys_dir}")
        for filename in os.listdir(keys_dir):
            if key_type == "public" and filename.endswith("_public.pem"):
                key_id = filename.split("_")[0]
                print(key_id)
                keys.append(key_id)
            elif key_type == "host" and (filename.endswith("_public.pem") or filename.endswith("_private.pem")):
                print(filename)
                keys.append(filename)
    return keys

def add_public_key(key_id, key_path, dest_dir):
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
        print(f"Keys directory '{dest_dir}' created.")

    key_file_name = f"{key_id}_public.pem"
    dest_file_path = os.path.join(dest_dir, key_file_name)
    
    if os.path.exists(dest_file_path):
        print(f"Key file '{key_file_name}' already exists in '{dest_dir}'.")
        return

    try:
        shutil.copy(key_path, dest_file_path)
        print(f"Public key '{key_file_name}' copied to '{dest_dir}'.")
    except Exception as e:
        print(f"Error copying key file: {e}")

def delete_key(keys_dirs, key_id, key_type="public"):
    deleted = False
    for keys_dir in keys_dirs:
        if key_type == "public":
            key_file = os.path.join(keys_dir, f"{key_id}_public.pem")
        else:  # host keys
            key_file = os.path.join(keys_dir, f"{key_id}_private.pem")
            if os.path.exists(key_file):
                os.remove(key_file)
                print(f"Private key '{key_id}' deleted from '{keys_dir}'.")
            key_file = os.path.join(keys_dir, f"{key_id}_public.pem")
        
        if os.path.exists(key_file):
            os.remove(key_file)
            print(f"Public key '{key_id}' deleted from '{keys_dir}'.")
            deleted = True
    if not deleted:
        print(f"Key '{key_id}' not found in any keys directory.")

def add_keys_directory(public_keys_dirs):
    keys_dir = input("Enter the path of the public keys directory to add: ")
    initialize_keys_directory(keys_dir)
    public_keys_dirs.append(keys_dir)
    host_keys_dir, _ = load_keys_directories_from_config()
    save_keys_directories_to_config(host_keys_dir, public_keys_dirs)

def delete_keys_directory(public_keys_dirs):
    keys_dir = input("Enter the path of the public keys directory to delete: ")
    if keys_dir in public_keys_dirs:
        public_keys_dirs.remove(keys_dir)
        host_keys_dir, _ = load_keys_directories_from_config()
        save_keys_directories_to_config(host_keys_dir, public_keys_dirs)
        print(f"Public keys directory '{keys_dir}' deleted.")
    else:
        print(f"Public keys directory '{keys_dir}' not found.")

def generate_host_key(key_id, host_keys_dir):
    private_key_path = os.path.join(host_keys_dir, f"{key_id}_private.pem")
    public_key_path = os.path.join(host_keys_dir, f"{key_id}_public.pem")

    # Generate private key
    subprocess.run([
        "openssl", "genpkey", "-algorithm", "RSA", "-out", private_key_path,
        "-pkeyopt", "rsa_keygen_bits:2048"
    ])
    
    # Generate public key from the private key
    subprocess.run([
        "openssl", "rsa", "-pubout", "-in", private_key_path, "-out", public_key_path
    ])
    
    print(f"New host key pair '{key_id}' generated and saved to '{host_keys_dir}'.")

def renew_host_key(host_keys_dir):
    key_id = input("Enter the ID of the host key to renew: ")
    delete_key([host_keys_dir], key_id, key_type="host")
    generate_host_key(key_id, host_keys_dir)

def set_host_keys_directory():
    host_keys_dir = input("Enter the path of the host keys directory: ")
    initialize_keys_directory(host_keys_dir)
    _, public_keys_dirs = load_keys_directories_from_config()
    save_keys_directories_to_config(host_keys_dir, public_keys_dirs)
    print(f"Host keys directory set to '{host_keys_dir}'.")

def genkeys():
    config_file = "crypt.config"
    if not os.path.exists(config_file):
        host_keys_dir = input("Enter the path of the host keys directory: ")
        public_keys_dirs = input("Enter comma-separated paths of the public keys directories: ").split(',')
        initialize_keys_directory(host_keys_dir)
        for keys_dir in public_keys_dirs:
            initialize_keys_directory(keys_dir)
        save_keys_directories_to_config(host_keys_dir, public_keys_dirs)
    else:
        host_keys_dir, public_keys_dirs = load_keys_directories_from_config()

    print("Available options:")
    print("1. List public keys")
    print("2. Add a public key")
    print("3. Delete a public key")
    print("4. Add a public keys directory")
    print("5. Delete a public keys directory")
    print("6. List host keys")
    print("7. Renew a host key")
    print("8. Set host keys directory")
    
    choice = input("Enter your choice: ")
    if choice == '1':
        list_keys(public_keys_dirs, key_type="public")
    elif choice == '2':
        key_id = input("Enter the ID of the key to add: ")
        key_path = input("Enter the path of the public key file: ")
        dest_dir = input("Enter the destination directory: ")
        add_public_key(key_id, key_path, dest_dir)
    elif choice == '3':
        key_id = input("Enter the ID of the key to delete: ")
        delete_key(public_keys_dirs, key_id, key_type="public")
    elif choice == '4':
        add_keys_directory(public_keys_dirs)
    elif choice == '5':
        delete_keys_directory(public_keys_dirs)
    elif choice == '6':
        list_keys([host_keys_dir], key_type="host")
    elif choice == '7':
        renew_host_key(host_keys_dir)
    elif choice == '8':
        set_host_keys_directory()
    else:
        print("Invalid choice.")

def main():
    try:
        public_keys_dirs = load_public_keys_directories_from_config()
        private_key_file = load_host_private_key_from_config()
    except (ValueError, FileNotFoundError) as e:
        print(f"Error: {e}")
        return
    
    while True:
        print("\nOptions:")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Manage RSA Keys")
        print("4. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            try:
                public_keys = list_public_keys(public_keys_dirs)
                if not public_keys:
                    print("No public keys found.")
                    continue
                
                print("Available public keys:")
                for idx, (key_id, key_path) in enumerate(public_keys):
                    print(f"{idx + 1}. {key_id}")

                key_choice = int(input("Enter the number of the public key to use: ")) - 1
                
                if key_choice < 0 or key_choice >= len(public_keys):
                    print("Invalid choice.")
                    continue
                
                public_key_path = public_keys[key_choice][1]
                
                with open(public_key_path, "rb") as f:
                    public_key = serialization.load_pem_public_key(
                        f.read(),
                        backend=default_backend()
                    )

                input_file = input("Enter the path of the file to encrypt: ")
                output_file = input("Enter the path for the encrypted file: ")

                encrypt_file(input_file, output_file, public_key)
                print("File encrypted successfully.")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "2":
            try:
                input_file = input("Enter the path of the file to decrypt: ")
                output_file = input("Enter the path for the decrypted file: ")
                decrypt_file(input_file, output_file, private_key_file)
                print("File decrypted successfully.")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == "3":
            try:
                genkeys()
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "4":
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please enter a number.")

if __name__ == "__main__":
    main()
