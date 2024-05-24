import os
import configparser
import shutil
import subprocess

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from encrypt_decrypt import load_public_keys_directories_from_config, list_public_keys, encrypt_file, decrypt_file
from host_keys import load_host_private_key_from_config, generate_host_key, renew_host_key, set_host_keys_directory, delete_key
from keys_directories import initialize_keys_directory, load_keys_directories_from_config, save_keys_directories_to_config, list_keys, add_public_key, delete_keys_directory, add_keys_directory


def main():
    while True:
        print("\nOptions:")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. List public keys")
        print("4. Add a public key")
        print("5. Delete a public key")
        print("6. Add a public keys directory")
        print("7. Delete a public keys directory")
        print("8. List host keys")
        print("9. Renew a host key")
        print("10. Set host keys directory")
        print("0. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            try:
                public_keys_dirs = load_public_keys_directories_from_config()
            except ValueError as e:
                print(f"Error: {e}")
                continue
            
            public_keys = list_public_keys(public_keys_dirs)
            
            if not public_keys:
                print("No public keys found.")
                continue
            
            print("Available public keys:")
            for idx, (key_id, _) in enumerate(public_keys):
                print(f"{idx + 1}. {key_id}")

            choice = int(input("Enter the number of the public key to use: ")) - 1
            
            if choice < 0 or choice >= len(public_keys):
                print("Invalid choice.")
                continue
            
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

        elif choice == '2':
            try:
                private_key_file = load_host_private_key_from_config()
            except (ValueError, FileNotFoundError) as e:
                print(f"Error: {e}")
                continue

            input_file = input("Enter the path of the file to decrypt: ")
            output_file = input("Enter the path for the decrypted file: ")

            decrypt_file(input_file, output_file, private_key_file)
            print("File decrypted successfully.")
        
        elif choice == '3':
            host_keys_dir, public_keys_dirs = load_keys_directories_from_config()
            list_keys(public_keys_dirs, key_type="public")
        
        elif choice == '4':
            key_id = input("Enter the ID of the key to add: ")
            key_path = input("Enter the path of the public key file: ")
            dest_dir = input("Enter the destination directory: ")
            add_public_key(key_id, key_path, dest_dir)
        
        elif choice == '5':
            key_id = input("Enter the ID of the key to delete: ")
            delete_key(public_keys_dirs, key_id, key_type="public")
        
        elif choice == '6':
            add_keys_directory(public_keys_dirs)
        
        elif choice == '7':
            delete_keys_directory(public_keys_dirs)
        
        elif choice == '8':
            host_keys_dir, _ = load_keys_directories_from_config()
            list_keys([host_keys_dir], key_type="host")
        
        elif choice == '9':
            renew_host_key(host_keys_dir)
        
        elif choice == '10':
            set_host_keys_directory()
        
        elif choice == '0':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
