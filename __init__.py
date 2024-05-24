import os
import sys
import subprocess

def create_virtual_environment():
    try:
        subprocess.check_call([sys.executable, '-m', 'venv', 'env'])
        print("Virtual environment created successfully.")
    except subprocess.CalledProcessError:
        print("Failed to create virtual environment.")

def install_dependencies():
    try:
        subprocess.check_call([os.path.join('env', 'bin', 'pip'), 'install', '-r', 'requirements.txt'])
        print("Dependencies installed successfully.")
    except subprocess.CalledProcessError:
        print("Failed to install dependencies.")

def initialize_project():
    print("Initializing Python project...")
    create_virtual_environment()
    install_dependencies()
    print("Project initialization complete.")

# Importing functions from krypt.py
from .krypt import load_public_keys_directories_from_config, list_public_keys, load_host_private_key_from_config, \
                   encrypt_file, decrypt_file, initialize_keys_directory, load_keys_directories_from_config, \
                   save_keys_directories_to_config, list_keys, add_public_key, delete_key, add_keys_directory, \
                   delete_keys_directory, generate_host_key, renew_host_key, set_host_keys_directory, genkeys, main

# Initialize the project
initialize_project()
