Krypt - README
Overview

Krypt is a program designed for secure encryption and decryption of files using RSA and AES cryptographic techniques. It allows users to manage encryption keys, encrypt and decrypt files, and handle recipient-specific configurations.
Features

    RSA Key Generation: Generate RSA public and private keys.
    AES Encryption: Encrypt and decrypt files using AES encryption.
    Recipient Management: Add, update, or remove recipients and their corresponding encryption keys.
    File Encryption: Encrypt files for specific recipients.
    File Decryption: Decrypt received encrypted files.

Requirements

    Python 3.x
    cryptography library

Install the required library using pip:

pip install cryptography

Configuration

The configuration file is located at ~/.krypt/krypt.config. If it does not exist, it will be created during the initial setup. This file contains directory paths and recipient information.

Initial Setup

Run the program to perform the initial setup:

python krypt.py

During the setup, you will be prompted to create the necessary directories and generate RSA keys.

Usage
Main Menu

    Manage Recipients: Add, update, or delete recipient information.
    Manage Local Keys: Generate new RSA keys.
    Encrypt a File: Encrypt a file for a specific recipient.
    Decrypt a File: Decrypt a received encrypted file.
    Quit: Exit the program.

Managing Recipients

To manage recipients, select option 1 from the main menu. You can then choose to add or remove a recipient.

Encrypting a File

To encrypt a file, select option 3 from the main menu. You will be prompted to choose a recipient and specify the file to encrypt. The encrypted file and the AES key will be stored in a tar archive in the to_send directory.

Decrypting a File

To decrypt a file, select option 4 from the main menu. You will be prompted to provide the path to the encrypted tar archive. The program will extract and decrypt the file, saving it in the received directory.

Detailed Functionality

RSA Cryptography

    Generate RSA Key Pair: Generates a 2048-bit RSA key pair.
    Save RSA Keys: Saves the generated RSA keys to specified directories.

AES Cryptography

    Generate Random Key: Generates a random AES key.
    Encrypt Content: Encrypts content using AES with CBC mode.
    Encrypt File: Encrypts a file using a recipient's AES key and stores the encrypted content and key in a tar archive.
    Decrypt Content: Decrypts AES-encrypted content.
    Decrypt File: Decrypts a tar archive containing an encrypted file and AES key.

File Management

    Ensure Directory Exists: Creates a directory if it does not exist.
    Save to File: Saves content to a specified file.
    Create Tar Archive: Creates a tar archive of specified files.
    Extract Tar Archive: Extracts files from a tar archive.

Recipient Management

    Add New Recipient: Adds a new recipient by generating a new AES key and copying the recipient's RSA public key.
    Erase Recipient: Deletes a recipient's information and keys.
    Update Configuration: Updates the configuration file with recipient information.

Running the Program

To run the program, execute the following command:

python krypt.py

Follow the prompts to navigate through the menus and perform the desired actions.

License

This project is licensed under the MIT License.

Contact

For any issues or questions, please contact ITrackU at tbn@bigacloud.com

Krypt: Programme de Chiffrement et Déchiffrement

=====================FRENCH========================

Description

Krypt est un programme de chiffrement et déchiffrement de fichiers utilisant les algorithmes RSA et AES. Il permet de gérer les clés de chiffrement, de chiffrer et déchiffrer des fichiers, et de gérer les destinataires des fichiers chiffrés.
Fonctionnalités

    Génération et gestion des clés RSA
    Chiffrement AES des fichiers
    Gestion des destinataires et des clés associées
    Chiffrement et déchiffrement de fichiers

Prérequis

    Python 3.x
    Bibliothèque cryptography
    Bibliothèque configparser

Installation

    Clonez ce dépôt:

    bash

git clone <url_du_dépôt>
cd <nom_du_dépôt>

Installez les dépendances:

bash

    pip install cryptography

Configuration

Avant d'utiliser le programme, vous devez créer un fichier de configuration et initialiser les répertoires nécessaires.
Créer le fichier de configuration

Lors de la première exécution, le programme vous demandera si vous souhaitez créer un fichier de configuration par défaut:

bash

python main.py

Vous pouvez également créer le fichier de configuration manuellement:

python

def create_config_file():
    config_file_path = os.path.expanduser("~/.krypt/krypt.config")
    if os.path.exists(config_file_path):
        restore_default_config = input("Un fichier de configuration existe déjà. Voulez-vous rétablir la configuration par défaut ? (oui/non): ").lower()
        if restore_default_config in ["oui", "yes"]:
            os.remove(config_file_path)
        else:
            return
    base_directory = os.path.expanduser("~/.krypt")
    directories = {
        'host_keys_directory': os.path.join(base_directory, "keys/host_keys"),
        'remote_keys_directory': os.path.join(base_directory, "keys/remote_keys"),
        'to_send_directory': os.path.join(base_directory, "to_send"),
        'received_directory': os.path.join(base_directory, "received")
    }
    ensure_directory_exists(directories['host_keys_directory'])
    ensure_directory_exists(directories['remote_keys_directory'])
    ensure_directory_exists(directories['to_send_directory'])
    ensure_directory_exists(directories['received_directory'])
    config = configparser.ConfigParser()
    config['directories'] = directories
    with open(config_file_path, 'w') as configfile:
        config.write(configfile)

Utilisation

Lancez le programme:

bash

python main.py

Menu Principal

    Gérer les destinataires: Ajouter, renouveler ou supprimer des destinataires et leurs clés associées.
    Gérer les clés locales: Générer et sauvegarder des clés RSA locales.
    Encrypter un fichier: Chiffrer un fichier pour un destinataire spécifié.
    Décrypter un fichier: Déchiffrer un fichier reçu.
    Quitter: Quitter le programme.

Détails des Fonctions
RSA

    generate_rsa_key_pair(): Génère une paire de clés RSA.
    save_new_rsa_keys(): Sauvegarde les clés RSA générées.

AES

    generate_rdm(octets): Génère une clé AES aléatoire.
    crypt(content, aes_key): Chiffre un contenu avec AES.
    crypt_file(): Chiffre un fichier pour un destinataire spécifié.
    decrypt(encrypted_content, aes_key): Déchiffre un contenu AES.
    decrypt_file(): Déchiffre un fichier reçu.

Gestion des fichiers

    save_to_file(content, filename): Sauvegarde un contenu dans un fichier.
    ensure_directory_exists(directory): Assure l'existence d'un répertoire.
    create_tar(source_dir, archive_path): Crée une archive TAR.
    unarchive_tar(archive_path, extract_dir): Extrait une archive TAR.

Gestion des destinataires

    add_new_recipient(remote_keys_directory): Ajoute un nouveau destinataire et génère une clé AES.
    erase_recipient(remote_keys_directory): Supprime un destinataire et ses clés associées.
    manage_recipients(): Gère les destinataires (ajout, suppression).

Contribuer

    Fork ce dépôt.
    Créez une branche pour votre fonctionnalité (git checkout -b feature/nouvelle-fonctionnalité).
    Commitez vos changements (git commit -am 'Ajout d'une nouvelle fonctionnalité').
    Poussez votre branche (git push origin feature/nouvelle-fonctionnalité).
    Ouvrez une Pull Request.

### Licence

### Ce projet est sous licence MIT. Veuillez consulter le fichier LICENSE pour plus de détails.

Pour toute question ou suggestion, n'hésitez pas à ouvrir une issue sur le dépôt. Merci d'utiliser Krypt !
