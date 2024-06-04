import os
import configparser
import shutil
import tarfile
import random
import string

from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

## RSA Crypting
def generate_rsa_key_pair():
    # Générer une clé RSA avec une taille de 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Extraire la clé publique correspondante
    public_key = private_key.public_key()
    
    # Sérialiser les clés dans le format PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_pem, public_key_pem

def save_new_rsa_keys():
    # Récupérer le répertoire de clés d'hôte depuis le fichier de configuration
    config = configparser.ConfigParser()
    config_file_path = os.path.expanduser("~/.krypt/krypt.config")
    config.read(config_file_path)
    host_keys_directory = config['directories']['host_keys_directory']

    private_key_filename = os.path.join(host_keys_directory, "private_key.pem")
    public_key_filename = os.path.join(host_keys_directory, "public_key.pem")

    # Vérifier si des clés existent déjà
    if os.path.exists(private_key_filename) and os.path.exists(public_key_filename):
        regenerate_keys = input("Des clés RSA existent déjà. Voulez-vous les regénérer ? (oui/non): ").lower()
        if regenerate_keys == "oui" or regenerate_keys == "yes":
            # Générer de nouvelles clés RSA
            private_key, public_key = generate_rsa_key_pair()
            # Sauvegarder les nouvelles clés
            save_to_file(private_key, private_key_filename)
            save_to_file(public_key, public_key_filename)
            print("Les clés RSA ont été regénérées avec succès.")
        else:
            print("Opération annulée. Les clés existantes n'ont pas été modifiées.")
    else:
        # Générer les clés RSA
        private_key, public_key = generate_rsa_key_pair()
        # Sauvegarder les clés dans le répertoire host_keys
        save_to_file(private_key, private_key_filename)
        save_to_file(public_key, public_key_filename)
        print("Les clés RSA ont été sauvegardées avec succès.")

## AES Crypting
def generate_rdm(octets):
    key = os.urandom(octets)
    return key

def crypt(content, aes_key):
    # Générer un IV aléatoire
    iv = os.urandom(16)
    
    # Créer un objet Cipher avec AES en mode CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    
    # Créer un encryptor
    encryptor = cipher.encryptor()
    
    # Ajouter un padding au contenu
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(content) + padder.finalize()
    
    # Chiffrer le contenu
    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
    
    # Retourner l'IV encapsulé avec le contenu chiffré
    return iv + encrypted_content

def crypt_file():
    print("Voici les destinataires déjà enregistrés:", load_users())
    recipient_name = input("Quel est le destinataire que vous choisissez: ")
    aes_key_path, rsa_pubkey_path = load_user_config(recipient_name)

    if not os.path.exists(aes_key_path):
        print(f"Aucune clé AES trouvée pour le destinataire '{recipient_name}'.")
        return

    with open(aes_key_path, 'rb') as file:
        aes_key = file.read()

    file_to_encrypt = input("Entrez le chemin du fichier à chiffrer : ")
    with open(file_to_encrypt, 'rb') as file:
        content = file.read()

    encrypted_content = crypt(content, aes_key)

    to_send_directory, received_directory = load_files_config()

    encrypted_file_name = file_to_encrypt + ".enc"
    encrypted_file_path = os.path.join(to_send_directory, "temp")
    
    ensure_directory_exists(encrypted_file_path)
    
    encrypted_file_path_ = os.path.join(encrypted_file_path, encrypted_file_name)

    save_to_file(encrypted_content, encrypted_file_path_)

    encrypted_aes_key = encrypt_content_rsa(aes_key, rsa_pubkey_path)
    encrypted_aes_key_file_name = os.path.join(encrypted_file_path, "aes_key.enc")

    save_to_file(encrypted_aes_key, encrypted_aes_key_file_name)

    archive_name = os.path.join(to_send_directory, generate_archive_filename(recipient_name))

    create_tar(encrypted_file_path, archive_name)

def decrypt(encrypted_content, aes_key):
    # Extraire l'IV du contenu chiffré
    iv = encrypted_content[:16]
    encrypted_content = encrypted_content[16:]
    
    # Créer un objet Cipher avec AES en mode CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    
    # Créer un decryptor
    decryptor = cipher.decryptor()
    
    # Déchiffrer le contenu
    padded_data = decryptor.update(encrypted_content) + decryptor.finalize()
    
    # Retirer le padding du contenu
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()  # Utilisation du padding correct
    content = unpadder.update(padded_data) + unpadder.finalize()
    
    return content

def decrypt_file():
    archive_path_enc = input("Entrez le chemin de l'archive cryptée :")
    to_send_directory, received_directory = load_files_config()
    extract_dir = os.path.join(received_directory, get_archive_id(os.path.basename(archive_path_enc)))
    ensure_directory_exists(extract_dir)
    unarchive_tar(archive_path_enc, extract_dir)
    host_keys_directory, remote_keys_directory = load_config()
    private_key_path = os.path.join(host_keys_directory, "private_key.pem")
    aes_key_enc_path = os.path.join(extract_dir, "aes_key.enc")
    with open(aes_key_enc_path, 'rb') as file:
        aes_key_enc = file.read()
    aes_key = decrypt_content_rsa(aes_key_enc, private_key_path)

    decrypted_filename = get_enc_filename(extract_dir)
    content_enc_path = os.path.join(extract_dir, f"{decrypted_filename}.enc")
    with open(content_enc_path, 'rb') as file:
        content_enc = file.read()
    content_decrypt = decrypt(content_enc, aes_key)

    save_to_file(content_decrypt, os.path.join(extract_dir, decrypted_filename))

## RSA Crypting
def encrypt_content_rsa(content, public_key_path):
    # Charger la clé publique RSA
    with open(public_key_path, "rb") as key_file:
        public_key_data = key_file.read()
    public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())
    encrypted_content = public_key.encrypt(
    content,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    )

    return encrypted_content

def decrypt_content_rsa(encrypted_content, private_key_path):
    # Charger la clé privée RSA
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    
    # Déchiffrer le contenu
    content = private_key.decrypt(
        encrypted_content,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return content

## Files Managing
def initialisation():
    # Chemin du fichier de configuration
    config_file_path = os.path.expanduser("~/.krypt/krypt.config")

    # Vérifier l'existence du fichier de configuration
    if not os.path.exists(config_file_path):
        print("Le fichier de configuration n'existe pas.")
        return False

    # Charger le fichier de configuration
    config = configparser.ConfigParser()
    config.read(config_file_path)

    # Vérifier l'existence et la validité des répertoires spécifiés dans le fichier de configuration
    if 'directories' not in config:
        print("Le fichier de configuration ne contient pas de section 'directories'.")
        return False

    for directory_key, directory_path in config['directories'].items():
        if not os.path.exists(directory_path):
            print(f"Le répertoire '{directory_path}' spécifié dans le fichier de configuration n'existe pas.")
            return False

    print("Le fichier de configuration est valide.")
    return True

def save_to_file(content, filename):
    try:
        with open(filename, 'wb') as file:
            file.write(content)
        print(f"Le contenu a été sauvegardé dans '{filename}' avec succès.")
    except Exception as e:
        print(f"Une erreur s'est produite lors de la sauvegarde dans '{filename}': {e}")

def ensure_directory_exists(directory):
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Le répertoire '{directory}' a été créé avec succès.")
        else:
            print(f"Le répertoire '{directory}' existe déjà.")
    except Exception as e:
        print(f"Une erreur s'est produite lors de la création du répertoire '{directory}': {e}")

def load_config():
    config = configparser.ConfigParser()
    config_file_path = os.path.expanduser("~/.krypt/krypt.config")
    config.read(config_file_path)

    host_keys_directory = config.get("directories", "host_keys_directory")
    remote_keys_directory = config.get("directories", "remote_keys_directory")

    return host_keys_directory, remote_keys_directory

def load_user_config(user):
    config = configparser.ConfigParser()
    config_file_path = os.path.expanduser("~/.krypt/krypt.config")
    config.read(config_file_path)

    aes_key_path = config.get(user, "aes_key_path")
    rsa_pubkey_path = config.get(user, "rsa_pubkey_path")

    return aes_key_path, rsa_pubkey_path

def load_files_config():
    config = configparser.ConfigParser()
    config_file_path = os.path.expanduser("~/.krypt/krypt.config")
    config.read(config_file_path)

    to_send_directory = config.get("directories", "to_send_directory")
    received_directory = config.get("directories", "received_directory")

    return to_send_directory, received_directory

def load_users():
    config = configparser.ConfigParser()
    config_file_path = os.path.expanduser("~/.krypt/krypt.config")
    config.read(config_file_path)
    
    # Exclure la section 'directories'
    users = [section for section in config.sections() if section != 'directories']
    
    return users

def create_config_file():
    # Définition du chemin du fichier de configuration
    config_file_path = os.path.expanduser("~/.krypt/krypt.config")

    # Vérifier si un fichier de configuration existe déjà
    if os.path.exists(config_file_path):
        restore_default_config = input("Un fichier de configuration existe déjà. Voulez-vous rétablir la configuration par défaut ? (oui/non): ").lower()
        if restore_default_config == "oui" or restore_default_config == "yes":
            # Supprimer le fichier de configuration existant
            os.remove(config_file_path)
            print("Le fichier de configuration existant a été supprimé.")
        else:
            print("Opération annulée. Le fichier de configuration existant n'a pas été modifié.")
            return

    # Définition des répertoires de travail
    base_directory = os.path.expanduser("~/.krypt")
    host_keys_directory = os.path.join(base_directory, "keys/host_keys")
    remote_keys_directory = os.path.join(base_directory, "keys/remote_keys")
    to_send_directory = os.path.join(base_directory, "to_send")
    received_directory = os.path.join(base_directory, "received")

    # Assurer l'existence des répertoires
    ensure_directory_exists(host_keys_directory)
    ensure_directory_exists(remote_keys_directory)
    ensure_directory_exists(to_send_directory)
    ensure_directory_exists(received_directory)

    # Créer le fichier de configuration
    config = configparser.ConfigParser()
    config['directories'] = {
        'host_keys_directory': host_keys_directory,
        'remote_keys_directory': remote_keys_directory,
        'to_send_directory': to_send_directory,
        'received_directory': received_directory
    }

    # Enregistrer le fichier de configuration
    with open(config_file_path, 'w') as configfile:
        config.write(configfile)
    print(f"Le fichier de configuration a été créé avec succès à '{config_file_path}'.")

def update_config(recipient_name, aes_key_filename, rsa_pubkey_filename):
    config = configparser.ConfigParser()
    config_file_path = os.path.expanduser("~/.krypt/krypt.config")
    config.read(config_file_path)

    # Ajouter ou mettre à jour les informations du destinataire dans le fichier de configuration
    if not config.has_section(recipient_name):
        config.add_section(recipient_name)
    config.set(recipient_name, 'aes_key_path', aes_key_filename)
    config.set(recipient_name, 'rsa_pubkey_path', rsa_pubkey_filename)

    # Enregistrer les modifications dans le fichier de configuration
    with open(config_file_path, 'w') as configfile:
        config.write(configfile)

    print(f"Les informations de {recipient_name} ont été mises à jour dans le fichier de configuration.")

def copy_file(source_file, destination_directory):
    try:
        # Copier le fichier vers le répertoire de destination
        shutil.copy(source_file, destination_directory)
        print(f"Le fichier '{source_file}' a été copié avec succès vers '{destination_directory}'.")
    except Exception as e:
        print(f"Une erreur s'est produite lors de la copie du fichier : {e}")

def create_tar(source_dir, archive_path):
    with tarfile.open(archive_path, "w") as tar:
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                file_path = os.path.join(root, file)
                tar.add(file_path, arcname=os.path.relpath(file_path, source_dir))
                os.remove(file_path)

def unarchive_tar(archive_path, extract_dir):
    with tarfile.open(archive_path, "r") as tar:
        tar.extractall(path=extract_dir)

def get_archive_id(archive_name):
    # Diviser le nom de l'archive en utilisant les underscores comme séparateurs
    parts = archive_name.split('_')
    
    # L'ID de l'archive se trouve entre le premier et le dernier underscore
    if len(parts) >= 3:
        archive_id = parts[1]
        return archive_id
    else:
        return None

# Function to generate an encrypted filename
def generate_archive_filename(username):
    random.seed(datetime.now())
    identifier = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    encrypted_filename = f"{username}_{identifier}_krypt.tar"
    return encrypted_filename

def get_enc_filename(directory):
    for filename in os.listdir(directory):
        if filename != "aes_key.enc" and filename.endswith(".enc"):
            # Supprimer le suffixe ".enc"
            base_filename = os.path.splitext(filename)[0]
            return base_filename
    return None  # Retourner None si aucun fichier correspondant n'est trouvé

## Recipient Managing
def add_new_recipient(remote_keys_directory):
    # Demander le nom du destinataire et le chemin de sa clé publique RSA
    recipient_name = input("Entrez le nom du destinataire : ")
    rsa_public_key_path = input("Entrez le chemin de la clé publique RSA du destinataire : ")

    recipient_keys_directory = os.path.join(remote_keys_directory, recipient_name)
    ensure_directory_exists(recipient_keys_directory)

    # Générer une nouvelle clé AES 256 bits
    aes_key = generate_rdm(32)

    # Sauvegarder la clé AES dans un fichier dans le répertoire du destinataire
    aes_key_filename = os.path.join(recipient_keys_directory, f"{recipient_name}_aes_key.bin")
    with open(aes_key_filename, 'wb') as file:
        file.write(aes_key)

    # Copier la clé publique RSA du destinataire dans le répertoire du destinataire
    rsa_pubkey_filename = os.path.join(recipient_keys_directory, f"{recipient_name}_rsa_key.pub")
    copy_file(rsa_public_key_path, rsa_pubkey_filename)

    # Mettre à jour le fichier de configuration
    update_config(recipient_name, aes_key_filename, rsa_pubkey_filename)

    print(f"La clé AES de {recipient_name} a été sauvegardée dans '{aes_key_filename}'.")
    print(f"La clé publique RSA de {recipient_name} a été sauvegardée dans '{rsa_pubkey_filename}'.")

def erase_recipient(remote_keys_directory):
    # Demander le nom du destinataire à supprimer
    recipient_name = input("Entrez le nom du destinataire à supprimer : ")

    recipient_keys_directory = os.path.join(remote_keys_directory, recipient_name)

    # Vérifier si le répertoire du destinataire existe
    if not os.path.exists(recipient_keys_directory):
        print(f"Le répertoire pour le destinataire '{recipient_name}' n'existe pas.")
        return

    # Demander confirmation avant de supprimer
    confirmation = input(f"Êtes-vous sûr de vouloir supprimer le destinataire '{recipient_name}' et toutes ses clés ? (oui/non): ").lower()
    if confirmation not in ["oui", "yes"]:
        print("Opération annulée.")
        return

    # Supprimer le répertoire du destinataire
    shutil.rmtree(recipient_keys_directory)
    print(f"Le répertoire pour le destinataire '{recipient_name}' a été supprimé.")

    # Mettre à jour le fichier de configuration
    config = configparser.ConfigParser()
    config_file_path = os.path.expanduser("~/.krypt/krypt.config")
    config.read(config_file_path)

    if config.has_section(recipient_name):
        config.remove_section(recipient_name)

        with open(config_file_path, 'w') as configfile:
            config.write(configfile)

        print(f"Les informations de {recipient_name} ont été supprimées du fichier de configuration.")
    else:
        print(f"Le destinataire '{recipient_name}' n'existait pas dans le fichier de configuration.")

def manage_recipients():
    host_keys_directory, remote_keys_directory = load_config()
    print("\nGestion des destinataires:")
    print("Voici les destinataires déjà enregistrés:", load_users())
    print("1. Ajouter/Renouveler un destinataire")
    print("2. Supprimer un destinataire")
    choix1 = input("Entrez votre choix: ")
    if choix1 == '1':
        add_new_recipient(remote_keys_directory)
    elif choix1 == '2':
        erase_recipient(remote_keys_directory)
    else :
        print("Choix invalide")

def main():
    if not initialisation():
        print("Initialisation en cours")
        create_config_file()
        save_new_rsa_keys()

    while True:
        print("\nMenu Principal:")
        print("1. Gérer les destinataires")
        print("2. Gérer les clés locales")
        print("3. Encrypter un fichier")
        print("4. Décrypter un fichier")
        print("5. Quitter")

        choix = input("Entrez votre choix: ")

        if choix == '1':
            manage_recipients()
        elif choix == '2':
            save_new_rsa_keys()
        elif choix == '3':
            crypt_file()

            pass
        elif choix == '4':
            decrypt_file()
            pass
        elif choix == '5':
            print("Quitter le programme.")
            break
        else:
            print("Choix invalide. Veuillez réessayer.")

if __name__ == "__main__":
    main()