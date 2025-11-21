import string
import hashlib
import os
import hmac
import json

# ----- Hachage sécurisé SHA-256 -----

def hash_password_sha256(password, pepper, iterations=100_000):
    salt = os.urandom(16)
    pwd_peppered = password.encode() + pepper

    hash_value = pwd_peppered
    for _ in range(iterations):
        hash_value = hashlib.sha256(salt + hash_value).digest()

    return salt, hash_value


def verify_password_sha256(password, salt, stored_hash, pepper, iterations=100_000):
    pwd_peppered = password.encode() + pepper

    hash_value = pwd_peppered
    for _ in range(iterations):
        hash_value = hashlib.sha256(salt + hash_value).digest()

    return hmac.compare_digest(hash_value, stored_hash)


# ----- Vérification de complexité -----

def verifier_mot_de_passe(mdp):
    if len(mdp) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères."
    if not any(c.isupper() for c in mdp):
        return False, "Le mot de passe doit contenir au moins une majuscule."
    if not any(c.islower() for c in mdp):
        return False, "Le mot de passe doit contenir au moins une minuscule."
    if not any(c.isdigit() for c in mdp):
        return False, "Le mot de passe doit contenir au moins un chiffre."
    if not any(c in string.punctuation for c in mdp):
        return False, "Le mot de passe doit contenir au moins un caractère spécial."
    
    return True, "Mot de passe valide."


# ----- Vérification si le mot de passe existe déjà -----

def mot_de_passe_deja_utilise(mdp, pepper, fichier="users.json"):
    if not os.path.exists(fichier):
        return False  # aucun utilisateur enregistré

    with open(fichier, "r") as f:
        data = json.load(f)

    for user, info in data.items():
        salt = bytes.fromhex(info["salt"])
        stored_hash = bytes.fromhex(info["hash"])

        # On vérifie le mot de passe contre le hash stocké
        if verify_password_sha256(mdp, salt, stored_hash, pepper):
            return True  # le mot de passe appartient déjà à quelqu'un

    return False


# ----- Fonction de sauvegarde -----

def sauvegarder_mot_de_passe(username, salt, password_hash, fichier="users.json"):
    if os.path.exists(fichier):
        with open(fichier, "r") as f:
            data = json.load(f)
    else:
        data = {}

    data[username] = {
        "salt": salt.hex(),
        "hash": password_hash.hex()
    }

    with open(fichier, "w") as f:
        json.dump(data, f, indent=4)

    print("\n💾 Mot de passe enregistré dans", fichier)


# ----- Programme principal -----

pepper = b"SECRET_PEPPER"  # secret : à protéger !

username = input("Nom d'utilisateur : ")

while True:
    mdp = input("Veuillez entrer votre mot de passe : ")
    valide, message = verifier_mot_de_passe(mdp)

    if not valide:
        print("❌", message)
        print("Veuillez réessayer.\n")
        continue

    # Vérifier si déjà utilisé
    if mot_de_passe_deja_utilise(mdp, pepper):
        print("❌ Ce mot de passe est déjà utilisé par un autre utilisateur.")
        print("Veuillez en choisir un différent.\n")
        continue

    # Aucun problème → on continue
    print("✅", message)

    # Hachage
    salt, password_hash = hash_password_sha256(mdp, pepper)

    # Sauvegarde
    sauvegarder_mot_de_passe(username, salt, password_hash)

    print("\nSel :", salt.hex())
    print("Hash :", password_hash.hex())
    break
