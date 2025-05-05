import re
import hashlib
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

class PasswordChecker:
    def __init__(self, min_length=12):
        self.min_length = min_length
        self.common_passwords = self._load_common_passwords()
        
        self.checks = [
            (self.check_length, f"Le mot de passe doit contenir au moins {min_length} caractères"),
            (self.check_lowercase, "Le mot de passe doit contenir au moins une minuscule"),
            (self.check_uppercase, "Le mot de passe doit contenir au moins une majuscule"),
            (self.check_digit, "Le mot de passe doit contenir au moins un chiffre"),
            (self.check_special_char, "Le mot de passe doit contenir au moins un caractère spécial"),
            (self.check_common, "Le mot de passe est trop commun et se trouve dans les listes de mots de passe faibles"),
            (self.check_sequences, "Le mot de passe contient des séquences simples (comme 1234 ou azerty)"),
            (self.check_repeats, "Le mot de passe contient des répétitions de caractères (comme aaaa ou 1111)"),
        ]
    
    def _load_common_passwords(self):
        try:
            with open(Path(__file__).parent / 'data' / 'common_passwords.txt', 'r', encoding='utf-8') as f:
                return set(line.strip() for line in f)
        except FileNotFoundError:
            return set()
    
    def check_length(self, password):
        return len(password) >= self.min_length
    
    def check_lowercase(self, password):
        return any(c.islower() for c in password)
    
    def check_uppercase(self, password):
        return any(c.isupper() for c in password)
    
    def check_digit(self, password):
        return any(c.isdigit() for c in password)
    
    def check_special_char(self, password):
        special_chars = r"~!@#$%^&*()_+{}\":;'[]"
        return any(c in special_chars for c in password)
    
    def check_common(self, password):
        return password.lower() not in self.common_passwords
    
    def check_sequences(self, password):
        sequences = [
            '1234', '4321', '123456', '654321',
            'qwerty', 'azerty', 'password', 'admin'
        ]
        lower_pwd = password.lower()
        return not any(seq in lower_pwd for seq in sequences)
    
    def check_repeats(self, password):
        return not re.search(r'(.)\1{3,}', password)
    
    def evaluate(self, password):
        strength = 0
        feedback = []
        
        for check_func, msg in self.checks:
            if check_func(password):
                strength += 1
            else:
                feedback.append(msg)
        
        total_checks = len(self.checks)
        score = strength / total_checks
        
        if score == 1:
            return ("Très robuste", [], score)
        elif score >= 0.8:
            return ("Robuste", feedback, score)
        elif score >= 0.6:
            return ("Moyen", feedback, score)
        elif score >= 0.4:
            return ("Faible", feedback, score)
        else:
            return ("Très faible", feedback, score)
    
    def hash_password(self, password, salt=None):
        """Hash le mot de passe avec scrypt (fonction de dérivation de clé)"""
        if salt is None:
            salt = get_random_bytes(16)
        key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)
        return salt + key
    
    def encrypt_data(self, data, password):
        """Chiffre des données avec AES en utilisant le mot de passe"""
        salt = get_random_bytes(16)
        key = self.hash_password(password, salt)
        cipher = AES.new(key[16:], AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return salt + cipher.nonce + tag + ciphertext
    
    def decrypt_data(self, encrypted_data, password):
        """Déchiffre des données avec AES en utilisant le mot de passe"""
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        tag = encrypted_data[32:48]
        ciphertext = encrypted_data[48:]
        key = self.hash_password(password, salt)
        cipher = AES.new(key[16:], AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()