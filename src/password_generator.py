import random
import string
from Crypto.Random import get_random_bytes

class PasswordGenerator:
    @staticmethod
    def generate_secure_password(length=16):
        """Génère un mot de passe sécurisé cryptographiquement"""
        if length < 12:
            raise ValueError("La longueur minimale recommandée est 12 caractères")
        
        # Caractères possibles
        lower = string.ascii_lowercase
        upper = string.ascii_uppercase
        digits = string.digits
        special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        # Garantir au moins un caractère de chaque type
        password = [
            random.choice(lower),
            random.choice(upper),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Remplir le reste avec un mélange aléatoire
        remaining = length - 4
        all_chars = lower + upper + digits + special
        password.extend(random.choices(all_chars, k=remaining))
        
        # Mélanger pour plus de sécurité
        random.shuffle(password)
        
        return ''.join(password)
    
    @staticmethod
    def generate_crypto_password(length=32):
        """Génère un mot de passe très sécurisé avec cryptographie"""
        chars = string.ascii_letters + string.digits + '!@#$%^&*'
        rand_bytes = get_random_bytes(length)
        password = []
        
        for byte in rand_bytes:
            index = byte % len(chars)
            password.append(chars[index])
        
        return ''.join(password)