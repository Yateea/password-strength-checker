import pytest
from src.password_checker import PasswordChecker
from src.password_generator import PasswordGenerator

@pytest.fixture
def checker():
    return PasswordChecker()

def test_password_length(checker):
    assert checker.check_length("short") is False
    assert checker.check_length("longenoughpassword") is True

def test_password_lowercase(checker):
    assert checker.check_lowercase("ALLUPPERCASE") is False
    assert checker.check_lowercase("HasLower") is True

def test_password_uppercase(checker):
    assert checker.check_uppercase("alllowercase") is False
    assert checker.check_uppercase("hasUpper") is True

def test_password_digit(checker):
    assert checker.check_digit("noDigitsHere") is False
    assert checker.check_digit("has1Digit") is True

def test_password_special_char(checker):
    assert checker.check_special_char("noSpecialChars") is False
    assert checker.check_special_char("has@Special") is True

def test_password_evaluation(checker):
    # Test avec un mot de passe très robuste
    result = checker.evaluate("Str0ngP@ssw0rd!")
    assert result[0] == "Très robuste"
    assert len(result[1]) == 0
    
    # Test avec un mot de passe faible
    result = checker.evaluate("weak")
    assert result[0] == "Très faible"
    assert len(result[1]) > 0

def test_password_generator():
    generator = PasswordGenerator()
    password = generator.generate_secure_password()
    
    assert len(password) >= 12
    assert any(c.islower() for c in password)
    assert any(c.isupper() for c in password)
    assert any(c.isdigit() for c in password)
    assert any(not c.isalnum() for c in password)

def test_crypto_password_generator():
    generator = PasswordGenerator()
    password = generator.generate_crypto_password()
    
    assert len(password) >= 32
    # On ne peut pas vraiment tester le caractère aléatoire cryptographique
    # mais on peut vérifier la longueur et la diversité des caractères
    assert len(set(password)) > len(password) / 2