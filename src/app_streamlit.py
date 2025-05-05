import streamlit as st
from password_checker import PasswordChecker
from password_generator import PasswordGenerator
import json
from pathlib import Path

def main():
    st.set_page_config(page_title="Password Checker", page_icon="🔒", layout="wide")
    
    st.title("🔒 Password Strength Checker with Cryptography")
    st.write("Un outil complet pour vérifier et générer des mots de passe sécurisés")
    
    # Initialisation
    if 'checker' not in st.session_state:
        st.session_state.checker = PasswordChecker()
        st.session_state.generator = PasswordGenerator()
    
    # Onglets
    tab1, tab2, tab3 = st.tabs(["Vérification", "Génération", "Cryptographie"])
    
    with tab1:
        st.header("Vérification de robustesse")
        password = st.text_input("Entrez un mot de passe:", type="password")
        
        if st.button("Vérifier la robustesse"):
            if not password:
                st.warning("Veuillez entrer un mot de passe")
            else:
                strength, feedback, score = st.session_state.checker.evaluate(password)
                
                # Affichage des résultats
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("Résultats")
                    st.metric("Robustesse", strength)
                    
                    # Barre de progression colorée
                    progress_color = {
                        "Très robuste": "green",
                        "Robuste": "blue",
                        "Moyen": "orange",
                        "Faible": "yellow",
                        "Très faible": "red"
                    }.get(strength, "gray")
                    
                    st.progress(score, text=f"Score: {score*100:.1f}%")
                    
                    # Feedback
                    if feedback:
                        st.warning("Problèmes détectés:")
                        for item in feedback:
                            st.write(f"- {item}")
                    else:
                        st.success("Aucun problème détecté. Mot de passe sécurisé!")
                
                with col2:
                    st.subheader("Analyse cryptographique")
                    st.write("Fonction de hachage (scrypt):")
                    hashed = st.session_state.checker.hash_password(password)
                    st.code(hashed.hex())
                    
                    st.download_button(
                        label="Télécharger les résultats",
                        data=json.dumps({
                            'password': password,
                            'strength': strength,
                            'score': score,
                            'feedback': feedback,
                            'hash': hashed.hex()
                        }, indent=2),
                        file_name="password_analysis.json",
                        mime="application/json"
                    )
    
    with tab2:
        st.header("Générateur de mots de passe sécurisés")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Générateur standard")
            length1 = st.slider("Longueur", 12, 32, 16, key="gen1")
            
            if st.button("Générer un mot de passe", key="btn1"):
                password = st.session_state.generator.generate_secure_password(length1)
                st.code(password)
                st.download_button(
                    label="Télécharger le mot de passe",
                    data=password,
                    file_name="generated_password.txt"
                )
        
        with col2:
            st.subheader("Générateur cryptographique")
            length2 = st.slider("Longueur", 16, 64, 32, key="gen2")
            
            if st.button("Générer un mot de passe", key="btn2"):
                password = st.session_state.generator.generate_crypto_password(length2)
                st.code(password)
                st.download_button(
                    label="Télécharger le mot de passe",
                    data=password,
                    file_name="crypto_password.txt"
                )
    
    with tab3:
        st.header("Fonctions cryptographiques")
        
        st.subheader("Chiffrement AES")
        crypto_text = st.text_area("Texte à chiffrer:")
        crypto_pwd = st.text_input("Mot de passe pour le chiffrement:", type="password")
        
        if st.button("Chiffrer"):
            if not crypto_text or not crypto_pwd:
                st.error("Veuillez entrer un texte et un mot de passe")
            else:
                try:
                    encrypted = st.session_state.checker.encrypt_data(crypto_text, crypto_pwd)
                    st.success("Texte chiffré avec succès")
                    st.code(encrypted.hex())
                except Exception as e:
                    st.error(f"Erreur: {str(e)}")
        
        st.subheader("Déchiffrement AES")
        encrypted_hex = st.text_area("Texte chiffré (hexadécimal):")
        decrypt_pwd = st.text_input("Mot de passe pour le déchiffrement:", type="password")
        
        if st.button("Déchiffrer"):
            if not encrypted_hex or not decrypt_pwd:
                st.error("Veuillez entrer des données chiffrées et un mot de passe")
            else:
                try:
                    encrypted_bytes = bytes.fromhex(encrypted_hex)
                    decrypted = st.session_state.checker.decrypt_data(encrypted_bytes, decrypt_pwd)
                    st.success("Texte déchiffré avec succès")
                    st.code(decrypted)
                except Exception as e:
                    st.error(f"Erreur: {str(e)}")

if __name__ == "__main__":
    main()