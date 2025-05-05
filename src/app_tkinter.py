import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from password_checker import PasswordChecker
from password_generator import PasswordGenerator
import json
from pathlib import Path

class PasswordCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vérificateur de robustesse de mot de passe")
        self.root.geometry("600x500")
        
        self.checker = PasswordChecker()
        self.generator = PasswordGenerator()
        
        self.setup_ui()
        self.setup_menu()
    
    def setup_menu(self):
        menubar = tk.Menu(self.root)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Enregistrer les résultats", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.root.quit)
        menubar.add_cascade(label="Fichier", menu=file_menu)
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Générer un mot de passe", command=self.show_generator)
        tools_menu.add_command(label="Tester un fichier", command=self.test_file)
        menubar.add_cascade(label="Outils", menu=tools_menu)
        
        self.root.config(menu=menubar)
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        input_frame = ttk.LabelFrame(main_frame, text="Vérification de mot de passe", padding=10)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="Mot de passe:").grid(row=0, column=0, sticky=tk.W)
        self.password_entry = ttk.Entry(input_frame, show="•", width=40)
        self.password_entry.grid(row=0, column=1, padx=5)
        
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(input_frame, text="Afficher", variable=self.show_password_var, command=self.toggle_password_visibility).grid(row=0, column=2)
        
        ttk.Button(input_frame, text="Vérifier", command=self.check_password).grid(row=1, column=1, pady=5)
        
        result_frame = ttk.LabelFrame(main_frame, text="Résultats", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.strength_var = tk.StringVar(value="Non testé")
        ttk.Label(result_frame, textvariable=self.strength_var, font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        self.progress = ttk.Progressbar(result_frame, orient='horizontal', length=550, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)

        # Ajout du style pour progress bar
        self.style = ttk.Style(self.root)
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")
        
        self.feedback_text = tk.Text(result_frame, height=8, wrap=tk.WORD, font=('Arial', 10))
        self.feedback_text.pack(fill=tk.BOTH, expand=True)
        self.feedback_text.config(state=tk.DISABLED)
        
        crypto_frame = ttk.LabelFrame(main_frame, text="Fonctions cryptographiques", padding=10)
        crypto_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(crypto_frame, text="Hacher le mot de passe", command=self.hash_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(crypto_frame, text="Chiffrer un texte", command=self.encrypt_data).pack(side=tk.LEFT, padx=5)
    
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def check_password(self):
        password = self.password_entry.get()
        
        if not password:
            messagebox.showwarning("Attention", "Veuillez entrer un mot de passe")
            return
        
        strength, feedback, score = self.checker.evaluate(password)
        
        self.strength_var.set(f"Robustesse: {strength}")
        
        colors = {
            "Très robuste": "#28a745",
            "Robuste": "#007bff",
            "Moyen": "#ffc107",
            "Faible": "#fd7e14",
            "Très faible": "#dc3545"
        }
        
        color = colors.get(strength, "gray")
        self.progress['value'] = score * 100
        
        # Appliquer le style dynamique
        self.style.configure(
            'color.Horizontal.TProgressbar',
            troughcolor='#f0f0f0',
            bordercolor='lightgray',
            background=color,
            lightcolor=color,
            darkcolor=color
        )
        self.progress.config(style='color.Horizontal.TProgressbar')
        
        self.feedback_text.config(state=tk.NORMAL)
        self.feedback_text.delete(1.0, tk.END)
        
        if feedback:
            self.feedback_text.insert(tk.END, "Problèmes détectés:\n\n")
            for item in feedback:
                self.feedback_text.insert(tk.END, f"• {item}\n")
        else:
            self.feedback_text.insert(tk.END, "Aucun problème détecté. Votre mot de passe est sécurisé!\n\n")
            self.feedback_text.insert(tk.END, "Conseil : Changez régulièrement vos mots de passe et n'utilisez pas le même mot de passe pour plusieurs comptes.")
        
        self.feedback_text.config(state=tk.DISABLED)
    
    def show_generator(self):
        gen_window = tk.Toplevel(self.root)
        gen_window.title("Générateur de mots de passe")
        gen_window.geometry("400x300")
        
        ttk.Label(gen_window, text="Longueur:").pack(pady=5)
        length_var = tk.IntVar(value=16)
        ttk.Spinbox(gen_window, from_=12, to=64, textvariable=length_var).pack(pady=5)
        
        password_var = tk.StringVar()
        ttk.Entry(gen_window, textvariable=password_var, state='readonly', width=40).pack(pady=10)
        
        def generate():
            try:
                password = self.generator.generate_secure_password(length_var.get())
                password_var.set(password)
            except ValueError as e:
                messagebox.showerror("Erreur", str(e))
        
        ttk.Button(gen_window, text="Générer", command=generate).pack(pady=5)
        ttk.Button(gen_window, text="Copier", command=lambda: self.root.clipboard_append(password_var.get())).pack(pady=5)
    
    def hash_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Attention", "Veuillez entrer un mot de passe")
            return
        
        hashed = self.checker.hash_password(password)
        messagebox.showinfo("Résultat du hachage", f"Mot de passe haché (en hexadécimal):\n\n{hashed.hex()}")
    
    def encrypt_data(self):
        data = simpledialog.askstring("Chiffrement", "Entrez le texte à chiffrer:")
        if not data:
            return
        
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Attention", "Veuillez entrer un mot de passe pour le chiffrement")
            return
        
        try:
            encrypted = self.checker.encrypt_data(data, password)
            messagebox.showinfo("Résultat du chiffrement", f"Données chiffrées (en hexadécimal):\n\n{encrypted.hex()}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du chiffrement: {str(e)}")
    
    def test_file(self):
        filepath = filedialog.askopenfilename(title="Sélectionner un fichier texte")
        if not filepath:
            return
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            results = []
            for pwd in passwords:
                strength, feedback, _ = self.checker.evaluate(pwd)
                results.append({
                    'password': pwd,
                    'strength': strength,
                    'feedback': feedback
                })
            
            output_file = Path(filepath).with_name(f"results_{Path(filepath).name}")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            
            messagebox.showinfo("Succès", f"Analyse terminée. Résultats enregistrés dans:\n\n{output_file}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'analyse: {str(e)}")
    
    def save_results(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Attention", "Aucun mot de passe à enregistrer")
            return
        
        strength, feedback, score = self.checker.evaluate(password)
        
        filepath = filedialog.asksaveasfilename(
            title="Enregistrer les résultats",
            defaultextension=".json",
            filetypes=[("Fichiers JSON", "*.json"), ("Tous les fichiers", "*.*")]
        )
        
        if not filepath:
            return
        
        data = {
            'password': password,
            'strength': strength,
            'score': score,
            'feedback': feedback,
            'hash': self.checker.hash_password(password).hex()
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            messagebox.showinfo("Succès", "Résultats enregistrés avec succès")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'enregistrement: {str(e)}")

def main():
    root = tk.Tk()
    app = PasswordCheckerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
