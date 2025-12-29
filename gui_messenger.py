#!/usr/bin/env python3
"""
gui_messenger.py - Interface graphique pour le système de messagerie sécurisée
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import json
import threading
import time
from datetime import datetime

# Import des modules du projet
from utils import (
    load_public_key, load_private_key,
    rsa_encrypt_aes_key, rsa_decrypt_aes_key,
    rsa_sign, rsa_verify, _b64, _unb64, sha256_hex
)
from crypto import gen_aes_key, aes_cbc_encrypt, aes_cbc_decrypt, compute_hmac, verify_hmac

class SecureMessengerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Messagerie Sécurisée - RSA + AES-CBC")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2b2b2b')
        
        # Configuration du style
        self.setup_styles()
        
        # Variables
        self.current_user = tk.StringVar(value="alice")
        self.recipient = tk.StringVar(value="bob")
        self.passphrase = tk.StringVar()
        self.sign_message = tk.BooleanVar(value=True)
        
        # Création de l'interface
        self.create_widgets()
        
        # État du système
        self.status_text = "✅ Système prêt"
        self.update_status()
    
    def setup_styles(self):
        """Configuration des styles"""
        style = ttk.Style()
        
        # Couleurs
        self.colors = {
            'bg': '#2b2b2b',
            'fg': '#ffffff',
            'accent': '#4CAF50',
            'secondary': '#2196F3',
            'warning': '#FF9800',
            'error': '#F44336',
            'text_bg': '#1e1e1e',
            'entry_bg': '#3c3c3c'
        }
        
        # Configuration du thème
        style.theme_use('clam')
        
        # Configuration des couleurs de base
        style.configure('TLabel', 
                       background=self.colors['bg'], 
                       foreground=self.colors['fg'])
        style.configure('TFrame', background=self.colors['bg'])
        style.configure('TLabelframe', 
                       background=self.colors['bg'], 
                       foreground=self.colors['fg'])
        
        # Bouton spécial
        style.configure('Accent.TButton',
                       background=self.colors['accent'],
                       foreground='white',
                       font=('Arial', 10, 'bold'))
    
    def create_widgets(self):
        """Création des éléments de l'interface"""
        
        # Cadre du titre
        title_frame = ttk.Frame(self.root)
        title_frame.pack(fill=tk.X, padx=20, pady=10)
        
        title_label = tk.Label(title_frame,
                              text="🔐 Messagerie Sécurisée",
                              font=('Arial', 24, 'bold'),
                              bg=self.colors['bg'],
                              fg=self.colors['accent'])
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame,
                                 text="Système de messagerie chiffrée avec RSA et AES-CBC",
                                 font=('Arial', 12),
                                 bg=self.colors['bg'],
                                 fg=self.colors['fg'])
        subtitle_label.pack()
        
        # Création des onglets
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Différents onglets
        self.create_send_tab()
        self.create_receive_tab()
        self.create_keys_tab()
        self.create_info_tab()
        
        # Barre d'état
        self.status_bar = tk.Label(self.root,
                                  text="",
                                  bd=1,
                                  relief=tk.SUNKEN,
                                  anchor=tk.W,
                                  bg=self.colors['text_bg'],
                                  fg=self.colors['fg'])
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_send_tab(self):
        """Création de l'onglet Envoyer"""
        send_frame = ttk.Frame(self.notebook)
        self.notebook.add(send_frame, text="📤 Envoyer un message")
        
        # Cadre utilisateur
        user_frame = ttk.LabelFrame(send_frame, text="👤 Informations utilisateur", padding=15)
        user_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Expéditeur
        ttk.Label(user_frame, text="Expéditeur:").grid(row=0, column=0, sticky=tk.W, pady=5)
        sender_entry = ttk.Entry(user_frame, textvariable=self.current_user, width=20)
        sender_entry.grid(row=0, column=1, padx=10, pady=5)
        
        # Destinataire
        ttk.Label(user_frame, text="Destinataire:").grid(row=0, column=2, sticky=tk.W, pady=5)
        recipient_entry = ttk.Entry(user_frame, textvariable=self.recipient, width=20)
        recipient_entry.grid(row=0, column=3, padx=10, pady=5)
        
        # Mot de passe
        ttk.Label(user_frame, text="Mot de passe clé:").grid(row=1, column=0, sticky=tk.W, pady=5)
        pass_entry = ttk.Entry(user_frame, textvariable=self.passphrase, width=20, show="•")
        pass_entry.grid(row=1, column=1, padx=10, pady=5)
        
        # Cadre message
        msg_frame = ttk.LabelFrame(send_frame, text="📝 Message", padding=15)
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.message_text = scrolledtext.ScrolledText(msg_frame,
                                                     height=10,
                                                     font=('Arial', 11),
                                                     bg=self.colors['text_bg'],
                                                     fg=self.colors['fg'],
                                                     insertbackground='white')
        self.message_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Bouton pour charger un fichier
        load_btn = ttk.Button(msg_frame,
                             text="📁 Charger depuis fichier",
                             command=self.load_message_file)
        load_btn.pack(pady=5)
        
        # Cadre options
        options_frame = ttk.Frame(send_frame)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Checkbutton(options_frame,
                       text="✍️ Signer le message (RSA-PSS)",
                       variable=self.sign_message).pack(side=tk.LEFT, padx=10)
        
        # Bouton Envoyer
        send_btn = ttk.Button(send_frame,
                             text="🔐 Chiffrer et Envoyer",
                             command=self.send_message_thread,
                             style='Accent.TButton')
        send_btn.pack(pady=15)
        
        # Cadre résultats
        result_frame = ttk.LabelFrame(send_frame, text="📊 Résultats", padding=15)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.result_text = scrolledtext.ScrolledText(result_frame,
                                                    height=8,
                                                    font=('Courier New', 9),
                                                    bg=self.colors['text_bg'],
                                                    fg=self.colors['fg'])
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # Boutons de sortie
        btn_frame = ttk.Frame(result_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame,
                  text="📋 Copier résultat",
                  command=self.copy_result).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame,
                  text="💾 Sauvegarder",
                  command=self.save_result).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame,
                  text="🧹 Effacer",
                  command=self.clear_result).pack(side=tk.LEFT, padx=5)
    
    def create_receive_tab(self):
        """Création de l'onglet Recevoir"""
        receive_frame = ttk.Frame(self.notebook)
        self.notebook.add(receive_frame, text="📥 Recevoir un message")
        
        # Cadre utilisateur
        user_frame = ttk.LabelFrame(receive_frame, text="👤 Destinataire", padding=15)
        user_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(user_frame, text="Nom d'utilisateur:").pack(side=tk.LEFT)
        self.receive_user = ttk.Entry(user_frame, width=20)
        self.receive_user.pack(side=tk.LEFT, padx=10)
        self.receive_user.insert(0, "bob")
        
        ttk.Label(user_frame, text="Mot de passe:").pack(side=tk.LEFT)
        self.receive_pass = ttk.Entry(user_frame, width=20, show="•")
        self.receive_pass.pack(side=tk.LEFT, padx=10)
        
        # Cadre fichier
        file_frame = ttk.LabelFrame(receive_frame, text="📁 Fichier message chiffré", padding=15)
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.file_path = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path, width=50)
        file_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        ttk.Button(file_frame,
                  text="🔍 Parcourir",
                  command=self.browse_encrypted_file).pack(side=tk.RIGHT)
        
        # Options
        options_frame = ttk.Frame(receive_frame)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.verify_sig = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame,
                       text="✅ Vérifier la signature",
                       variable=self.verify_sig).pack(side=tk.LEFT, padx=10)
        
        # Bouton Déchiffrer
        decrypt_btn = ttk.Button(receive_frame,
                                text="🔓 Déchiffrer et Vérifier",
                                command=self.receive_message_thread,
                                style='Accent.TButton')
        decrypt_btn.pack(pady=10)
        
        # Cadre résultats
        result_frame = ttk.LabelFrame(receive_frame, text="📊 Résultats du déchiffrement", padding=15)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Création des onglets pour les résultats
        result_notebook = ttk.Notebook(result_frame)
        result_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Onglet Message
        msg_tab = ttk.Frame(result_notebook)
        result_notebook.add(msg_tab, text="📝 Message")
        
        self.decrypted_text = scrolledtext.ScrolledText(msg_tab,
                                                       font=('Arial', 12),
                                                       bg=self.colors['text_bg'],
                                                       fg=self.colors['fg'])
        self.decrypted_text.pack(fill=tk.BOTH, expand=True)
        
        # Onglet Détails
        details_tab = ttk.Frame(result_notebook)
        result_notebook.add(details_tab, text="🔧 Détails techniques")
        
        self.details_text = scrolledtext.ScrolledText(details_tab,
                                                     font=('Courier New', 10),
                                                     bg=self.colors['text_bg'],
                                                     fg=self.colors['fg'])
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Onglet Infos fichier
        info_tab = ttk.Frame(result_notebook)
        result_notebook.add(info_tab, text="📄 Informations fichier")
        
        self.file_info_text = scrolledtext.ScrolledText(info_tab,
                                                       font=('Courier New', 9),
                                                       bg=self.colors['text_bg'],
                                                       fg=self.colors['fg'])
        self.file_info_text.pack(fill=tk.BOTH, expand=True)
    
    def create_keys_tab(self):
        """Création de l'onglet Clés"""
        keys_frame = ttk.Frame(self.notebook)
        self.notebook.add(keys_frame, text="🔑 Gestion des clés")
        
        # Cadre informations
        info_frame = ttk.LabelFrame(keys_frame, text="ℹ️ Informations clés", padding=15)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        info_text = """
🔐 Informations sur les clés RSA:

• Taille de clé: 3072 bits (recommandé)
• Format: PEM
• Clés privées: keys/nom_utilisateur_private.pem
• Clés publiques: keys/nom_utilisateur_public.pem

📁 Emplacement des clés:
• keys/alice_private.pem
• keys/alice_public.pem
• keys/bob_private.pem
• keys/bob_public.pem

⚠️ Conseils de sécurité:
• Gardez les clés privées en sécurité
• Partagez les clés publiques avec vos contacts
• Utilisez un mot de passe fort pour protéger les clés
• Faites des sauvegardes des clés importantes
"""
        
        info_widget = scrolledtext.ScrolledText(info_frame,
                                               height=15,
                                               font=('Arial', 11),
                                               bg=self.colors['text_bg'],
                                               fg=self.colors['fg'])
        info_widget.insert(1.0, info_text)
        info_widget.config(state=tk.DISABLED)
        info_widget.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Cadre gestion clés
        manage_frame = ttk.LabelFrame(keys_frame, text="🛠️ Gestion des clés", padding=15)
        manage_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Boutons de gestion
        btn_frame = ttk.Frame(manage_frame)
        btn_frame.pack()
        
        ttk.Button(btn_frame,
                  text="🔄 Générer nouvelles clés",
                  command=self.generate_keys_dialog).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(btn_frame,
                  text="📊 Afficher infos clés",
                  command=self.show_key_info).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(btn_frame,
                  text="🧹 Nettoyer anciennes clés",
                  command=self.clean_old_keys).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Cadre état clés
        status_frame = ttk.LabelFrame(keys_frame, text="📈 État des clés", padding=15)
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.key_status_text = scrolledtext.ScrolledText(status_frame,
                                                        height=6,
                                                        font=('Courier New', 9),
                                                        bg=self.colors['text_bg'],
                                                        fg=self.colors['fg'])
        self.key_status_text.pack(fill=tk.BOTH)
        self.update_key_status()
    
    def create_info_tab(self):
        """Création de l'onglet Informations"""
        info_frame = ttk.Frame(self.notebook)
        self.notebook.add(info_frame, text="ℹ️ Informations projet")
        
        info_text = """
🎓 Projet: Système de messagerie sécurisée
📚 Cours: Cryptographie
🎯 Objectif: Système de chiffrement hybride (RSA + AES-CBC)

🔐 Algorithmes de chiffrement utilisés:
• RSA-3072: Échange de clés et signatures
• AES-256-CBC: Chiffrement des messages
• SHA-256: Fonction de hachage pour l'intégrité
• HMAC-SHA256: Vérification de l'intégrité des données
• RSA-PSS: Signatures numériques

📊 Exigences remplies:
✓ Génération de clés RSA pour les utilisateurs
✓ Échange sécurisé de clé AES via RSA
✓ Chiffrement symétrique avec AES-CBC
✓ Signature et vérification RSA avec SHA-256
✓ Interface ligne de commande (CLI)
✓ Interface graphique (GUI)

🚀 Mécanisme de fonctionnement:
1. Génération de clés RSA pour chaque utilisateur
2. Chiffrement des messages avec AES-256-CBC
3. Chiffrement de la clé AES avec la clé publique du destinataire
4. Signature du message avec la clé privée de l'expéditeur
5. Envoi du fichier chiffré au destinataire
6. Déchiffrement et vérification par le destinataire

👨‍💻 Comment utiliser:
1. Générer les clés: python keygen.py --user nom_utilisateur
2. Envoyer un message: python sender.py --from expéditeur --to destinataire --message "texte"
3. Recevoir un message: python receiver.py --user destinataire --in fichier_message

📞 Pour de l'aide:
• Consultez le fichier README.md
• Vérifiez les exemples dans example_workflow.sh
• Utilisez l'option --help avec n'importe quelle commande

✅ Ce projet a été développé comme projet final de cours de cryptographie.
"""
        
        info_widget = scrolledtext.ScrolledText(info_frame,
                                               font=('Arial', 11),
                                               bg=self.colors['text_bg'],
                                               fg=self.colors['fg'])
        info_widget.insert(1.0, info_text)
        info_widget.config(state=tk.DISABLED)
        info_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # ============= Fonctions utilitaires =============
    
    def update_status(self, text=None):
        """Mettre à jour la barre d'état"""
        if text:
            self.status_text = text
        self.status_bar.config(text=f"📡 {self.status_text}")
    
    def update_key_status(self):
        """Mettre à jour l'état des clés"""
        self.key_status_text.delete(1.0, tk.END)
        
        if not os.path.exists("keys"):
            self.key_status_text.insert(1.0, "❌ Dossier des clés n'existe pas")
            return
        
        key_files = os.listdir("keys")
        if not key_files:
            self.key_status_text.insert(1.0, "⚠️  Aucune clé. Générer de nouvelles clés.")
            return
        
        self.key_status_text.insert(1.0, "✅ Clés disponibles:\n\n")
        for file in sorted(key_files):
            if file.endswith(".pem"):
                path = os.path.join("keys", file)
                size = os.path.getsize(path)
                self.key_status_text.insert(tk.END, f"📄 {file} ({size:,} octets)\n")
    
    def load_message_file(self):
        """Charger un message depuis un fichier"""
        filename = filedialog.askopenfilename(
            title="Choisir un fichier texte",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous fichiers", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.message_text.delete(1.0, tk.END)
                self.message_text.insert(1.0, content)
                self.update_status(f"📂 Fichier chargé: {os.path.basename(filename)}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec du chargement: {e}")
    
    def browse_encrypted_file(self):
        """Parcourir pour un fichier chiffré"""
        filename = filedialog.askopenfilename(
            title="Choisir un fichier message chiffré",
            filetypes=[("Fichiers JSON", "*.json"), ("Tous fichiers", "*.*")]
        )
        if filename:
            self.file_path.set(filename)
            self.update_status(f"📄 Fichier sélectionné: {os.path.basename(filename)}")
    
    def copy_result(self):
        """Copier les résultats"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.result_text.get(1.0, tk.END))
        self.update_status("📋 Résultats copiés dans le presse-papier")
    
    def save_result(self):
        """Sauvegarder les résultats"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous fichiers", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.result_text.get(1.0, tk.END))
                self.update_status(f"💾 Résultats sauvegardés: {os.path.basename(filename)}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec de sauvegarde: {e}")
    
    def clear_result(self):
        """Effacer les résultats"""
        self.result_text.delete(1.0, tk.END)
        self.update_status("🧹 Résultats effacés")
    
    # ============= Fonctions opérationnelles =============
    
    def send_message_thread(self):
        """Envoyer un message dans un thread séparé"""
        threading.Thread(target=self.send_message, daemon=True).start()
    
    def send_message(self):
        """Envoyer un message chiffré"""
        try:
            # Désactiver l'interface pendant le traitement
            self.root.config(cursor="watch")
            self.update_status("🔐 Chiffrement du message en cours...")
            
            # Collecter les données
            sender = self.current_user.get().strip()
            recipient = self.recipient.get().strip()
            message = self.message_text.get(1.0, tk.END).strip()
            passphrase = self.passphrase.get() or None
            
            if not sender or not recipient:
                messagebox.showwarning("Avertissement", "Veuillez saisir l'expéditeur et le destinataire")
                return
            
            if not message:
                messagebox.showwarning("Avertissement", "Veuillez saisir un message")
                return
            
            # Vérifier l'existence des clés
            if not os.path.exists(f"keys/{sender}_private.pem"):
                messagebox.showerror("Erreur", f"Clé privée pour '{sender}' introuvable")
                return
            
            if not os.path.exists(f"keys/{recipient}_public.pem"):
                messagebox.showerror("Erreur", f"Clé publique pour '{recipient}' introuvable")
                return
            
            # Construire le message (directement sans exécuter de script externe)
            timestamp = int(time.time())
            outfile = f"messages/{sender}_to_{recipient}_{timestamp}.msg.json"
            os.makedirs("messages", exist_ok=True)
            
            # Chiffrer le message
            message_bytes = message.encode('utf-8')
            
            # 1. Générer les clés
            aes_key = gen_aes_key(32)
            hmac_key = os.urandom(32)
            
            # 2. Chiffrer le message
            iv, ciphertext = aes_cbc_encrypt(aes_key, message_bytes)
            
            # 3. Calculer HMAC
            hmac = compute_hmac(hmac_key, ciphertext)
            
            # 4. Chiffrer les clés avec RSA
            recipient_pub = load_public_key(recipient)
            enc_aes_key = rsa_encrypt_aes_key(recipient_pub, aes_key)
            enc_hmac_key = rsa_encrypt_aes_key(recipient_pub, hmac_key)
            
            # 5. Calculer le hash
            msg_hash = sha256_hex(message_bytes)
            
            # 6. Signature
            signature_b64 = None
            if self.sign_message.get():
                sender_priv = load_private_key(sender, passphrase)
                to_sign = iv + ciphertext + msg_hash.encode()
                signature = rsa_sign(sender_priv, to_sign)
                signature_b64 = _b64(signature)
            
            # 7. Construire l'objet message
            msg_obj = {
                "version": "1.0",
                "from": sender,
                "to": recipient,
                "timestamp": datetime.now().isoformat(),
                "enc_aes_key": _b64(enc_aes_key),
                "enc_hmac_key": _b64(enc_hmac_key),
                "iv": _b64(iv),
                "ciphertext": _b64(ciphertext),
                "hmac": _b64(hmac),
                "sha256_plaintext": msg_hash,
                "signature": signature_b64,
                "metadata": {
                    "encryption": "AES-256-CBC",
                    "key_wrapping": "RSA-OAEP-SHA256",
                    "integrity": "HMAC-SHA256",
                    "signed": self.sign_message.get(),
                    "message_size": len(message_bytes)
                }
            }
            
            # Sauvegarder le message
            with open(outfile, "w", encoding="utf-8") as f:
                json.dump(msg_obj, f, indent=2, ensure_ascii=False)
            
            # Afficher les résultats
            self.result_text.delete(1.0, tk.END)
            result_text = f"""✅ Message envoyé avec succès!

📊 Informations du message:
┌─────────────────────────────────────
│ 📁 Fichier: {os.path.basename(outfile)}
│ 👤 Expéditeur: {sender}
│ 👥 Destinataire: {recipient}
│ 📊 Taille message: {len(message_bytes):,} octets
│ 🔐 Chiffrement: AES-256-CBC
│ 🔑 Échange clé: RSA-OAEP-SHA256
│ ✅ Intégrité: HMAC-SHA256
│ ✍️  Signature: {'✅ Oui' if self.sign_message.get() else '❌ Non'}
└─────────────────────────────────────

📤 Instructions de transfert:
1. Envoyez le fichier '{os.path.basename(outfile)}' à {recipient}
2. Utilisez email, stockage cloud, ou méthode sécurisée
3. Assurez-vous que {recipient} a votre clé publique

📁 Emplacement: {outfile}
"""
            self.result_text.insert(1.0, result_text)
            
            self.update_status(f"✅ Message envoyé à {recipient}")
            
            # Afficher fenêtre de succès
            messagebox.showinfo("Succès", f"Message chiffré envoyé à {recipient}")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec d'envoi: {str(e)}")
            self.update_status(f"❌ Erreur: {str(e)}")
        finally:
            self.root.config(cursor="")
    
    def receive_message_thread(self):
        """Recevoir un message dans un thread séparé"""
        threading.Thread(target=self.receive_message, daemon=True).start()
    
    def receive_message(self):
        """Déchiffrer un message"""
        try:
            # Désactiver l'interface pendant le traitement
            self.root.config(cursor="watch")
            self.update_status("🔓 Déchiffrement du message en cours...")
            
            # Collecter les données
            recipient = self.receive_user.get().strip()
            infile = self.file_path.get()
            passphrase = self.receive_pass.get() or None
            
            if not recipient:
                messagebox.showwarning("Avertissement", "Veuillez saisir le nom d'utilisateur")
                return
            
            if not infile or not os.path.exists(infile):
                messagebox.showwarning("Avertissement", "Veuillez choisir un fichier message chiffré")
                return
            
            # Vérifier l'existence de la clé privée
            if not os.path.exists(f"keys/{recipient}_private.pem"):
                messagebox.showerror("Erreur", f"Clé privée pour '{recipient}' introuvable")
                return
            
            # Lire le fichier chiffré
            with open(infile, "r", encoding="utf-8") as f:
                msg = json.load(f)
            
            # Vérifier le destinataire
            if msg.get("to") != recipient:
                messagebox.showerror("Erreur", 
                    f"Ce message est destiné à '{msg.get('to')}', pas à '{recipient}'")
                return
            
            # Afficher informations fichier
            self.file_info_text.delete(1.0, tk.END)
            file_info = f"""📄 Informations fichier:
┌─────────────────────────────────────
│ 📁 Fichier: {os.path.basename(infile)}
│ 👤 Expéditeur: {msg.get('from')}
│ 👥 Destinataire: {msg.get('to')}
│ 🕒 Heure: {msg.get('timestamp', 'Inconnue')}
│ 🔐 Chiffrement: {msg.get('metadata', {}).get('encryption', 'Inconnu')}
│ ✍️  Signé: {msg.get('metadata', {}).get('signed', False)}
│ 📊 Taille: {len(json.dumps(msg)):,} octets
└─────────────────────────────────────

📋 Contenu fichier (abrégé):
"""
            self.file_info_text.insert(1.0, file_info)
            
            # Déchiffrement
            # 1. Déchiffrer clés AES et HMAC
            recipient_priv = load_private_key(recipient, passphrase)
            
            enc_aes_key = _unb64(msg["enc_aes_key"])
            aes_key = rsa_decrypt_aes_key(recipient_priv, enc_aes_key)
            
            enc_hmac_key = _unb64(msg["enc_hmac_key"])
            hmac_key = rsa_decrypt_aes_key(recipient_priv, enc_hmac_key)
            
            # 2. Vérifier HMAC
            ciphertext = _unb64(msg["ciphertext"])
            received_hmac = _unb64(msg["hmac"])
            
            if not verify_hmac(hmac_key, ciphertext, received_hmac):
                raise ValueError("Échec vérification HMAC - message peut avoir été altéré!")
            
            # 3. Déchiffrer le message
            iv = _unb64(msg["iv"])
            plaintext = aes_cbc_decrypt(aes_key, iv, ciphertext)
            
            # 4. Vérifier SHA-256
            expected_hash = msg.get("sha256_plaintext")
            actual_hash = sha256_hex(plaintext)
            integrity_ok = (expected_hash == actual_hash)
            
            # 5. Vérifier signature
            signature_b64 = msg.get("signature")
            sig_ok = None
            
            if signature_b64 and self.verify_sig.get():
                sender = msg["from"]
                if os.path.exists(f"keys/{sender}_public.pem"):
                    sender_pub = load_public_key(sender)
                    to_verify = iv + ciphertext + expected_hash.encode()
                    sig_ok = rsa_verify(sender_pub, to_verify, _unb64(signature_b64))
                else:
                    sig_ok = False
            
            # Afficher le message
            self.decrypted_text.delete(1.0, tk.END)
            try:
                message_text = plaintext.decode('utf-8')
                self.decrypted_text.insert(1.0, message_text)
            except UnicodeDecodeError:
                self.decrypted_text.insert(1.0, f"<Données binaires>\n\nTaille: {len(plaintext)} octets")
            
            # Afficher détails techniques
            self.details_text.delete(1.0, tk.END)
            details = f"""✅ Message déchiffré avec succès!

📊 Résultats déchiffrement:
┌─────────────────────────────────────
│ 👤 Expéditeur: {msg.get('from')}
│ 👥 Destinataire: {msg.get('to')}
│ 🕒 Heure envoi: {msg.get('timestamp')}
│ 📊 Taille message: {len(plaintext):,} octets
│ 🔒 Intégrité (SHA-256): {'✅ Réussi' if integrity_ok else '❌ Échoué'}
│ ✅ Vérification HMAC: ✅ Réussi
│ ✍️  Signature: {'✅ Valide' if sig_ok else ('❌ Invalide' if sig_ok is False else '❌ Non disponible')}
└─────────────────────────────────────

🔧 Informations techniques:
• Chiffrement: {msg.get('metadata', {}).get('encryption', 'Inconnu')}
• Encapsulation clé: {msg.get('metadata', {}).get('key_wrapping', 'Inconnu')}
• Intégrité: {msg.get('metadata', {}).get('integrity', 'Inconnu')}
• Signature: {'✅ Oui' if msg.get('metadata', {}).get('signed') else '❌ Non'}
"""
            self.details_text.insert(1.0, details)
            
            self.update_status(f"✅ Message déchiffré de {msg.get('from')}")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec déchiffrement: {str(e)}")
            self.update_status(f"❌ Erreur: {str(e)}")
        finally:
            self.root.config(cursor="")
    
    def generate_keys_dialog(self):
        """Ouvrir fenêtre de génération de clés"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Générer nouvelles clés")
        dialog.geometry("400x250")
        dialog.configure(bg=self.colors['bg'])
        
        ttk.Label(dialog, text="🔑 Générer nouvelles clés RSA", 
                 font=('Arial', 14, 'bold')).pack(pady=10)
        
        ttk.Label(dialog, text="Nom d'utilisateur:").pack(pady=5)
        username_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=username_var, width=30).pack(pady=5)
        
        ttk.Label(dialog, text="Mot de passe (optionnel):").pack(pady=5)
        pass_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=pass_var, width=30, show="•").pack(pady=5)
        
        def generate():
            username = username_var.get().strip()
            if not username:
                messagebox.showwarning("Avertissement", "Veuillez saisir un nom d'utilisateur")
                return
            
            try:
                # Exécuter keygen.py
                cmd = ["python", "keygen.py", "--user", username]
                if pass_var.get():
                    cmd.extend(["--passphrase", pass_var.get()])
                
                import subprocess
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    messagebox.showinfo("Succès", f"Clés générées pour '{username}'")
                    self.update_key_status()
                    dialog.destroy()
                else:
                    messagebox.showerror("Erreur", f"Échec génération: {result.stderr}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec génération: {str(e)}")
        
        ttk.Button(dialog, text="🔄 Générer", 
                  command=generate, style='Accent.TButton').pack(pady=20)
    
    def show_key_info(self):
        """Afficher informations détaillées sur les clés"""
        if not os.path.exists("keys"):
            messagebox.showinfo("Information", "Aucune clé. Générer de nouvelles clés.")
            return
        
        key_files = os.listdir("keys")
        if not key_files:
            messagebox.showinfo("Information", "Aucune clé. Générer de nouvelles clés.")
            return
        
        info = "🔐 Informations sur les clés:\n\n"
        for file in sorted(key_files):
            if file.endswith(".pem"):
                path = os.path.join("keys", file)
                size = os.path.getsize(path)
                modified = time.ctime(os.path.getmtime(path))
                
                info += f"📄 {file}\n"
                info += f"   📏 Taille: {size:,} octets\n"
                info += f"   🕒 Dernière modification: {modified}\n"
                info += f"   📍 Chemin: {path}\n\n"
        
        messagebox.showinfo("Informations clés", info)
        self.update_key_status()
    
    def clean_old_keys(self):
        """Nettoyer les anciennes clés"""
        if not os.path.exists("keys"):
            return
        
        response = messagebox.askyesno("Nettoyage", 
            "Voulez-vous supprimer toutes les anciennes clés?\n\n⚠️  Attention: Cette action est irréversible!")
        
        if response:
            try:
                for file in os.listdir("keys"):
                    os.remove(os.path.join("keys", file))
                os.rmdir("keys")
                self.update_key_status()
                messagebox.showinfo("Succès", "Toutes les anciennes clés ont été nettoyées")
                self.update_status("🧹 Anciennes clés nettoyées")
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec nettoyage: {str(e)}")

def main():
    root = tk.Tk()
    
    # Charger l'icône du programme (si elle existe)
    try:
        root.iconbitmap("icon.ico")
    except:
        pass
    
    app = SecureMessengerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
