import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_and_save_keypair():
    try:
        # Générer une paire de clés RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Sauvegarder la clé privée
        filename_private = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if not filename_private:
            return
        with open(filename_private, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Sauvegarder la clé publique
        public_key = private_key.public_key()
        filename_public = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if not filename_public:
            return
        with open(filename_public, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        messagebox.showinfo("Clés générées et sauvegardées", "La paire de clés RSA a été générée et sauvegardée avec succès.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur est survenue lors de la génération et de la sauvegarde des clés : {e}")

def select_file(title):
    filename = filedialog.askopenfilename(title=title)
    if filename:
        return filename
    else:
        messagebox.showerror("Erreur", "Aucun fichier sélectionné.")
        return None

def encrypt_file(input_file, output_file, public_key):
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Chiffrer les données du fichier avec la clé publique
    cipher_text = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Écrire les données chiffrées dans un nouveau fichier
    with open(output_file, 'wb') as f:
        f.write(cipher_text)

def decrypt_file(input_file, output_file, private_key):
    with open(input_file, 'rb') as f:
        cipher_text = f.read()
    
    # Déchiffrer les données du fichier avec la clé privée
    plain_text = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Écrire les données déchiffrées dans un nouveau fichier
    with open(output_file, 'wb') as f:
        f.write(plain_text)

def sign_file(input_file, private_key):
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Signer les données du fichier avec la clé privée
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def save_signature(signature, filename):
    # Sauvegarder la signature dans un fichier
    with open(filename, 'wb') as f:
        f.write(signature)

def verify_signature(input_file, signature, public_key):
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Vérifier la signature des données du fichier avec la clé publique
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        messagebox.showinfo("Signature vérifiée", "La signature a été vérifiée avec succès.")
    except Exception as e:
        messagebox.showerror("Erreur de vérification", f"La vérification de la signature a échoué : {e}")

def encrypt():
    public_key_file = select_file("Sélectionner la clé publique")
    if not public_key_file:
        return
    
    input_file = select_file("Sélectionner le fichier à chiffrer")
    if not input_file:
        return
    
    output_file = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin")])
    if not output_file:
        return
    
    try:
        public_key = serialization.load_pem_public_key(open(public_key_file, 'rb').read(), backend=default_backend())
        encrypt_file(input_file, output_file, public_key)
        messagebox.showinfo("Chiffrement terminé", "Le fichier a été chiffré avec succès.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur est survenue lors du chiffrement : {e}")

def decrypt():
    private_key_file = select_file("Sélectionner la clé privée")
    if not private_key_file:
        return
    
    input_file = select_file("Sélectionner le fichier chiffré")
    if not input_file:
        return
    
    output_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if not output_file:
        return
    
    try:
        private_key = serialization.load_pem_private_key(open(private_key_file, 'rb').read(), password=None, backend=default_backend())
        decrypt_file(input_file, output_file, private_key)
        messagebox.showinfo("Déchiffrement terminé", "Le fichier a été déchiffré avec succès.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur est survenue lors du déchiffrement : {e}")

def sign():
    private_key_file = select_file("Sélectionner la clé privée")
    if not private_key_file:
        return
    
    input_file = select_file("Sélectionner le fichier à signer")
    if not input_file:
        return
    
    output_file = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin")])
    if not output_file:
        return
    
    try:
        private_key = serialization.load_pem_private_key(open(private_key_file, 'rb').read(), password=None, backend=default_backend())
        signature = sign_file(input_file, private_key)
        save_signature(signature, output_file)
        messagebox.showinfo("Signature créée", "La signature a été créée avec succès.")
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur est survenue lors de la signature : {e}")

def verify():
    public_key_file = select_file("Sélectionner la clé publique")
    if not public_key_file:
        return
    
    input_file = select_file("Sélectionner le fichier à vérifier")
    if not input_file:
        return
    
    signature_file = select_file("Sélectionner le fichier signature")
    if not signature_file:
        return
    
    try:
        public_key = serialization.load_pem_public_key(open(public_key_file, 'rb').read(), backend=default_backend())
        signature = open(signature_file, 'rb').read()
        verify_signature(input_file, signature, public_key)
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur est survenue lors de la vérification de la signature : {e}")

def main():
    root = tk.Tk()
    root.title("Crypto App")
    
    frame = tk.Frame(root)
    frame.pack(padx=10, pady=10)
    
    btn_generate_keypair = tk.Button(frame, text="Générer et sauvegarder la paire de clés", command=generate_and_save_keypair)
    btn_generate_keypair.grid(row=0, column=0, padx=5, pady=5)
    
    btn_encrypt = tk.Button(frame, text="Chiffrer un fichier", command=encrypt)
    btn_encrypt.grid(row=1, column=0, padx=5, pady=5)
    
    btn_decrypt = tk.Button(frame, text="Déchiffrer un fichier", command=decrypt)
    btn_decrypt.grid(row=2, column=0, padx=5, pady=5)
    
    btn_sign = tk.Button(frame, text="Signer un fichier", command=sign)
    btn_sign.grid(row=3, column=0, padx=5, pady=5)
    
    btn_verify = tk.Button(frame, text="Vérifier la signature", command=verify)
    btn_verify.grid(row=4, column=0, padx=5, pady=5)
    
    root.mainloop()

if __name__ == "__main__":
    main()
