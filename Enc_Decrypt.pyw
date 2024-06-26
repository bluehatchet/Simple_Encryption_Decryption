import os
from tkinter import Tk, Label, Button, filedialog, messagebox
from cryptography.fernet import Fernet

# Function to generate a key and save it into a file
def generate_key(key_file):
    key = Fernet.generate_key()
    with open(key_file, 'wb') as file:
        file.write(key)

# Function to load the key from a file
def load_key(key_file):
    return open(key_file, 'rb').read()

# Function to encrypt a file
def encrypt_file(input_file, key_file):
    key = load_key(key_file)
    fernet = Fernet(key)
    
    with open(input_file, 'rb') as file:
        original = file.read()
        
    encrypted = fernet.encrypt(original)
    
    with open(input_file, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
        
    messagebox.showinfo("Success", f"File '{input_file}' encrypted successfully.")

# Function to decrypt a file
def decrypt_file(input_file, key_file):
    key = load_key(key_file)
    fernet = Fernet(key)
    
    with open(input_file, 'rb') as encrypted_file:
        encrypted = encrypted_file.read()
        
    decrypted = fernet.decrypt(encrypted)
    
    with open(input_file, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)
        
    messagebox.showinfo("Success", f"File '{input_file}' decrypted successfully.")

def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_label.config(text=file_path)
    else:
        file_label.config(text="No file selected")

def encrypt_selected_file():
    file_path = file_label.cget("text")
    if file_path != "No file selected":
        encrypt_file(file_path, key_file)
    else:
        messagebox.showwarning("Warning", "No file selected for encryption")

def decrypt_selected_file():
    file_path = file_label.cget("text")
    if file_path != "No file selected":
        decrypt_file(file_path, key_file)
    else:
        messagebox.showwarning("Warning", "No file selected for decryption")

if __name__ == "__main__":
    key_file = 'filekey.key'

    # Generate a key and save it if it doesn't exist
    if not os.path.exists(key_file):
        generate_key(key_file)
        messagebox.showinfo("Key Generated", f"Key generated and saved to '{key_file}'.")

    # Create the GUI
    root = Tk()
    root.title("File Encryptor/Decryptor")

    label = Label(root, text="Select a file to encrypt or decrypt")
    label.pack(pady=10)

    file_label = Label(root, text="No file selected", wraplength=300)
    file_label.pack(pady=5)

    select_button = Button(root, text="Select File", command=select_file)
    select_button.pack(pady=5)

    encrypt_button = Button(root, text="Encrypt File", command=encrypt_selected_file)
    encrypt_button.pack(pady=5)

    decrypt_button = Button(root, text="Decrypt File", command=decrypt_selected_file)
    decrypt_button.pack(pady=5)

    root.mainloop()
