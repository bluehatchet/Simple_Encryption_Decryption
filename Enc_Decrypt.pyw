import os
from tkinter import Tk, Label, Button, filedialog, messagebox, PhotoImage
from cryptography.fernet import Fernet

# Function to generate a key and save it into a file
def generate_key():
    key = Fernet.generate_key()
    key_file = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
    if key_file:
        with open(key_file, 'wb') as file:
            file.write(key)
        messagebox.showinfo("Key Generated", f"Key generated and saved to '{key_file}'.")
        messagebox.showinfo("Advisory", "Please remember to safely store the encryption key file in a safe location after every use of this program. Rename the file for every batch of encrypted files.")
    else:
        messagebox.showwarning("Warning", "No file selected. Key not generated.")

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
        
    print(f"File '{input_file}' encrypted successfully.")

# Function to decrypt a file
def decrypt_file(input_file, key_file):
    key = load_key(key_file)
    fernet = Fernet(key)
    
    with open(input_file, 'rb') as encrypted_file:
        encrypted = encrypted_file.read()
        
    decrypted = fernet.decrypt(encrypted)
    
    with open(input_file, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)
        
    print(f"File '{input_file}' decrypted successfully.")

def select_files_and_encrypt():
    key_file = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
    if not key_file:
        messagebox.showwarning("Warning", "No key file selected. Encryption aborted.")
        return
    
    file_paths = filedialog.askopenfilenames()
    if file_paths:
        file_label.config(text='\n'.join(file_paths))
        for file_path in file_paths:
            encrypt_file(file_path, key_file)
        messagebox.showinfo("Success", "Files encrypted successfully.")
    else:
        file_label.config(text="No files selected")
        messagebox.showwarning("Warning", "No files selected for encryption")

def select_files_and_decrypt():
    key_file = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
    if not key_file:
        messagebox.showwarning("Warning", "No key file selected. Decryption aborted.")
        return

    file_paths = filedialog.askopenfilenames()
    if file_paths:
        file_label.config(text='\n'.join(file_paths))
        for file_path in file_paths:
            decrypt_file(file_path, key_file)
        messagebox.showinfo("Success", "Files decrypted successfully.")
    else:
        file_label.config(text="No files selected")
        messagebox.showwarning("Warning", "No files selected for decryption")

if __name__ == "__main__":
    # Create the GUI
    root = Tk()
    root.title("File Encryptor/Decryptor")

    label = Label(root, text="Select files to encrypt or decrypt")
    label.pack(pady=10)

    file_label = Label(root, text="No files selected", wraplength=300, justify="left")
    file_label.pack(pady=5)

    generate_key_button = Button(root, text="Generate Key", command=generate_key)
    generate_key_button.pack(pady=5)

    encrypt_button = Button(root, text="Encrypt Files", command=select_files_and_encrypt)
    encrypt_button.pack(pady=5)

    decrypt_button = Button(root, text="Decrypt Files", command=select_files_and_decrypt)
    decrypt_button.pack(pady=5)
    
################################# Pixel_Art Icon #################################################################    
# Define the pixel art data as a space-separated string
pixel_data = (
    "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
    "0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 0 "
    "0 0 0 0 0 0 0 0 1 1 1 0 1 1 1 0 "
    "0 0 0 0 0 0 0 0 1 0 1 1 1 1 0 0 "
    "0 0 0 0 0 0 0 0 0 1 0 1 1 0 0 0 "
    "0 0 0 0 0 0 0 0 1 0 1 0 1 1 0 0 "
    "0 0 0 0 0 0 0 1 0 1 1 1 0 1 0 0 "
    "0 0 0 0 0 0 1 0 1 1 1 0 1 1 0 0 "
    "0 0 0 0 0 1 0 1 1 1 0 0 0 0 0 0 "
    "0 0 0 0 1 0 1 1 1 0 0 0 0 0 0 0 "
    "0 0 0 1 0 1 1 1 0 0 1 1 1 0 0 0 "
    "0 0 1 0 1 1 1 0 0 0 0 0 0 0 0 0 "
    "0 1 0 1 1 1 0 0 1 1 1 1 1 1 1 0 "
    "0 1 1 1 1 0 0 0 0 0 0 0 0 0 0 0 "
    "0 1 1 1 0 0 1 1 1 1 1 1 1 1 1 1 "
    "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
)

# Split the pixel data by spaces to get a list of values
pixel_data_list = pixel_data.split()

# Convert the pixel data into a PhotoImage
icon = PhotoImage(width=16, height=16)

# Set the pixels in the PhotoImage
for y in range(16):
    for x in range(16):
        bit = int(pixel_data_list[y * 16 + x])
        color = '#000000' if bit == 1 else '#FFFFFF'
        icon.put(color, (x, y))

# Set the window icon
root.iconphoto(True, icon)
##########################################################################################################################

root.mainloop()
