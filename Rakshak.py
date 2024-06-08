import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
from customtkinter import *
from tkinter import ttk, messagebox
from PIL import Image, ImageTk

key = None
key_visible = True

def toggle_key_visibility(show=None):
    global key_visible
    if show is not None:
        key_visible = show
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key if key_visible else '*' * len(key))

def generate_key():
    global key
    key = Fernet.generate_key()
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key.decode())

def copy_key():
    global key
    if key:
        key_entry.clipboard_clear()
        key_entry.clipboard_append(key.decode())
        messagebox.showinfo("Copied", "Key copied to clipboard.")
    else:
        messagebox.showwarning("No Key", "Please generate a key first.")

def encrypt_message():
    global key
    message = message_entry.get("1.0", tk.END).strip()
    try:
        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(message.encode())
        ciphertext_text.delete("1.0", tk.END)
        ciphertext_text.insert("1.0", encrypted_message.decode())
        copy_button.configure(state=tk.NORMAL)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def copy_ciphertext():
    ciphertext = ciphertext_text.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(ciphertext)
    root.update()
    messagebox.showinfo("Copied", "Ciphertext copied to clipboard.")

def decrypt_message():
    key1 = key1_entry.get().strip()
    ciphertext = ciphertext_entry.get("1.0", tk.END).strip()
    try:
        fernet = Fernet(key1.encode())
        decrypted_message = fernet.decrypt(ciphertext.encode())
        decrypted_text.delete("1.0", tk.END)
        decrypted_text.insert("1.0", decrypted_message.decode())
    except Exception as e:
        messagebox.showerror("Error", str(e))

root = CTk()
root.title("AES Encrypter and Decrypter")
root.geometry("750x800")
root.configure()

notebook = ttk.Notebook(root)
encrypt_frame = ttk.Frame(notebook)
decrypt_frame = ttk.Frame(notebook)

notebook.add(encrypt_frame, text="Encrypt")
notebook.add(decrypt_frame, text="Decrypt")
notebook.pack(expand=True, fill='both')

# Encryption Section
CTkLabel(encrypt_frame, text="Encryption Section", text_color = "#000000").pack(pady=10)
mask_unmask_button = CTkButton(encrypt_frame, text="Mask/Unmask Key", command=lambda: toggle_key_visibility(not key_visible), corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2, text_color = "#000000")
mask_unmask_button.pack(pady=10)

generate_key_button = CTkButton(encrypt_frame, text="Generate Key", command=generate_key, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2, text_color = "#000000")
generate_key_button.pack(pady=10)

key_label = CTkLabel(encrypt_frame, text="Key:", text_color = "#FF0000")
key_label.pack()
key_entry = CTkEntry(encrypt_frame, show="")
key_entry.pack(pady=10)

copy_key_button = CTkButton(encrypt_frame, text="Copy Key", command=copy_key, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2, text_color = "#000000")
copy_key_button.pack(pady=10)

message_label = CTkLabel(encrypt_frame, text="Enter Message:", text_color = "#000000")
message_label.pack()
message_entry = CTkTextbox(encrypt_frame, wrap=tk.WORD, height=70, width=400)
message_entry.pack(pady=10)

encrypt_button = CTkButton(encrypt_frame, text="Encrypt", command=encrypt_message, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2, text_color = "#FF0000")
encrypt_button.pack(pady=10)

ciphertext_label = CTkLabel(encrypt_frame, text="Ciphertext:", text_color = "#FF0000")
ciphertext_label.pack()
ciphertext_text = CTkTextbox(encrypt_frame, wrap=tk.WORD, height=70, width=400)
ciphertext_text.pack(pady=10)

copy_button = CTkButton(encrypt_frame, text="Copy Ciphertext", state=tk.DISABLED, command=copy_ciphertext, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2, text_color = "#000000")
copy_button.pack(pady=10)

# Decryption Section
CTkLabel(decrypt_frame, text="Decryption Section", text_color = "#000000").pack(pady=10)
key1_label = CTkLabel(decrypt_frame, text="Key: (Copy and paste the key using Ctrl+v)", text_color = "#000000")
key1_label.pack()

key1_entry = CTkEntry(decrypt_frame, show="")
key1_entry.pack(pady=10)

ciphertext_label = CTkLabel(decrypt_frame, text="Ciphertext: (Copy the CipherText and paste here)", text_color = "#000000")
ciphertext_label.pack()

ciphertext_entry = CTkTextbox(decrypt_frame, wrap=tk.WORD, height=70, width=400)
ciphertext_entry.pack(pady=10)

decrypt_button = CTkButton(decrypt_frame, text="Decrypt", command=decrypt_message, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2, text_color = "#FF0000")
decrypt_button.pack(pady=10)

decrypted_label = CTkLabel(decrypt_frame, text="Decrypted Message:", text_color = "#000000")
decrypted_label.pack()

decrypted_text = CTkTextbox(decrypt_frame, wrap=tk.WORD, height=70, width=400)
decrypted_text.pack(pady=10)

root.mainloop()
