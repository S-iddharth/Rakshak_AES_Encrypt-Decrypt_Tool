import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
from tkinter import PhotoImage 

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
    message = message_entry.get("1.0", tk.END).strip()  # Get the message from Text widget

    try:
        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(message.encode())
        ciphertext_text.delete("1.0", tk.END)
        ciphertext_text.insert("1.0", encrypted_message.decode())
        # Enable the copy button
        copy_button.config(state=tk.NORMAL)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def copy_ciphertext():
    ciphertext = ciphertext_text.get("1.0", tk.END)
    root.clipboard_clear()
    root.clipboard_append(ciphertext)
    root.update()  # This is required on some systems
    messagebox.showinfo("Copied", "Ciphertext copied to clipboard.")

root = tk.Tk()
root.title("AES Encrypter(By Siddharth Gupta)")

root.resizable(False, False) 
root.configure(bg="black")

mask_unmask_button = ttk.Button(root, text="Mask/Unmask Key", command=lambda: toggle_key_visibility(not key_visible))
mask_unmask_button.pack(pady=10)

bg_image = PhotoImage(file="/home/lucifer/Screenshot from 2023-09-03 18-23-29.png")  
bg_label = tk.Label(root, image=bg_image)
bg_label.place(relwidth=1, relheight=1)

generate_key_button = ttk.Button(root, text="Generate Key", command=generate_key)
generate_key_button.pack(pady=10)  # Increased spacing below the button

key_label = ttk.Label(root, text="Key:", background="light grey", foreground =)
key_label.pack()
key_entry = ttk.Entry(root, show="")
key_entry.pack()

copy_key_button = ttk.Button(root, text="Copy Key", command=copy_key)
copy_key_button.pack(pady=10)  # Increased spacing below the button

message_label = ttk.Label(root, text="Enter Message:", background="light grey")
message_label.pack()
message_entry = tk.Text(root, wrap=tk.WORD, height=5, width=30, bg="light grey")  # Use tk.Text for multi-line input
message_entry.pack(pady=10)  # Increased spacing below the text widget

encrypt_button = ttk.Button(root, text="Encrypt", command=encrypt_message)
encrypt_button.pack(pady=10)  # Increased spacing below the button

ciphertext_label = ttk.Label(root, text="Ciphertext:", background="light grey")
ciphertext_label.pack()
ciphertext_text = tk.Text(root, wrap=tk.WORD, height=5, width=30, bg="light grey")
ciphertext_text.pack(pady=10)  # Increased spacing below the text widget

copy_button = ttk.Button(root, text="Copy Ciphertext", state=tk.DISABLED, command=copy_ciphertext)
copy_button.pack(pady=10)  # Increased spacing below the button

def decrypt_message():
    key1 = key1_entry.get()
    ciphertext = ciphertext_entry.get("1.0", tk.END).strip()  # Get the ciphertext from Text widget

    try:
        key_bytes = key1.encode()  # Encode the key as bytes
        fernet = Fernet(key_bytes)
        decrypted_message = fernet.decrypt(ciphertext.encode())
        message_text.delete("1.0", tk.END)
        message_text.insert("1.0", decrypted_message.decode())
    except Exception as e:
        messagebox.showerror("Error", str(e))
        
root = tk.Tk()
root.title("AES Decrypter(By Siddharth Gupta)")
root.configure(bg="dark grey")
root.resizable(False, False)

key1_label = ttk.Label(root, text="Key: (Copy and paste the key using Ctrl+v)", background="light grey")
key1_label.pack()

key1_entry = ttk.Entry(root, show="", background = "light grey")
key1_entry.pack(pady=10)  # Increased spacing below the entry field

ciphertext_label = ttk.Label(root, text="Ciphertext: (Copy the CipherText and paste here using Ctrl+v)")
ciphertext_label.pack()

ciphertext_entry = tk.Text(root, wrap=tk.WORD, height=5, width=40, bg = "light grey")
ciphertext_entry.pack(pady=10)  # Increased spacing below the text widget

decrypt_button = ttk.Button(root, text="Decrypt", command=decrypt_message)
decrypt_button.pack(pady=10)  # Increased spacing below the button

message_label = ttk.Label(root, text="Decrypted Message:", background="light grey")
message_label.pack()

message_text = tk.Text(root, wrap=tk.WORD, height=5, width=40, bg="light grey")
message_text.pack(pady=10)  # Increased spacing below the text widget

root.mainloop()

