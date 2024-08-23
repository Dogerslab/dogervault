import os
import random
import string
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.simpledialog import askstring
from cryptography.fernet import Fernet
import re

# Set the path to the USB drive folder
usb_path = 'F:\\Passwords'

# Generate and store a new key (only once)
def generate_and_store_key():
    key = Fernet.generate_key()
    with open(os.path.join(usb_path, 'key.key'), 'wb') as key_file:
        key_file.write(key)
    return key

# Load encryption key
def load_key():
    key_path = os.path.join(usb_path, 'key.key')
    if not os.path.exists(key_path):
        messagebox.showerror("Error", "Encryption key not found. Ensure the key file exists.")
        return None
    return open(key_path, "rb").read()

# Encrypt a message
def encrypt_message(message: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(message.encode())

# Decrypt a message
def decrypt_message(encrypted_message: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()

# Save entry (email and password) to file
def save_entry(account_name: str, email: str, password: str, key: bytes, file_path: str):
    encrypted_email = encrypt_message(email, key)
    encrypted_password = encrypt_message(password, key)
    with open(file_path, "ab") as file:
        file.write(f"{account_name}:{encrypted_email.decode()}:{encrypted_password.decode()}\n".encode())

# Load entries from file
def load_entries(file_path: str, key: bytes):
    entries = {}
    if not os.path.exists(file_path):
        return entries
    with open(file_path, "rb") as file:
        lines = file.readlines()
    for line in lines:
        parts = line.split(b':')
        if len(parts) == 3:
            account_name = parts[0].decode()
            encrypted_email = parts[1]
            encrypted_password = parts[2].strip()
            email = decrypt_message(encrypted_email, key)
            password = decrypt_message(encrypted_password, key)
            entries[account_name] = (email, password)
    return entries

# Delete entry from file
def delete_entry(account_name: str, key: bytes, file_path: str):
    entries = load_entries(file_path, key)
    if account_name in entries:
        del entries[account_name]
        with open(file_path, "wb") as file:
            for name, (email, password) in entries.items():
                encrypted_email = encrypt_message(email, key)
                encrypted_password = encrypt_message(password, key)
                file.write(f"{name}:{encrypted_email.decode()}:{encrypted_password.decode()}\n".encode())
        return True
    return False

# Generate a random password
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

# Password strength calculation
def calculate_strength(password: str):
    if len(password) < 8:
        return "Weak"
    score = 0
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[0-9]', password):
        score += 1
    if re.search(r'[@$!%*?&]', password):
        score += 1
    if len(password) >= 12:
        score += 1
    
    strength = ["Weak", "Moderate", "Strong", "Very Strong"]
    return strength[score]

# GUI Code
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Dogervault")
        self.key = load_key()
        if not self.key:
            self.root.destroy()
            return
        self.file_path = os.path.join(usb_path, 'entries.txt')

        # Set modern design parameters
        self.font = ('Helvetica', 12)
        self.bg_color = "#f4f4f4"
        self.fg_color = "#333"
        self.button_color = "#007bff"
        self.button_text_color = "#fff"
        self.entry_bg_color = "#fff"
        self.entry_border_color = "#ced4da"

        self.root.configure(bg=self.bg_color)

        # Create GUI elements
        self.create_widgets()

    def create_widgets(self):
        # Frame for adding entries
        self.add_frame = tk.LabelFrame(self.root, text="Add New Entry", padx=10, pady=10, font=self.font, bg=self.bg_color, fg=self.fg_color, bd=0, relief="flat")
        self.add_frame.pack(padx=10, pady=10, fill="both", expand=True, side=tk.LEFT)

        tk.Label(self.add_frame, text="Account Name:", font=self.font, bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.account_name_entry = tk.Entry(self.add_frame, width=30, font=self.font, bg=self.entry_bg_color, bd=1, relief="solid")
        self.account_name_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(self.add_frame, text="Email Address:", font=self.font, bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.email_entry = tk.Entry(self.add_frame, width=30, font=self.font, bg=self.entry_bg_color, bd=1, relief="solid")
        self.email_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(self.add_frame, text="Password:", font=self.font, bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.password_entry = tk.Entry(self.add_frame, show="*", width=30, font=self.font, bg=self.entry_bg_color, bd=1, relief="solid")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        self.toggle_password_button = tk.Button(self.add_frame, text="Show", command=self.toggle_password_visibility, font=self.font, bg=self.button_color, fg=self.button_text_color, relief="flat", bd=0, height=1, width=5)
        self.toggle_password_button.grid(row=2, column=2, padx=5, pady=5)

        self.save_button = tk.Button(self.add_frame, text="Save Entry", command=self.save_entry, font=self.font, bg=self.button_color, fg=self.button_text_color, relief="flat", bd=0, height=1, width=15)
        self.save_button.grid(row=3, columnspan=3, pady=10)

        # Frame for viewing, searching, and deleting entries
        self.view_frame = tk.LabelFrame(self.root, text="Manage Entries", padx=10, pady=10, font=self.font, bg=self.bg_color, fg=self.fg_color, bd=0, relief="flat")
        self.view_frame.pack(padx=10, pady=10, fill="both", expand=True, side=tk.LEFT)

        tk.Label(self.view_frame, text="Search:", font=self.font, bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.search_entry = tk.Entry(self.view_frame, width=30, font=self.font, bg=self.entry_bg_color, bd=1, relief="solid")
        self.search_entry.grid(row=0, column=1, padx=5, pady=5)
        self.search_button = tk.Button(self.view_frame, text="Search", command=self.search_entries, font=self.font, bg=self.button_color, fg=self.button_text_color, relief="flat", bd=0, height=1, width=10)
        self.search_button.grid(row=0, column=2, padx=5, pady=5)

        self.view_button = tk.Button(self.view_frame, text="Show All Entries", command=self.show_all_entries, font=self.font, bg=self.button_color, fg=self.button_text_color, relief="flat", bd=0, height=1, width=15)
        self.view_button.grid(row=1, columnspan=3, pady=10)

        self.entries_text = tk.Text(self.view_frame, height=15, width=60, font=self.font, bg=self.entry_bg_color, bd=1, relief="solid", wrap=tk.WORD)
        self.entries_text.grid(row=2, columnspan=3, padx=5, pady=5)

        self.delete_button = tk.Button(self.view_frame, text="Delete Entry", command=self.delete_entry, font=self.font, bg="red", fg=self.button_text_color, relief="flat", bd=0, height=1, width=15)
        self.delete_button.grid(row=3, column=0, padx=5, pady=5)

        self.edit_button = tk.Button(self.view_frame, text="Edit Entry", command=self.edit_entry, font=self.font, bg=self.button_color, fg=self.button_text_color, relief="flat", bd=0, height=1, width=15)
        self.edit_button.grid(row=3, column=1, padx=5, pady=5)

        self.quit_button = tk.Button(self.view_frame, text="Quit", command=self.quit_app, font=self.font, bg="red", fg=self.button_text_color, relief="flat", bd=0, height=1, width=10)
        self.quit_button.grid(row=3, column=2, padx=5, pady=5)

        self.password_strength_label = tk.Label(self.add_frame, text="Password Strength:", font=self.font, bg=self.bg_color, fg=self.fg_color)
        self.password_strength_label.grid(row=4, column=0, sticky="w", padx=5, pady=5)

        self.password_strength_value = tk.Label(self.add_frame, text="", font=self.font, bg=self.bg_color, fg=self.fg_color)
        self.password_strength_value.grid(row=4, column=1, padx=5, pady=5)

        self.check_strength_button = tk.Button(self.add_frame, text="Check Strength", command=self.check_strength, font=self.font, bg=self.button_color, fg=self.button_text_color, relief="flat", bd=0, height=1, width=15)
        self.check_strength_button.grid(row=5, columnspan=3, pady=10)

    def toggle_password_visibility(self):
        if self.password_entry.cget('show') == "":
            self.password_entry.config(show="*")
            self.toggle_password_button.config(text="Show")
        else:
            self.password_entry.config(show="")
            self.toggle_password_button.config(text="Hide")

    def save_entry(self):
        account_name = self.account_name_entry.get()
        email = self.email_entry.get()
        password = self.password_entry.get()
        if not account_name or not email or not password:
            messagebox.showerror("Error", "All fields must be filled")
            return
        save_entry(account_name, email, password, self.key, self.file_path)
        messagebox.showinfo("Success", "Entry saved successfully")
        self.clear_entries()

    def search_entries(self):
        search_query = self.search_entry.get().strip()
        entries = load_entries(self.file_path, self.key)
        self.entries_text.delete(1.0, tk.END)
        for account_name, (email, password) in entries.items():
            if search_query.lower() in account_name.lower():
                self.entries_text.insert(tk.END, f"Account: {account_name}\nEmail: {email}\nPassword: {password}\n\n")

    def show_all_entries(self):
        entries = load_entries(self.file_path, self.key)
        self.entries_text.delete(1.0, tk.END)
        for account_name, (email, password) in entries.items():
            self.entries_text.insert(tk.END, f"Account: {account_name}\nEmail: {email}\nPassword: {password}\n\n")

    def delete_entry(self):
        account_name = askstring("Delete Entry", "Enter the account name to delete:")
        if account_name and delete_entry(account_name, self.key, self.file_path):
            messagebox.showinfo("Success", "Entry deleted successfully")
            self.show_all_entries()
        else:
            messagebox.showerror("Error", "Entry not found")

    def edit_entry(self):
        account_name = askstring("Edit Entry", "Enter the account name to edit:")
        entries = load_entries(self.file_path, self.key)
        if account_name in entries:
            new_email = askstring("Edit Email", "Enter the new email address:")
            new_password = askstring("Edit Password", "Enter the new password:")
            if new_email and new_password:
                delete_entry(account_name, self.key, self.file_path)
                save_entry(account_name, new_email, new_password, self.key, self.file_path)
                messagebox.showinfo("Success", "Entry updated successfully")
                self.show_all_entries()
        else:
            messagebox.showerror("Error", "Entry not found")

    def check_strength(self):
        password = self.password_entry.get()
        if password:
            strength = calculate_strength(password)
            self.password_strength_value.config(text=strength)
        else:
            self.password_strength_value.config(text="No password entered")

    def clear_entries(self):
        self.account_name_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.password_strength_value.config(text="")

    def quit_app(self):
        self.root.destroy()

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()

