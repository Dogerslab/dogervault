from cryptography.fernet import Fernet

def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

if __name__ == "__main__":
    generate_key()
    print("Encryption key generated and saved as 'key.key'.")