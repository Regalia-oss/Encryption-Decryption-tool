# encryption_tool.py
from Crypto.Cipher import AES
import base64

# ----- Helper functions -----
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr((ord(char) - offset + shift) % 26 + offset)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def vigenere_encrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            k = ord(key[key_index % len(key)]) - 65
            result += chr((ord(char) - offset + k) % 26 + offset)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            k = ord(key[key_index % len(key)]) - 65
            result += chr((ord(char) - offset - k) % 26 + offset)
            key_index += 1
        else:
            result += char
    return result

def xor_encrypt(text, key):
    return ''.join([chr(ord(c)^ord(key[i%len(key)])) for i,c in enumerate(text)])

# ----- AES Encryption -----
def pad(text):
    while len(text) % 16 != 0:
        text += " "
    return text

def aes_encrypt(text, key):
    key = pad(key)[:16].encode()  # AES key must be 16 bytes
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text).encode())
    return base64.b64encode(encrypted).decode()

def aes_decrypt(ciphertext, key):
    key = pad(key)[:16].encode()
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode().strip()

# ----- Main CLI -----
def main():
    print("=== Encryption/Decryption Tool ===")
    print("Options:")
    print("1. Caesar Cipher")
    print("2. Vigenère Cipher")
    print("3. XOR Cipher")
    print("4. AES Encryption")
    
    choice = input("Select an option (1-4): ")
    
    text = input("Enter text: ")
    
    if choice == "1":
        shift = int(input("Enter shift number: "))
        encrypted = caesar_encrypt(text, shift)
        decrypted = caesar_decrypt(encrypted, shift)
    elif choice == "2":
        key = input("Enter keyword: ")
        encrypted = vigenere_encrypt(text, key)
        decrypted = vigenere_decrypt(encrypted, key)
    elif choice == "3":
        key = input("Enter key (any text): ")
        encrypted = xor_encrypt(text, key)
        decrypted = xor_encrypt(encrypted, key)
    elif choice == "4":
        key = input("Enter 16-char key: ")
        encrypted = aes_encrypt(text, key)
        decrypted = aes_decrypt(encrypted, key)
    else:
        print("Invalid choice")
        return
    
    print("\nEncrypted:", encrypted)
    print("Decrypted:", decrypted)

if __name__ == "__main__":
    main()
