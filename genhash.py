from cryptography.fernet import Fernet

# Generate a new secret key for AES encryption
#key = Fernet.generate_key()

# Create a new instance of the Fernet class using the secret key
#cipher_suite = Fernet(key)

# Encrypt some data using AES encryption
#plaintext = b"Hello,2023world!"
#ciphertext = cipher_suite.encrypt(plaintext)

def generate_key():
    
    key = Fernet.generate_key()
       
    with open('genhash.key', 'wb') as key_file:
        key_file.write(key)
    print('Key generate and save to genhash.key')

if __name__== '__main__':
    generate_key()


