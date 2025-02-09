# Required libraries
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad #PKCS5Padding = PKCS7Padding modern version
import random
import binascii
from datetime import datetime

def generate_rsa_keypair():
    # Generate RSA keys for Destination B
    key = RSA.generate(2048)
    private_key = key #Full object is private key(contains both private and public key)
    public_key = key.publickey() #Public key is extracted from the full key object
    # Print public key in hex format
    print(f"Destination B's Public Key (hex): {binascii.hexlify(public_key.export_key()).decode()}")
    return private_key, public_key

def generate_aes_key(student_id):
    # Seed the random number generator with student ID
    random.seed(student_id)
    
    # Generate random number using seeded generator
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    
    # Hash the random number
    hasher = SHA256.new()
    hasher.update(random_bytes)
    return hasher.digest()

class SourceA:
    def __init__(self):
        self.aes_key = None
        self.message = None
    
    def set_message(self, message):
        message_bytes = message.encode()
        print(f"Message length in bytes: {len(message_bytes)}")  # Debug
        if len(message_bytes) > 16:
            raise ValueError(f"Message must be less than 16 bytes (current: {len(message_bytes)} bytes)") #raise will stop the program
        self.message = message
    
    def encrypt_message(self, public_key):
        # Step 1: AES encryption of message
        cipher_aes = AES.new(self.aes_key, AES.MODE_ECB)
        padded_message = pad(self.message.encode(), AES.block_size)
        encrypted_message = cipher_aes.encrypt(padded_message)
        
        # Step 2: RSA encryption of AES key
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_key = cipher_rsa.encrypt(self.aes_key)
        
        return encrypted_message, encrypted_key

class DestinationB:
    def __init__(self, private_key):
        self.private_key = private_key
    
    def decrypt_data(self, encrypted_message, encrypted_key):
        # Step 1: Recover AES key
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        aes_key = cipher_rsa.decrypt(encrypted_key)
        
        # Step 2: Decrypt message
        cipher_aes = AES.new(aes_key, AES.MODE_ECB)
        decrypted_padded = cipher_aes.decrypt(encrypted_message)
        original_message = unpad(decrypted_padded, AES.block_size)
        
        return original_message.decode(), aes_key

def main():
    # Initialize
    student_id = "F414984"
    message = "Hello World!"  # Test message (less than 16 bytes)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"crypto_result_{timestamp}.txt"
    
    # Open file for writing
    with open(output_file, "w") as f:
        # Generate keys
        private_key, public_key = generate_rsa_keypair()
        f.write(f"Destination B's Public Key (hex): {binascii.hexlify(public_key.export_key()).decode()}\n")
        
        # Source A operations
        source = SourceA()
        source.aes_key = generate_aes_key(student_id)
        source.set_message(message)
        
        # Write original values
        f.write(f"\nOriginal Message: {message}\n")
        f.write(f"Message length: {len(message.encode())} bytes\n")
        f.write(f"Original AES Key (hex): {binascii.hexlify(source.aes_key).decode()}\n")
        
        # Encrypt at Source A
        encrypted_message, encrypted_key = source.encrypt_message(public_key)
        f.write(f"Encrypted Message (hex): {binascii.hexlify(encrypted_message).decode()}\n")
        f.write(f"Encrypted AES Key (hex): {binascii.hexlify(encrypted_key).decode()}\n")
        
        # Decrypt at Destination B
        destination = DestinationB(private_key)
        decrypted_message, recovered_key = destination.decrypt_data(encrypted_message, encrypted_key)
        
        # Write verification results
        f.write(f"\nRecovered Message: {decrypted_message}\n")
        f.write(f"Recovered AES Key (hex): {binascii.hexlify(recovered_key).decode()}\n")
    
    # Read and print the file contents to console
    with open(output_file, "r") as f:
        print(f.read())

if __name__ == "__main__":
    main()
