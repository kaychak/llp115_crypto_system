# Required libraries
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import binascii

def generate_rsa_keypair():
    # Generate RSA keys for Destination B (already 2048-bit, which meets requirements)
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    # Add display of public key in hex format
    print(f"Destination B's Public Key (hex): {binascii.hexlify(public_key.export_key()).decode()}")
    return private_key, public_key

def generate_aes_key(student_id):
    # Generate AES key using student ID as seed
    hasher = SHA256.new()
    seed = str(student_id).encode()
    random_bytes = get_random_bytes(32)
    hasher.update(seed + random_bytes)
    return hasher.digest()

class SourceA:
    def __init__(self):
        self.aes_key = None
        self.message = None
    
    def set_message(self, message):
        message_bytes = message.encode()
        print(f"Message length in bytes: {len(message_bytes)}")  # Debug
        if len(message_bytes) > 16:
            raise ValueError(f"Message must be less than 16 bytes (current: {len(message_bytes)} bytes)")
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
    # Initialize system
    student_id = "F414984"
    message = "Hello World!"  # Test message (less than 16 bytes)
    
    # Generate keys
    private_key, public_key = generate_rsa_keypair()
    
    # Source A operations
    source = SourceA()
    source.aes_key = generate_aes_key(student_id)
    source.set_message(message)
    
    # Print original values (add message length)
    print(f"\nOriginal Message: {message}")
    print(f"Message length: {len(message.encode())} bytes")
    print(f"Original AES Key (hex): {binascii.hexlify(source.aes_key).decode()}")
    
    # Encrypt at Source A
    encrypted_message, encrypted_key = source.encrypt_message(public_key)
    print(f"Encrypted Message (hex): {binascii.hexlify(encrypted_message).decode()}")
    print(f"Encrypted AES Key (hex): {binascii.hexlify(encrypted_key).decode()}")
    
    # Decrypt at Destination B
    destination = DestinationB(private_key)
    decrypted_message, recovered_key = destination.decrypt_data(encrypted_message, encrypted_key)
    
    # Verify results
    print(f"\nRecovered Message: {decrypted_message}")
    print(f"Recovered AES Key (hex): {binascii.hexlify(recovered_key).decode()}")

if __name__ == "__main__":
    main()
