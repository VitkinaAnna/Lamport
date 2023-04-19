import hashlib
import random

# Key generation
def generate_keys(length):
    private_key = []
    public_key = []
    for i in range(length):
        private_key.append([random.randint(0, 1) for j in range(256)])
        hash_obj = hashlib.sha256(str(private_key[i]).encode())
        public_key.append(hash_obj.digest())
    return private_key, public_key

# Signing
def sign(private_key, message):
    message_hash = hashlib.sha256(message.encode()).digest()
    signature = []
    for i in range(len(message_hash)):
        bit_list = []
        for j in range(8):
            bit_list.append(private_key[i*8+j][message_hash[i]>>j&1])
        signature.append(bit_list)
    return signature

# Verification
def verify(public_key, message, signature):
    message_hash = hashlib.sha256(message.encode()).digest()
    for i in range(len(message_hash)):
        bit_list = []
        for j in range(8):
            bit_list.append(public_key[i*8+j][signature[i][j]])
        hash_obj = hashlib.sha256(str(bit_list).encode())
        if hash_obj.digest() != message_hash[i:i+1]:
            return False
    return True

# Example usage
private_key, public_key = generate_keys(256)
message = "This is a message for authentication."
signature = sign(private_key, message)
if verify(public_key, message, signature):
    print("Authentication successful!")
else:
    print("Authentication failed!")
