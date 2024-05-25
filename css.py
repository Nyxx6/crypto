import time
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Random import get_random_bytes

# Symmetric Encryption Algorithms
def encrypt_aes(data, key): # AES
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce
    return ciphertext, tag, nonce

def decrypt_aes(ciphertext, tag, key, nonce):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

def encrypt_des(data, key): # DES
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

def decrypt_des(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# Asymmetric Encryption Algorithms
def generate_rsa_key_pair():    # RSA
    key = RSA.generate(2048)
    return key

def encrypt_rsa(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

def decrypt_rsa(encrypted_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    data = cipher.decrypt(encrypted_data)
    return data

# Function to derive symmetric key from shared secret using HKDF
# round to 8, key size = 32 bytes, empty salt
def derive_key(shared_secret):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None).derive(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big"))

def dh_key_exchange(generator, modulus, private_key):
    return pow(generator, private_key, modulus)

def dh():
    # Predefined DH parameters (Group 14)
    # Prime modulus (2048-bit)
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
        "A63A3621", 16)
    # Prime modulus (768-bit)
    """p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
        "A63A36210000000000090563", 16)"""
    # Generator
    g = 2
    # Generate private keys for Alice and Bob
    alice_private_key = int.from_bytes(get_random_bytes(32), "big")
    bob_private_key = int.from_bytes(get_random_bytes(32), "big")
    # Alice computes her public key
    alice_public_key = dh_key_exchange(g, p, alice_private_key)
    # Bob computes his public key
    bob_public_key = dh_key_exchange(g, p, bob_private_key)
    # Both parties compute the shared secret
    shared_secret_alice = dh_key_exchange(bob_public_key, p, alice_private_key)
    shared_secret_bob = dh_key_exchange(alice_public_key, p, bob_private_key)
    assert shared_secret_alice == shared_secret_bob    
    # Derive symmetric keys from shared secrets
    return derive_key(shared_secret_alice), derive_key(shared_secret_bob)
   

# Hashing Algorithms
def hash_sha256(data):  # SHA256
    return hashlib.sha256(data).hexdigest()

def hash_md5(data): # MD5
    return hashlib.md5(data).hexdigest()

# Test Performance
def test_performance(data_size, iterations):
    key_aes = b'0123456789ABCDEF' # 128-bit key for AES
    key_des = b'12345678' # 64-bit key for DES
    data = b'a' * data_size
    data1 = b'a' * ((int)(data_size / 1024) * 50)
    aes_time = [] 
    for _ in range(iterations):
        start_time = time.time()
        ciphertext_aes, tag_aes, nonce_aes = encrypt_aes(data, key_aes)
        decrypted_data_aes = decrypt_aes(ciphertext_aes, tag_aes, key_aes, nonce_aes)
        aes_time.append(time.time() - start_time)
    aes_time_avg = sum(aes_time) / len(aes_time)
    print(f"AES Time: {aes_time_avg:.6f} seconds")

    des_time = [] 
    for _ in range(iterations):
        start_time = time.time()
        ciphertext_des = encrypt_des(data, key_des)
        decrypted_data_des = decrypt_des(ciphertext_des, key_des)
        des_time.append(time.time() - start_time)
    des_time_avg = sum(des_time) / len(des_time)
    print(f"DES Time: {des_time_avg:.6f} seconds")

    rsa_key = generate_rsa_key_pair()
    rsa_time = [] 
    for _ in range(iterations):
        start_time = time.time()
        encrypted_data_rsa = encrypt_rsa(data1, rsa_key.publickey())
        decrypted_data_rsa = decrypt_rsa(encrypted_data_rsa, rsa_key)
        rsa_time.append(time.time() - start_time)
    rsa_time_avg = sum(rsa_time) / len(rsa_time)
    print(f"RSA Time: {rsa_time_avg:.6f} seconds")

    dh_time = []
    for _ in range(iterations):
        start_time = time.time()
        alice_key, bob_key = dh()
        dh_key_exchange_time = time.time() - start_time

        start_time_exchange = time.time()
        ciphertext, tag, nonce = encrypt_aes(data, alice_key)
        decrypted_message = decrypt_aes(ciphertext, tag, bob_key, nonce)
        dh_time.append(dh_key_exchange_time + (time.time() - start_time_exchange))
    dh_time_avg = sum(dh_time) / len(dh_time)
    print(f"Diffie Hellman Time: {dh_time_avg:.6f} seconds")

    sha256_time = [] 
    for _ in range(iterations):
        start_time = time.time()
        hashed_data = hash_sha256(data)
        sha256_time.append(time.time() - start_time)
    sha256_time_avg = sum(sha256_time) / len(sha256_time)
    print(f"SHA-256 Time: {sha256_time_avg:.6f} seconds")

    md5_time = [] 
    for _ in range(iterations):
        start_time = time.time()
        hashed_data = hash_md5(data)
        md5_time.append(time.time() - start_time)
    md5_time_avg = sum(md5_time) / len(md5_time)
    print(f"MD5 Time: {md5_time_avg:.6f} seconds")

# Test Performance with different data sizes
print("Test 1 ( data_size=1024 ) :")
test_performance(data_size=1024, iterations=100)
print("\nTest 2 ( data_size=2048 ) :")
test_performance(data_size=2048, iterations=100)
print("\nTest 3 ( data_size=4096 ) :")
test_performance(data_size=4096, iterations=100)

