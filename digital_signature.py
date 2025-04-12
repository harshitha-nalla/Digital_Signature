from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls
import hashlib

def generate_keys(client_number):
    secret_key = bls.KeyGen(int.to_bytes(client_number, length=32, byteorder='big'))
    public_key = bls.SkToPk(secret_key)
    return secret_key, public_key

def create_signature(secret_key, plain_text):
    hashed_message = hashlib.sha256(plain_text.encode()).digest()
    signature = bls.Sign(secret_key, hashed_message)
    return signature, hashed_message

def validate_signature(public_key, hashed_message, signature):
    return bls.Verify(public_key, hashed_message, signature)

def run_simulation():
    num_clients = int(input("Enter number of clients: "))
    for i in range(1, num_clients + 1):
        message = input(f"Enter message for client {i}: ")
        secret_key, public_key = generate_keys(i)
        signature, hashed_message = create_signature(secret_key, message)
        print(f"[Client {i}] Message: '{message}'")
        is_valid = validate_signature(public_key, hashed_message, signature)
        print(f"-> Signature valid: {is_valid}\n")

run_simulation()
