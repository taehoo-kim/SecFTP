import hashlib
import os

def authenticate_user(username, password):
    with open('password.txt', 'r') as f:
        for line in f:
            stored_user, salt, hash_value = line.strip().split(':')
            if username == stored_user:
                test_hash = hash_password(password, salt)
                return test_hash == hash_value
    return False

def hash_password(password, salt):
    return hashlib.sha256(
        (password + salt).encode()
    ).hexdigest()