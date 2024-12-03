import hashlib

def hash_password(password, salt):
    combined = (password + salt).encode('utf-8')
    return hashlib.sha256(combined).hexdigest()

def create_password_file():
    test_hash = hash_password('admin123', 'salt123')
    print(f"Test hash for admin123: {test_hash}")
    
    with open('password.txt', 'w') as f:
        # admin:admin123
        admin_hash = hash_password('admin123', 'salt123')
        f.write(f'admin:salt123:{admin_hash}\n')
        
        # test:test123
        test_hash = hash_password('test123', 'salt456')
        f.write(f'test:salt456:{test_hash}\n')

if __name__ == '__main__':
    create_password_file()