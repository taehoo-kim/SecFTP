import socket
import threading
import hashlib
import os
from client.crypto_utils import (
    generate_rsa_keys,
    decrypt_with_rsa,
    encrypt_with_aes,
    decrypt_with_aes
)

class FTPServer:
    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = generate_rsa_keys()
        self.symmetric_key = None

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")
        
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"[+] New client connected from {addr[0]}:{addr[1]}")
            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, addr)
            )
            client_thread.start()

    def process_command(self, client_socket, command):
        try:
            cmd_parts = command.decode().split()
            if cmd_parts[0] == 'send':
                filename = cmd_parts[1]
                print(f"[DEBUG] Waiting for file data: {filename}")
                
                encrypted_data = client_socket.recv(4096)
                if encrypted_data:
                    data = decrypt_with_aes(encrypted_data, self.symmetric_key)
                    save_path = os.path.join('server_files', filename)
                    
                    with open(save_path, 'wb') as f:
                        f.write(data)
                    print(f"[+] File saved successfully: {save_path}")
                    
        except Exception as e:
            print(f"[!] Error in process_command: {e}")

    def handle_client(self, client_socket, addr):
        try:
            client_socket.send(self.public_key)
            print("[+] Public key sent to client")

            encrypted_credentials = client_socket.recv(4096)
            username, password = self.decrypt_credentials(encrypted_credentials)
            
            if self.authenticate_user(username, password):
                client_socket.send(b"SUCCESS")
                print(f"[+] User {username} authenticated successfully")
                
                encrypted_symmetric_key = client_socket.recv(4096)
                self.symmetric_key = decrypt_with_rsa(encrypted_symmetric_key, self.private_key)
                print("[+] Symmetric key received")
                print("[+] Waiting for commands...")
                
                while True:
                    try:
                        encrypted_command = client_socket.recv(4096)
                        if not encrypted_command:
                            print("[!] Connection closed by client")
                            break
                            
                        command = decrypt_with_aes(encrypted_command, self.symmetric_key)
                        print(f"[DEBUG] Received command: {command.decode()}")
                        
                        if command.decode() == 'quit':
                            print("[+] Client requested to quit")
                            break
                            
                        self.process_command(client_socket, command)
                    except Exception as e:
                        print(f"[!] Error processing command: {e}")
                        break
                    
            else:
                client_socket.send(b"FAIL")
                print(f"[!] Authentication failed for user {username}")
                
        except Exception as e:
            print(f"[!] Error handling client: {e}")
        finally:
            client_socket.close()
            print("[+] Client connection closed")

    def hash_password(self, password, salt):
        try:
            combined = (password + salt).encode('utf-8')
            hashed = hashlib.sha256(combined).hexdigest()
            return hashed
        except Exception as e:
            print(f"[DEBUG] Hashing error: {e}")
            return None

    def create_password_entry(username, password, salt):
        hash_value = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
        return f"{username}:{salt}:{hash_value}"

    def decrypt_credentials(self, encrypted_credentials):
        try:
            decrypted_data = decrypt_with_rsa(encrypted_credentials, self.private_key)
            username, password = decrypted_data.decode().split(':')
            return username, password
        except Exception as e:
            print(f"[DEBUG] Decryption error: {e}")
            return None, None

    def authenticate_user(self, username, password):
        try:
            with open('password.txt', 'r') as f:
                content = f.read()
                
                f.seek(0)
                for line in f:
                    stored_user, stored_salt, stored_hash = line.strip().split(':')
                    if username == stored_user:
                        test_hash = self.hash_password(password, stored_salt)
                        return test_hash == stored_hash
            return False
        except Exception as e:
            print(f"[DEBUG] Authentication error: {e}")
            return False

    def handle_commands(self, client_socket):
        while True:
            encrypted_command = client_socket.recv(4096)
            if not encrypted_command:
                break
                
            command = decrypt_with_aes(
                encrypted_command,
                self.symmetric_key
            ).decode()
            
            if command == 'quit':
                print("[+] Client requested to quit")
                break
            
            self.process_command(command, client_socket)


if __name__ == "__main__":
    server = FTPServer()
    server.start()