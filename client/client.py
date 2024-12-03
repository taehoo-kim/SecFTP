import socket
from crypto_utils import (
    encrypt_with_rsa,
    decrypt_with_rsa,
    encrypt_with_aes,
    decrypt_with_aes,
    generate_symmetric_key
)

class FTPClient:
    def __init__(self):
        self.socket = None
        self.symmetric_key = None
        self.server_public_key = None
        
    def connect(self, host, port):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            print(f"[+] Connected to server {host}:{port}")
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
        
    def login(self, username, password):
        try:
            self.server_public_key = self.socket.recv(4096)
            
            credentials = f"{username}:{password}".encode()
            encrypted_credentials = encrypt_with_rsa(credentials, self.server_public_key)            
            self.socket.send(encrypted_credentials)
            
            response = self.socket.recv(1024)
            
            if response == b"SUCCESS":
                print("[+] Login successful")
                self.symmetric_key = generate_symmetric_key()
                encrypted_symmetric_key = encrypt_with_rsa(
                    self.symmetric_key,
                    self.server_public_key
                )
                self.socket.send(encrypted_symmetric_key)
                return True
            else:
                print("[!] Login failed")
                return False
                
        except Exception as e:
            print(f"[DEBUG] Login error details: {e}")
            return False

    def send_command(self, command):
        try:
            encrypted_command = encrypt_with_aes(
                command,
                self.symmetric_key
            )
            self.socket.send(encrypted_command)
            return True
        except Exception as e:
            print(f"[!] Error sending command: {e}")
            return False

    def send_file(self, local_path, remote_path):
        try:
            command = f"send {remote_path}".encode()
            encrypted_command = encrypt_with_aes(command, self.symmetric_key)
            self.socket.send(encrypted_command)
            print(f"[DEBUG] Send command sent for file: {local_path}")
            
            with open(local_path, 'rb') as f:
                data = f.read()
                print(f"[DEBUG] Read {len(data)} bytes from file")
            
            encrypted_data = encrypt_with_aes(data, self.symmetric_key)
            self.socket.send(encrypted_data)
            print(f"[DEBUG] Sent {len(encrypted_data)} bytes of encrypted data")
            
            print(f"[+] File {local_path} sent successfully")
            return True
        except Exception as e:
            print(f"[!] Error sending file: {e}")
            return False

    def receive_file(self, remote_path, local_path):
        try:
            command = f"recv {remote_path}"
            self.send_command(command)
            
            encrypted_data = self.socket.recv(4096)
            data = decrypt_with_aes(encrypted_data, self.symmetric_key)
            
            with open(local_path, 'wb') as f:
                f.write(data)
            print(f"[+] File received and saved as {local_path}")
            return True
        except Exception as e:
            print(f"[!] Error receiving file: {e}")
            return False

    def close(self):
        try:
            self.send_command("quit")
            self.socket.close()
            print("[+] Connection closed")
        except Exception as e:
            print(f"[!] Error closing connection: {e}")

def main():
    client = FTPClient()
    
    host = input("Enter server IP: ")
    port = int(input("Enter server port: "))
    
    if not client.connect(host, port):
        return
    
    username = input("Username: ")
    password = input("Password: ")
    
    if not client.login(username, password):
        client.close()
        return
    
    while True:
        command = input("\nEnter command (send/recv/quit): ").lower()
        
        if command == "quit":
            client.close()
            break
            
        elif command == "send":
            local_path = input("Enter source file path: ")
            remote_path = input("Enter destination path: ")
            client.send_file(local_path, remote_path)
            
        elif command == "recv":
            remote_path = input("Enter remote file path: ")
            local_path = input("Enter local save path: ")
            client.receive_file(remote_path, local_path)
            
        else:
            print("[!] Invalid command")

if __name__ == "__main__":
    main()