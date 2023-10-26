from Crypto.Cipher import AES
import json
import socket
import platform
from datetime import datetime

class FileDecryptor:
    def __init__(self, encrypted_filename, key, output_filename, second_key):
        self.encrypted_filename = encrypted_filename
        self.key = key
        self.output_filename = output_filename
        self.second_key = second_key

    def decrypt(self):
        with open(self.encrypted_filename, 'rb') as file:
            nonce = file.read(16)
            tag = file.read(16)
            ciphertext = file.read()

        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)

        with open(self.output_filename, 'wb') as file:
            file.write(plaintext)

        self.log_activity()

    def log_activity(self):
        ip = socket.gethostbyname(socket.gethostname())
        computer_name = platform.node()
        now = datetime.now()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

        log_data = {
            'activity': 'DESENCRYPTOR',
            'ip': ip,
            'computer_name': computer_name,
            'timestamp': timestamp,
            'second_key': self.second_key,
        }

        with open('activity_log.json', 'a') as log_file:
            log_file.write(json.dumps(log_data, indent=4) + "\n")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 5:
        print("Uso: python decryption.py <archivo_encriptado> <archivo_desencriptado> <clave> <segunda_llave>")
        sys.exit(1)

    encrypted_filename = sys.argv[1]
    output_filename = sys.argv[2]
    key = bytes.fromhex(sys.argv[3])  # Convertir la clave en bytes desde una representación hexadecimal
    second_key = sys.argv[4]

    decryptor = FileDecryptor(encrypted_filename, key, output_filename, second_key)
    decryptor.decrypt()
