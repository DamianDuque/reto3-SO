import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json
import socket
import platform
from datetime import datetime
import base64

class FileEncryptor:
    def __init__(self, filename, key, output_filename, second_key, nfragments, fragments, newfilenames):
        self.filename = filename
        self.key = key
        self.output_filename = output_filename
        self.second_key = second_key
        self.nfragments = nfragments
        self.fragments = fragments
        self.newfilenames = newfilenames

    def encrypt(self):
        for i in range(len(self.newfilenames)):
            cipher = AES.new(self.key, AES.MODE_EAX)
            #with open(self.newfilenames[i], "rb") as file:
                #jsonData = json.load(file)
                #datatoencript = jsonData[str(i)]
                #print(datatoencript, type(datatoencript))
            with open(self.newfilenames[i], "rb") as file2:
                plaintext = file2.read()
                #print(plaintext[9:-3])
                datatoencript = plaintext[9:-3]
            
            ciphertext, tag = cipher.encrypt_and_digest(datatoencript)
            encfilename = self.newfilenames[i].split(".")
            
            b2key = bytes(self.second_key, 'utf-8')
            with open("encrypted/"+encfilename[0]+"enc.txt", 'wb') as file:
                file.write(cipher.nonce)
                file.write(tag)
                file.write(ciphertext)
                

        self.log_activity()

    def log_activity(self):
        ip = socket.gethostbyname(socket.gethostname())
        computer_name = platform.node()
        now = datetime.now()
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

        key_hex = self.key.hex()  # Convierte la clave en una cadena hexadecimal
        
        log_data = {
            'activity': 'ENCRYPTOR',
            'ip': ip,
            'computer_name': computer_name,
            'timestamp': timestamp,
            'key': key_hex,
            'second_key': self.second_key,
        }

        with open('activity_log.json', 'a') as log_file:
            log_file.write(json.dumps(log_data, indent=4) + "\n")

    def rebuild_file(self):
        for i in range(self.nfragments):
            fragmento= str(self.fragments[i])
            elementos= fragmento.split(' ')
            value = base64.b64decode(elementos[2])
            value = str(value)
            #print(value, type(value))
            newJson = {elementos[1]:value}
            
            with open(elementos[1]+".json", "w") as json_file:
                json.dump(newJson, json_file)
            self.newfilenames.append(elementos[1]+".json")
            print(self.newfilenames)
        
        self.encrypt()

    def fragmentar_archivo(self):
        file = open(self.filename, "rb")
        encoded_string = base64.b64encode(file.read())
        len_fragments = len(encoded_string) // self.nfragments
        i = 0
        self.fragments = {}
        while i < self.nfragments:
            if i == self.nfragments - 1:
                subs = encoded_string[len_fragments * i:]
            else:
                subs = encoded_string[len_fragments *
                                      i: len_fragments * (i + 1)]
            self.fragments[i] = (self.filename + " " + str(i) + " ").encode('utf-8') + subs
            i += 1

        self.rebuild_file()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 5:
        print("Uso: py encryption.py <archivo_a_encriptar> <archivo_encriptado> <segunda_llave> <nfragmentos>")
        sys.exit(1)

    filename = sys.argv[1]
    output_filename = sys.argv[2]
    key = get_random_bytes(16)
    second_key = sys.argv[3]
    nfragments = int(sys.argv[4])
    fragments = {}
    newfilenames = []

    encryptor = FileEncryptor(filename, key, output_filename, second_key, nfragments, fragments, newfilenames)
    encryptor.fragmentar_archivo()
