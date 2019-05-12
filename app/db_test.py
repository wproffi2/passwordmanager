from app import application, db
from models import User, Passwords
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from binascii import hexlify, unhexlify
from sqlalchemy import create_engine
from base64 import b64encode

import os, sys
#ps = Passwords.query.all()

class NewManager:
    def __init__(self, key, salt):
        self.backend = default_backend()
        self.salt = salt
        self.key = self.KeyBuild(key)
        self.password_ls = Passwords.query.all()


    def __repr__(self):
        return "{}\n{}".format(self.key, self.salt)

    #@staticmethod
    def KeyBuild(self, key):
        key = key.encode()
        hdkf = HKDF(
            algorithm = hashes.SHA512(),
            length = 32,
            salt = self.salt,
            info = None,
            backend = self.backend
        )
        key = hdkf.derive(key)
        return(key)


    def decrypt(self):
        decrypted_ls = []
        for password in self.password_ls:
            decrypted_data = {}
            
            account = password.Account
            epass = unhexlify(password.Password.encode())
            iv = unhexlify(password.IV.encode())

            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
            dec = cipher.decryptor()
            dpass = (dec.update(epass) + dec.finalize()).decode().rstrip('#')
            
            decrypted_data['Account'] = account
            decrypted_data['Password'] = dpass
            decrypted_ls.append(decrypted_data)
        
        self.password_ls = decrypted_ls
        return(0)
            
            




username = 'test'
password = username
user = User.query.filter_by(username=username).first()
salt = user.salt
salt = salt.encode()

test = NewManager(password, salt)
test.decrypt()