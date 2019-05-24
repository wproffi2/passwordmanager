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


    def addPassword(self, account, password):
        
        password = password.encode()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        enc = cipher.encryptor()
        ciphertext = enc.update(password) + enc.finalize()

        iv = hexlify(iv).decode()
        ciphertext = hexlify(ciphertext).decode()

        new_password = Passwords(Account=account, Password=ciphertext, IV=iv)
        db.session.add(new_password)
        db.session.commit()

        
        self.getPasswords()
        return(0)


    def getPasswords(self):
        decrypted_ls = []
        for password in Passwords.query.all():
            decrypted_data = {}
            
            account = password.Account
            epass = unhexlify(password.Password.encode())
            iv = unhexlify(password.IV.encode())
            print(password.Count)

            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
            dec = cipher.decryptor()
            dpass = (dec.update(epass) + dec.finalize()).decode().rstrip('#')
            
            decrypted_data['Account'] = account
            decrypted_data['Password'] = dpass
            decrypted_ls.append(decrypted_data)
        
        self.password_ls = decrypted_ls
        return(0)
    
    
#Pad the password
def PasswordPad(password):
    odd_password = ''
    if len(password) < 16:
        v = True
        while v:
            password += '#'
            if len(password) == 16:
                v = False

    elif len(password) > 16 and len(password) < 32:
        v = True
        while v:
            password += '#'
            if len(password) == 32:
                v = False
    
    elif len(password) > 32:
        for i in range(32):
            odd_password += password[i]
        password = odd_password
    return(password)
            




username = 'test'
password = username
user = User.query.filter_by(username=username).first()
salt = user.salt
salt = salt.encode()

test = NewManager(password, salt)
test.getPasswords()
print(test.password_ls)

"""
test_pass = PasswordPad('test')
test.addPassword('Test4', test_pass)
print(test.password_ls)
"""
