from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from binascii import hexlify, unhexlify
from sqlalchemy import create_engine
from base64 import b64encode
import pandas
import os, sys

from app import db_uri, db
from models import User, Passwords

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


#Generate random password for user
def NewPass(size):
    size = int(size)
    for i in range(32):
        password = os.urandom(i)
        password = b64encode(password).decode()
        if len(password) >= size:
            break
    
    odd_password = ''
    if size % 2 != 0 and size < 44:
        for i in range(size):
            odd_password += password[i]
        password = odd_password
    
    password = PasswordPad(password)

    return(password)

class PasswordManager:
    def __init__(self, key, salt):
        self.backend = default_backend()
        self.salt = salt
        self.key = self.KeyBuild(key)
        self.password_ls = []

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

    def UpdateClass(self, key, salt):
        self.salt = salt
        key = self.KeyBuild(key)
        self.key = key
        self.UpdatePassList()
        return(0)

    def Encrypt(self, account, size = 0, password = ''):
        if password == '' and size != 0:
            password = NewPass(size)
        else:
            password = PasswordPad(password)
        
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

        self.UpdatePassList()

        return(0)

    def UpdatePassList(self):
        engine = create_engine(db_uri)
        data_frame = pandas.read_sql(sql = 'SELECT * FROM passwords', con=engine)
        enc_password_ls = data_frame.to_dict('records')

        dec_ls = []
        for d in enc_password_ls:
            dec_data = {}
            account = d['Account']
            enc_pass = d['Password']
            iv = d['IV']
            
            iv = iv.encode()
            iv = unhexlify(iv)
            enc_pass = enc_pass.encode()
            enc_pass = unhexlify(enc_pass)

            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
            dec = cipher.decryptor()
            pt = dec.update(enc_pass) + dec.finalize()

            dec_data['Account'] = account
            dec_data['Password'] = pt.decode()
            dec_ls.append(dec_data)

        for d in dec_ls:
            d['Password'] = d['Password'].rstrip('#')
        
        self.password_ls = dec_ls
        return(0)

    def PasswordDelete(self, account):
        Passwords.query.filter_by(Account=account).delete()
        db.session.commit()
        self.UpdatePassList()
        return(0)
    
    def PasswordUpdate(self, account):
        self.PasswordDelete(account)
        self.Encrypt(account)
        return(0)
