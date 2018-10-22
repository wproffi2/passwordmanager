from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from binascii import hexlify, unhexlify
from base64 import b64encode
from pandas import DataFrame
import os, string, random
import pandas

#app files
from .data import Data


#Pad the password
def PasswordPadd(password):
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
    
    password = PasswordPadd(password)

    return(password)


def KeyBuild(key, backend):
    data = Data()

    salt = data.GetSalt()
    if salt == b'' or salt == '':
        salt = os.urandom(16)
        data.WriteSalt(salt)
    
    key = key.encode()
    
    hdkf = HKDF(
        algorithm = hashes.SHA512(),
        length = 32,
        salt = salt,
        info = None,
        backend = backend
    )
    key = hdkf.derive(key)
    return(key)



class PasswordStorage:
    def __init__(self, key):
        cur_dir = os.path.dirname(os.path.realpath(__file__))
        self.file_name = os.path.join(cur_dir, 'passwords.csv')
        self.backend = default_backend()
        self.key = KeyBuild(key, self.backend)
        self.password_ls = []


    def UpdateKey(self, key):
        key = KeyBuild(key, self.backend)
        self.key = key
        self.UpdateList()
        return(0)


    def UpdateList(self):
        self.password_ls = self.Decrypt()
        return(0)


    def DeletePassword(self, account):
        
        del_pos = None
        
        pass_data = pandas.read_csv(self.file_name)
        pass_list = pass_data.to_dict('records')
        for i, d in enumerate(pass_list):
            if account == d['Account']:
                del_pos = i
                break
        
        if del_pos != None:
            pass_list.pop(del_pos)
        
        if pass_list != []:
            pass_data = DataFrame()
            pass_data = pass_data.append(pass_list)
            pass_data.to_csv(self.file_name, mode= 'w', header=True, index=False)
        
        self.UpdateList()
        return(0)


    def Encrypt(self, account, size = 0, password = ''):
        
        if password == '' and size != 0:
            password = NewPass(size)
        else:
            password = PasswordPadd(password)
        
        password = password.encode()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        enc = cipher.encryptor()
        ciphertext = enc.update(password) + enc.finalize()
        
        iv = hexlify(iv).decode()
        ciphertext = hexlify(ciphertext).decode()
        
        pass_dict = {'Account': account, 'Password': ciphertext, 'IV': iv}
        pass_ls = [pass_dict]
        pass_data = DataFrame()
        pass_data = pass_data.append(pass_ls)
        pass_data.to_csv(self.file_name, mode= 'a', header=True, index=False)
        
        self.UpdateList()
        
        return(0)


    def Decrypt(self):
        dec_ls = []
        try:
            pass_data = pandas.read_csv(self.file_name)
            pass_list = pass_data.to_dict('records')
            
            for d in pass_list:
                dec_data = {}
                if d['Account'] != 'Account' and d['IV'] != 'IV' and d['Password'] != 'Password':
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

            return(dec_ls)
        except:
            return(dec_ls)
            
