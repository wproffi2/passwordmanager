from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from binascii import hexlify, unhexlify
from passlib.hash import pbkdf2_sha256
from base64 import b64encode
from pandas import DataFrame
import os, string, random
import pandas


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


#Builds Crypto key
#Crypto key is generated from the users password
def KeyBuild(key, backend, salt):
    
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



#class for encrypting, decrypting, and storing passwords,
#ivs, and accound names
#Passwords are stored in a list of dictionaries for easy
#compatability with pandas
class PasswordStorage:

    def __init__(self, key):
        self.cur_dir = os.path.dirname(os.path.realpath(__file__))
        #path to csv file where passwords are stored
        self.csv_file = os.path.join(self.cur_dir, 'passwords.csv') 
        #cryptography backend
        self.backend = default_backend()
        #cryptography key
        self.key = KeyBuild(key, self.backend, b'')
        #empty password list, will be update
        #with proper key
        self.password_ls = []


    #Update the key once user logs in
    def UpdateKey(self, key):
        key = KeyBuild(key, self.backend, self.salt)
        self.key = key
        self.UpdateList()
        return(0)


    #update the password list whenever need be
    def UpdateList(self):
        self.password_ls = self.Decrypt()
        return(0)


    #Delete Password chosen by user
    def DeletePassword(self, account):
        del_pos = None
        #get passwords
        pass_data = pandas.read_csv(self.csv_file)
        pass_list = pass_data.to_dict('records')
        
        #search for account
        for i, d in enumerate(pass_list):
            if account == d['Account']:
                del_pos = i
                break
        
        if del_pos != None:
            pass_list.pop(del_pos)
        
        #Rewrite passwords to csv file
        if pass_list != []:
            pass_data = DataFrame()
            pass_data = pass_data.append(pass_list)
            pass_data.to_csv(self.csv_file, mode= 'w', header=True, index=False)
        
        self.UpdateList()
        return(0)


    #Encrypt password, either provided by user
    #or randomly generated. 
    #New Password is then added to csv file
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
        
        pass_dict = {'Account': account, 'Password': ciphertext, 'IV': iv}
        pass_ls = [pass_dict]
        pass_data = DataFrame()
        pass_data = pass_data.append(pass_ls)
        pass_data.to_csv(self.csv_file, mode= 'a', header=True, index=False)
        
        self.UpdateList()
        
        return(0)


    #Decrypt all passwords and returns the list of dictionaries
    def Decrypt(self):
        dec_ls = []
        try:
            pass_data = pandas.read_csv(self.csv_file)
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
            #if anything goes wrong, return empty list
            return(dec_ls)
            
    def WriteNewUser(self, username, password):
        salt = os.urandom(16)
        salt = hexlify(salt).decode()
        file_name = os.path.join(self.cur_dir, 'user')
        f = open(file_name, 'w')
        
        f.write(username)
        f.write('\n')
        
        f.write(password)
        f.write('\n')

        f.write(salt)
        f.close()
        return(0)

    def CheckUser(self, username, password):
        file_name = os.path.join(self.cur_dir, 'user')
        f = open(file_name, 'r')
        txt_user = f.readline()
        txt_password = f.readline()
        salt = f.readline()
        f.close()
        
        txt_user = txt_user.rstrip()
        txt_password = txt_password.rstrip()
        salt = salt.encode()
        self.salt = salt

        if txt_user == username and pbkdf2_sha256.verify(password, txt_password):
            return(True)
        else:
            return(False)