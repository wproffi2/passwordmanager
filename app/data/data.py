from binascii import hexlify, unhexlify
from passlib.hash import pbkdf2_sha256
import os


class Data:
    def __init__(self):
        self.cur_dir = os.path.dirname(os.path.realpath(__file__))
        self.salt = b''

    def WriteNewUser(self, username, password):
        salt = os.urandom(16)
        salt = hexlify(salt).decode()
        file_name = os.path.join(self.cur_dir, 'user')
        f = open(file_name, 'w')
        f.write(username)
        f.write('\n')
        f.write(password)
        f.close()
        return(0)

    def CheckUser(self, username, password):
        file_name = os.path.join(self.cur_dir, 'user')
        f = open(file_name, 'r')
        txt_user = f.readline()
        txt_password = f.readline()
        f.close()
        txt_user = txt_user.rstrip()

        if txt_user == username and pbkdf2_sha256.verify(password, txt_password):
            return(True)
        else:
            return(False)

    def GetSalt(self):
        file_name = os.path.join(self.cur_dir, 'salt')
        try:
            f = open(file_name, 'r')
            salt = f.readline()
            salt = salt.encode()
            salt = unhexlify(salt)
            return(salt)
        except Exception as e:
            print(e)

    def WriteSalt(self, salt):
        salt = hexlify(salt).decode()
        file_name = os.path.join(self.cur_dir, 'salt')
        f = open(file_name, 'w')
        f.write(salt)
        f.close()
        return(0)

