try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from binascii import hexlify, unhexlify
    from flask_sqlalchemy import SQLAlchemy
    from passlib.hash import pbkdf2_sha256
    from sqlalchemy import create_engine
    from base64 import b64encode
    from threading import Thread
    from time import sleep
    import webbrowser
    import sys, os
    import pandas

    from flask import (
        Flask, render_template, request, 
        redirect, url_for, json, 
        jsonify, make_response
    )
    from flask_jwt_extended import (
        JWTManager, jwt_required, create_access_token, 
        get_jwt_identity, current_user, get_jwt_claims, 
        verify_jwt_in_request, create_refresh_token, 
        jwt_refresh_token_required, set_access_cookies,
        unset_jwt_cookies
    )

except Exception as e:
    print(e)
    sleep(10)



db_name = 'app.db'

if getattr(sys, 'frozen', False):
    cur_dir = os.path.dirname(sys.executable)
    cur_dir = cur_dir + '\\' + db_name
        
else:
    cur_dir = os.path.join(os.path.dirname(__file__), db_name)

db_uri = 'sqlite:///{}'.format(cur_dir)

#template_folder = os.path.join(sys._MEIPASS, 'templates')
#application = Flask(__name__, template_folder=template_folder)
application = Flask(__name__)
application.config['JWT_SECRET_KEY'] = str(os.urandom(16))
application.config['JWT_TOKEN_LOCATION'] = ['cookies']
application.config['JWT_COOKIE_CSRF_PROTECT'] = False
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{}'.format(db_name)
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

jwt = JWTManager(application)
db = SQLAlchemy(application)


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


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(500), unique=True, nullable=False)
    salt = db.Column(db.String(500), unique=True, nullable=False)


class Passwords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Account = db.Column(db.String(80), unique=True, nullable=False)
    Password = db.Column(db.String(500), unique=True, nullable=False)
    IV = db.Column(db.String(500), unique=True, nullable=False)


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

pass_manager = PasswordManager(key='not_real_key', salt=b'not_real_salt')

def CloseApp():
    #Closes Application
    sleep(0.5)
    os._exit(1)
    return(0)


#Displays the index page containing options for 
#New User, Login, and Shutdown
@application.route('/', methods = ['POST', 'GET'])
def Index():
    if request.method == 'POST':
        if request.form['login'] == 'New User':
            return(redirect(url_for('SignUp')))
        elif request.form['login'] == 'Login':
            return(redirect(url_for('Login')))
        elif request.form['login'] == 'Shutdown':
            return(redirect(url_for('Shutdown')))
    
    elif request.method == 'GET':
        return(render_template('index.html'))


#Displays the main page containnig options for 
#New Password, View Passwords, Update Password
#Delete Password, and Logout
@application.route('/main', methods = ['POST', 'GET'])
@jwt_required
def Main():
    if request.method == 'POST':
        if request.form['pass'] == 'New Password':
            return(redirect(url_for('NewPassword')))
        
        elif request.form['pass'] == "Add Password":
            return(redirect(url_for('AddPassword')))

        elif request.form['pass'] == "View Passwords":
            return(redirect(url_for('PasswordDisplay')))

        elif request.form['pass'] == "Update Password":
            return(redirect(url_for('UpdatePassword')))
        
        elif request.form['pass'] == "Delete Password":
            return(redirect(url_for('DeletePassword')))

        elif request.form['pass'] == "Logout":
            return(redirect(url_for('Logout')))
        
    elif request.method == 'GET':
        return(render_template('main.html'))


#Displays the login page
@application.route('/login', methods = ['POST', 'GET'])
def Login():
    if request.method == 'GET':
        return(render_template('login.html'))
    elif request.method == 'POST':
        username = request.form['Username']
        password = request.form['Password']
        
        try:
            db_user = User.query.filter_by(username=username).first()
        except:
            print('No User Found') #404 Page here

        if db_user.username == username and pbkdf2_sha256.verify(password, db_user.password):
            salt = db_user.salt
            salt = salt.encode()
            pass_manager.UpdateClass(password, salt)

            access_token = create_access_token(identity=username)
            resp = make_response(redirect(url_for('Main')))
            set_access_cookies(resp, access_token)
            
            return(resp)
        else:
            return(render_template('login.html'))


#Displays the sign up page for new users
@application.route('/signup', methods = ['POST', 'GET'])
def SignUp():
    if request.method == 'GET':
        return(render_template('signup.html'))
    elif request.method == 'POST':
        username = request.form['Username']
        password = request.form['Password']
        confirm_password = request.form['Confirm_Password']
        if confirm_password != password:
            return(redirect(url_for('SignUp')))
        else:
            password = pbkdf2_sha256.hash(password)
            salt = os.urandom(16)
            salt = hexlify(salt).decode()

            user = User(username=username, password=password, salt=salt)

            db.session.add(user)
            db.session.commit()

            return(redirect(url_for('Login')))
    return(0)


#Displays the shutdown page and closes the app
@application.route('/shutdown')
def Shutdown():
    resp = make_response(render_template('shutdown.html'))
    
    #creates new thread for CloseApp function
    t = Thread(target=CloseApp)
    t.daemon = True
    t.start()

    #returns shutdown template
    return(resp)   
    

#Displays the logout page and closes the app
@application.route('/logout')
def Logout():
    #removes users cookies
    resp = make_response(render_template('logout.html'))
    unset_jwt_cookies(resp)
    
    t = Thread(target=CloseApp)
    t.daemon = True
    t.start()    
    return(resp)


#Displays the newpassword page
@application.route('/newpassword', methods = ['POST', 'GET'])
@jwt_required
def NewPassword():
    if request.method == 'POST':
        account = request.form['account'] #account name
        size = request.form['size'] #requested password size 
         
        pass_manager.Encrypt(account, size)#create new password
        return(redirect(url_for('Main')))

    elif request.method == 'GET':
        return(render_template('newpassword.html'))


#Displays the update page
#Currently does nothning
@application.route('/update', methods = ['POST', 'GET'])
@jwt_required
def UpdatePassword():
    data = pass_manager.password_ls
    if request.method == 'POST':
        
        account = request.form['account']
        pass_manager.PasswordUpdate(account)
        return(redirect(url_for('Main')))

    elif request.method == 'GET':
        #data = pass_store.password_ls
        return(render_template('update.html', data=data))


#Will display add page
@application.route('/add', methods = ['POST', 'GET'])
@jwt_required
def AddPassword():
    if request.method == 'GET':
        return(render_template('addpassword.html'))
    
    elif request.method == 'POST':
        account = request.form['Account']
        password = request.form['Password']
        confirm_password = request.form['Confirm Password']
        if confirm_password != password:
            return(redirect(url_for('AddPassword')))
        else:
            #pass_store.Encrypt(account, 0, password)
            pass_manager.Encrypt(account, 0, password)
            return(redirect(url_for('Main')))

    return(0)


#Displays the delete page
@application.route('/delete', methods = ['POST', 'GET'])
@jwt_required
def DeletePassword():
    data = pass_manager.password_ls
    if request.method == 'POST':
        #data = pass_store.password_ls
        account = request.form['account']
        pass_manager.PasswordDelete(account)

        return(redirect(url_for('Main')))

    elif request.method == 'GET':
        return(render_template('delete.html', data=data))


#Displays the password page
@application.route('/passwords', methods = ['POST', 'GET'])
@jwt_required
def PasswordDisplay():
    if request.method == 'POST':
        if request.form['pass'] == "Logout":
            return(redirect(url_for('Logout')))
    
    elif request.method == 'GET':
        data = pass_manager.password_ls
        return render_template('passwords.html', data=data)


#Opens Webbrowser and 
#directs it to localhost on port 5000
def OpenLocalHost():
    sleep(0.5)
    url = 'http://127.0.0.1:5000/'
    webbrowser.open_new(url)
    return(0)


if __name__ == '__main__':
    try:
        db.create_all()
        #Creates new thread to open app
        t = Thread(target=OpenLocalHost)
        t.daemon = True
        t.start()
        application.run(debug=False) #Run Flask 
    except Exception as e:
        print(e)
        sleep(10)