from binascii import hexlify, unhexlify
from passlib.hash import pbkdf2_sha256
from threading import Thread
from time import sleep
import os

from flask_login import login_user

from flask import (
    render_template, request, 
    redirect, url_for, json, 
    jsonify, make_response, session
)

from app import application, db, login_manager
from models import User, Passwords
from pm import PasswordManager


@login_manager.user_loader
def load_user(user_id):
    return None

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
            login_user(db_user)
            salt = db_user.salt
            salt = salt.encode()
            pass_manager = PasswordManager(password, salt)
            
            #This is not secure, I plan on updating this in the near future
            session['key'] = password
            session['salt'] = salt
            #session['pass_manager'] = pass_manager

            #access_token = create_access_token(identity=username)
            resp = make_response(redirect(url_for('Main')))
            #set_access_cookies(resp, access_token)
            
            return(resp)
        else:
            return(render_template('login.html'))


#Displays the main page containnig options for 
#New Password, View Passwords, Update Password
#Delete Password, and Logout
@application.route('/main', methods = ['POST', 'GET'])
#@jwt_required
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


#Displays the newpassword page
@application.route('/newpassword', methods = ['POST', 'GET'])
#@jwt_required
def NewPassword():
    if request.method == 'POST':
        account = request.form['account'] #account name
        size = request.form['size'] #requested password size 
        
        pass_manager = PasswordManager(session['key'], session['salt'])
        pass_manager.addPassword(account=account, size=size)#create new password
        

        return(redirect(url_for('Main')))

    elif request.method == 'GET':
        return(render_template('newpassword.html'))



#Will display add page
@application.route('/add', methods = ['POST', 'GET'])
#@jwt_required
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
            pass_manager = PasswordManager(session['key'], session['salt'])
            pass_manager.addPassword(account, password)
            
            return(redirect(url_for('Main')))

    return(0)


#Displays the delete page
@application.route('/delete', methods = ['POST', 'GET'])
#@jwt_required
def DeletePassword():
    pass_manager = PasswordManager(session['key'], session['salt'])
    data = pass_manager.getPasswords()

    if request.method == 'POST':
        account = request.form['account']
        pass_manager.deletePassword(account)
        
        return(redirect(url_for('Main')))

    elif request.method == 'GET':
        return(render_template('delete.html', data=data))


#Displays the password page
@application.route('/passwords', methods = ['POST', 'GET'])
#@jwt_required
def PasswordDisplay():
    if request.method == 'POST':
        if request.form['pass'] == "Logout":
            return(redirect(url_for('Logout')))
    
    elif request.method == 'GET':
        
        pass_manager = PasswordManager(session['key'], session['salt'])
        data = pass_manager.getPasswords()

        return render_template('passwords.html', data=data)


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
    
    
    t = Thread(target=CloseApp)
    t.daemon = True
    t.start()    
    return(resp)


