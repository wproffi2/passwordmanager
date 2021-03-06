from binascii import hexlify, unhexlify
from passlib.hash import pbkdf2_sha256
from threading import Thread
from time import sleep
import os

from flask_login import login_user, login_required

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
    return User.query.get(int(user_id))

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
    try:
        if request.method == 'GET':
            return(render_template('login.html'))
        
        elif request.method == 'POST':
            username = request.form['Username']
            password = request.form['Password']
            
            db_user = User.query.filter_by(username=username).first()

            if db_user.username == username and pbkdf2_sha256.verify(password, db_user.password):
                login_user(db_user)
                salt = db_user.salt
                salt = salt.encode()
                pass_manager = PasswordManager(password, salt)
                
                session['key'] = password
                session['salt'] = salt

                resp = make_response(redirect(url_for('Main')))
                
                return(resp)
            else:
                return(render_template('login.html'))
    
    except Exception as e:
        error = str(e)
        return render_template('error.html', error=error)

#Displays the main page containnig options for 
#New Password, View Passwords, Update Password
#Delete Password, and Logout
@application.route('/main', methods = ['POST', 'GET'])
@login_required
def Main():
    try:
    
        if request.method == 'POST':
            #redirect to another function using button value
            return(redirect(url_for(request.form['pass'])))
            
        elif request.method == 'GET':
            return(render_template('main.html'))
    
    except Exception as e:
        error = str(e)
        return render_template('error.html', error=error)

#Displays the newpassword page
@application.route('/newpassword', methods = ['POST', 'GET'])
@login_required
def newPassword():
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
@login_required
def addPassword():
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
@login_required
def deletePassword():
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
@login_required
def displayPasswords():
    if request.method == 'POST':
        if request.form['pass'] == "Logout":
            return(redirect(url_for('logout')))
    
    elif request.method == 'GET':
        
        pass_manager = PasswordManager(session['key'], session['salt'])
        data = pass_manager.getPasswords()

        return render_template('passwords.html', data=data)


#Displays the sign up page for new users
@application.route('/signup', methods = ['POST', 'GET'])
def SignUp():
    try:
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
    except Exception as e:
        error = str(e)
        return render_template('error.html', error=error)
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
@login_required
def logout():
    #removes users cookies
    resp = make_response(render_template('logout.html')) 
    
    
    t = Thread(target=CloseApp)
    t.daemon = True
    t.start()    
    return(resp)


