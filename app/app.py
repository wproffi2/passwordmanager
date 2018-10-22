from passlib.hash import pbkdf2_sha256
from threading import Thread
from time import sleep
import webbrowser
import sys, os

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

#app files
from data.encryption import PasswordStorage
from data.data import Data

key = 'not_real_key' #temp key for pass_store
pass_store = PasswordStorage(key) 
data = Data()

application = Flask(__name__)
application.config['JWT_SECRET_KEY'] = str(os.urandom(16))
application.config['JWT_TOKEN_LOCATION'] = ['cookies']
application.config['JWT_COOKIE_CSRF_PROTECT'] = False
jwt = JWTManager(application)


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
        check = data.CheckUser(username, password)
        if check:
            pass_store.UpdateKey(password)
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
        confirm_password = request.form['Confirm Password']
        if confirm_password != password:
            return(redirect(url_for('SignUp')))
        else:
            password = pbkdf2_sha256.hash(password)
            data.WriteNewUser(username, password)

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
        
        pass_store.Encrypt(account, size) #create new password
        return(redirect(url_for('Main')))

    elif request.method == 'GET':
        return(render_template('newpassword.html'))


#Displays the update page
#Currently does nothning
@application.route('/update', methods = ['POST', 'GET'])
@jwt_required
def UpdatePassword():
    if request.method == 'POST':
        data = pass_store.password_ls
        account = request.form['account']
        for d in data:
            if account == d['Account']:
                print(True)
        return(redirect(url_for('Main')))

    elif request.method == 'GET':
        data = pass_store.password_ls
        return(render_template('update.html', data=data))


#Will display add page
#Currently does nothing 
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
            pass_store.Encrypt(account, 0, password)
            return(redirect(url_for('Main')))

    return(0)


#Displays the delete page
#Currently does nothing 
@application.route('/delete', methods = ['POST', 'GET'])
@jwt_required
def DeletePassword():
    if request.method == 'POST':
        data = pass_store.password_ls
        account = request.form['account']
        
        pass_store.DeletePassword(account)

        return(redirect(url_for('Main')))

    elif request.method == 'GET':
        data = pass_store.password_ls
        return(render_template('delete.html', data=data))


#Displays the password page
@application.route('/passwords', methods = ['POST', 'GET'])
@jwt_required
def PasswordDisplay():
    if request.method == 'POST':
        if request.form['pass'] == "Logout":
            return(redirect(url_for('Logout')))
    
    elif request.method == 'GET':
        data = pass_store.password_ls
        return render_template('passwords.html', data=data)


def OpenLocalHost():
    sleep(0.5)
    url = 'http://127.0.0.1:5000/'
    webbrowser.open_new(url)
    return(0)


if __name__ == '__main__':
    t = Thread(target=OpenLocalHost)
    t.daemon = True
    t.start()
    application.run(debug=False)