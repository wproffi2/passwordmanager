from app import application
from unittest import TestCase, main

class AppTestCase(TestCase):
    def setUp(self):
        self.app = application.test_client()

    #Ensures index is reachable
    def test_index(self):
        resp = self.app.get('/')
        self.assertEqual(resp.status_code, 200)
    

    #Ensures sign up works
    def test_signup_post(self):
        resp = self.app.post(
            '/login',
            data = dict(Username='test', Password='test', Confirm_Password='test'),
            follow_redirects=True
        )
        self.assertEqual(resp.status_code, 200)

    
    #Ensures login page is reachable
    def test_login_get(self):
        resp = self.app.get('/login')
        self.assertEqual(resp.status_code, 200)
    
    
    #Ensures login works
    def test_login_post(self):
        resp = self.app.post(
            '/login',
            data = dict(Username='test', Password='test'),
            follow_redirects=True
        )
        
        self.assertEqual(resp.status_code, 200)
    
    
    #Ensures main page is not reachable
    def test_main_get(self):
        resp = self.app.get('/main')
        self.assertEqual(resp.status_code, 401)
        


if __name__ == '__main__':
    main()