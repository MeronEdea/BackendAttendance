# import jwt

# # Your token
# token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzE1MDMzMDU1LCJpYXQiOjE3MTUwMjk0NTUsImp0aSI6ImYzNjZjMWZjM2QyOTQ2Mjc5YjM1MGQ2MGM3ZTQ3ZDdiIiwidXNlcl9pZCI6MX0.N67cj8vgQ3ttRUhMREwoMExGLLZeLVl4IJpQwAlBlz4"

# # Your secret key
# secret_key = "django-insecure-mqdda)7#)9nm(&+*9ko95-kp0o5pg$8mhor-%v63*d5_2rn&ps"

# try:
#     # Decode the token
#     decoded_token = jwt.decode(token, key=secret_key, algorithms=["HS256"])
    
#     # Print the decoded token
#     print(decoded_token)
# except jwt.exceptions.DecodeError as e:
#     print("Error decoding token:", e)
# except jwt.exceptions.InvalidSignatureError as e:
#     print("Invalid signature:", e)



import jwt
from datetime import datetime, timedelta
from django.test import TestCase

class AuthenticationTest(TestCase):

    def setUp(self):
        # Your secret key for encoding/decoding JWT
        self.secret_key = 'django-insecure-mqdda)7#)9nm(&+*9ko95-kp0o5pg$8mhor-%v63*d5_2rn&ps'

    def generate_token(self):
        payload = {
            'exp': datetime.utcnow() + timedelta(hours=1),  # Token expiration time
            'iat': datetime.utcnow(),                      # Token issuance time
            'sub': 'test_subject'                          # Subject of the token
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')

    def test_authentication(self):
        token = self.generate_token()
        decoded_token = jwt.decode(token, key=self.secret_key, algorithms=["HS256"])
        self.assertEqual(decoded_token['sub'], 'test_subject')
