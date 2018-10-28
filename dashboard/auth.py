import jwt
from django.conf import settings
from django.http import HttpResponse
from rest_framework import exceptions
from rest_framework.authentication import get_authorization_header, BaseAuthentication

from back.dashboard.models import User

users = getattr(settings, "USERS", None)

class TokenAuthentication(BaseAuthentication):
    model = None

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'token':
            return None

        if len(auth) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid token header'
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1]
            if token == "null":
                msg = 'Null token not allowed'
                raise exceptions.AuthenticationFailed(msg)
        except UnicodeError:
            msg = 'Invalid token header. Token string should not contain invalid characters.'
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(token)

    def authenticate_credentials(self, token):
        payload = jwt.decode(token, "J_AIME_LES_CREVETTES?!??!")
        email = payload['email']
        userid = payload['id']
        msg = {'status':False,'Error': "Token mismatch"}
        try:

            user_col = users.find_one({"email":email})
            if not user_col:
                raise exceptions.AuthenticationFailed(msg)
            user=User()
            user.email=email
            user.id = userid



        except jwt.ExpiredSignature or jwt.DecodeError or jwt.InvalidTokenError:
            return HttpResponse({'Error': "Token is invalid",'status':False}, status="403")
        except:
            return HttpResponse({'Error': "Internal server error",'status':False}, status="500")

        return (user, token)

    def authenticate_header(self, request):
        return 'Token'
