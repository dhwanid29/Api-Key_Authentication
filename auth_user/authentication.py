import codecs
from tokenize import TokenError

import jwt
from rest_framework import HTTP_HEADER_ENCODING
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.settings import api_settings
from auth_user.models import User
# AUTH_HEADER_TYPES = ('Api-Key',)


class ApiAuth(JWTAuthentication):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.AUTH_HEADER_TYPES = None

    def get_header(self, request):
        """
        Extracts the header containing the JSON web token from the given
        request.
        """
        print('get header 23')
        try:
            get_authorization = request.META['HTTP_AUTHORIZATION']
            # print(len(get_authorization.split(',')), 'wowo')
            auth = get_authorization.split()[0]
            print(auth, "kkk")
            #
            # if len(get_authorization.split(',')) == 2:
            #     raise ValidationError("hjj")
            if auth == 'Bearer':
                print('ifff')
                self.AUTH_HEADER_TYPES = ('Bearer',)
            else:
                print('elsee')
                self.AUTH_HEADER_TYPES = ('Api-Key',)
        except:
            raise ValidationError("Authentication credentials are required.")
        header = request.META.get(api_settings.AUTH_HEADER_NAME)
        print(header, "HEADER")

        if isinstance(header, str):
            # Work around django test client oddness
            header = header.encode(HTTP_HEADER_ENCODING)
            print(header, 'HEADER')

        return header

    def get_raw_token(self, header):
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        print('get raw token 39')
        parts = header.split()
        print(parts, "PARTS")

        if len(parts) == 0:
            return None
        AUTH_HEADER_TYPE_BYTES = {h.encode(HTTP_HEADER_ENCODING) for h in self.AUTH_HEADER_TYPES}

        print(AUTH_HEADER_TYPE_BYTES, "ll")

        if parts[0] not in AUTH_HEADER_TYPE_BYTES:
            print('inside if')
            # Assume the header does not contain a JSON web token
            return None

        if len(parts) != 2:
            raise AuthenticationFailed(
                _("Authorization header must contain two space-delimited values"),
                code="bad_authorization_header",
            )

        return parts[1]


    def get_validated_token(self, header):
        """
        Validates an encoded JSON web token and returns a validated token
        wrapper object.
        """
        print('get validated token 67')
        print(self.AUTH_HEADER_TYPES, "hahha")
        print('headersssssssssssssssss', str(header, 'UTF-8'))
        if self.AUTH_HEADER_TYPES[0] == 'Bearer':
            messages = []
            for AuthToken in api_settings.AUTH_TOKEN_CLASSES:
                try:
                    return AuthToken(header)
                except TokenError as e:
                    messages.append(
                        {
                            "token_class": AuthToken.__name__,
                            "token_type": AuthToken.token_type,
                            "message": e.args[0],
                        }
                    )

            raise InvalidToken(
                {
                    "detail": _("Given token not valid for any token type"),
                    "messages": messages,
                }
            )
        elif self.AUTH_HEADER_TYPES[0] == 'Api-Key':
            return header

    def get_user(self, header):
        """
        Attempts to find and return a user using the given validated token.
        """
        if self.AUTH_HEADER_TYPES[0] == 'Bearer':

            print("eloooo")
            try:
                user_id = header[api_settings.USER_ID_CLAIM]
            except KeyError:
                raise InvalidToken(_("Token contained no recognizable user identification"))

            try:
                user = self.user_model.objects.get(**{api_settings.USER_ID_FIELD: user_id})
            except self.user_model.DoesNotExist:
                raise AuthenticationFailed(_("User not found"), code="user_not_found")

            if not user.is_active:
                raise AuthenticationFailed(_("User is inactive"), code="user_inactive")

            return user
        elif self.AUTH_HEADER_TYPES[0] == 'Api-Key':
            print(header, "jiijijji")

            print("get user 95")
            key = header.split()
            api_key = str(key[0], 'UTF-8')
            print(api_key, 'keyy')

            print(str(key), "keuyyyyyyyyyyyyyy")
            try:
                user_id = User.objects.filter(api_key=api_key).first()

            except:
                raise ValidationError("Key contained no recognizable user identification")

            try:
                user = self.user_model.objects.get(**{api_settings.USER_ID_FIELD: user_id.id})
                print(user, "USER")
            except self.user_model.DoesNotExist:
                raise AuthenticationFailed(_("User not found"), code="user_not_found")

            if not user.is_active:
                raise AuthenticationFailed(_("User is inactive"), code="user_inactive")
            print('hie', user)
            return user


#
# class ApiAuth(JWTAuthentication):
#
#     def __init__(self, *args, **kwargs):
#         super().__init__(*args, **kwargs)
#         self.AUTH_HEADER_TYPES = None
#
#     def get_header(self, request):
#         """
#         Extracts the header containing the JSON web token from the given
#         request.
#         """
#         print('get header 23')
#         try:
#             get_authorization = request.META['HTTP_AUTHORIZATION']
#             # print(len(get_authorization.split(',')), 'wowo')
#             auth = get_authorization.split()[0]
#             print(auth, "kkk")
#             #
#             # if len(get_authorization.split(',')) == 2:
#             #     raise ValidationError("hjj")
#             if auth == 'Bearer':
#                 print('ifff')
#                 self.AUTH_HEADER_TYPES = ('Bearer',)
#             else:
#                 print('elsee')
#                 self.AUTH_HEADER_TYPES = ('Api-Key',)
#         except:
#             raise ValidationError("Authentication credentials are required.")
#         header = request.META.get(api_settings.AUTH_HEADER_NAME)
#         print(header, "HEADER")
#
#         if isinstance(header, str):
#             # Work around django test client oddness
#             header = header.encode(HTTP_HEADER_ENCODING)
#             print(header, 'HEADER')
#
#         return header
#
#     def get_raw_token(self, header):
#         """
#         Extracts an unvalidated JSON web token from the given "Authorization"
#         header value.
#         """
#         print('get raw token 39')
#         parts = header.split()
#         print(parts, "PARTS")
#
#         if len(parts) == 0:
#             return None
#         AUTH_HEADER_TYPE_BYTES = {h.encode(HTTP_HEADER_ENCODING) for h in self.AUTH_HEADER_TYPES}
#
#         print(AUTH_HEADER_TYPE_BYTES, "ll")
#
#         if parts[0] not in AUTH_HEADER_TYPE_BYTES:
#             print('inside if')
#             # Assume the header does not contain a JSON web token
#             return None
#
#         if len(parts) != 2:
#             raise AuthenticationFailed(
#                 _("Authorization header must contain two space-delimited values"),
#                 code="bad_authorization_header",
#             )
#
#         return parts[1]
#
#
#     def get_validated_token(self, header):
#         """
#         Validates an encoded JSON web token and returns a validated token
#         wrapper object.
#         """
#         print('get validated token 67')
#         print(self.AUTH_HEADER_TYPES, "hahha")
#         print('headersssssssssssssssss', str(header, 'UTF-8'))
#         if self.AUTH_HEADER_TYPES[0] == 'Bearer':
#             messages = []
#             for AuthToken in api_settings.AUTH_TOKEN_CLASSES:
#                 try:
#                     return AuthToken(header)
#                 except TokenError as e:
#                     messages.append(
#                         {
#                             "token_class": AuthToken.__name__,
#                             "token_type": AuthToken.token_type,
#                             "message": e.args[0],
#                         }
#                     )
#
#             raise InvalidToken(
#                 {
#                     "detail": _("Given token not valid for any token type"),
#                     "messages": messages,
#                 }
#             )
#         elif self.AUTH_HEADER_TYPES[0] == 'Api-Key':
#             return header
#
#     def get_user(self, header):
#         """
#         Attempts to find and return a user using the given validated token.
#         """
#         if self.AUTH_HEADER_TYPES[0] == 'Bearer':
#
#             print("eloooo")
#             try:
#                 user_id = header[api_settings.USER_ID_CLAIM]
#             except KeyError:
#                 raise InvalidToken(_("Token contained no recognizable user identification"))
#
#             try:
#                 user = self.user_model.objects.get(**{api_settings.USER_ID_FIELD: user_id})
#             except self.user_model.DoesNotExist:
#                 raise AuthenticationFailed(_("User not found"), code="user_not_found")
#
#             if not user.is_active:
#                 raise AuthenticationFailed(_("User is inactive"), code="user_inactive")
#
#             return user
#         elif self.AUTH_HEADER_TYPES[0] == 'Api-Key':
#             print(header, "jiijijji")
#
#             print("get user 95")
#             key = header.split()
#             api_key = str(key[0], 'UTF-8')
#             print(api_key, 'keyy')
#
#             print(str(key), "keuyyyyyyyyyyyyyy")
#             try:
#                 user_id = User.objects.filter(api_key=api_key).first()
#
#             except:
#                 raise ValidationError("Key contained no recognizable user identification")
#
#             try:
#                 user = self.user_model.objects.get(**{api_settings.USER_ID_FIELD: user_id.id})
#                 print(user, "USER")
#             except self.user_model.DoesNotExist:
#                 raise AuthenticationFailed(_("User not found"), code="user_not_found")
#
#             if not user.is_active:
#                 raise AuthenticationFailed(_("User is inactive"), code="user_inactive")
#             print('hie', user)
#             return user