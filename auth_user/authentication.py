from datetime import date
from rest_framework import HTTP_HEADER_ENCODING
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.settings import api_settings
from auth_user.models import UserApiKey


class ApiAuth(JWTAuthentication):
    """
    Overrode JWTAuthentication Middleware
    This class Fetches the header whether it be Authorization or Api-Key, If the header is something else other than
    these two then it throws error, else the Token or Api-Key is verified. If the user enters both Token and Api-Key,
    then authorization takes place using the token.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.AUTH_HEADER_TYPES = None
        self.auth_prefix = None
        self.header = None

    def get_header(self, request):
        """
        Extracts the header containing the JSON web token from the given
        request.
        """

        get_authorization = request.META.get('HTTP_AUTHORIZATION')
        get_authorization_key = request.META.get('HTTP_X_API_KEY')

        if get_authorization:
            self.auth_prefix = get_authorization.split()[0].lower()
            if self.auth_prefix == 'bearer':
                self.AUTH_HEADER_TYPES = ('Bearer',)
                self.header = request.META.get(api_settings.AUTH_HEADER_NAME)
        elif get_authorization_key:
            self.auth_prefix = get_authorization_key.split()[0].lower()
            if self.auth_prefix == 'api-key':
                self.AUTH_HEADER_TYPES = ('Api-Key',)
                self.header = get_authorization_key
        else:
            raise ValidationError('Authentication credentials are required.')

        if isinstance(self.header, str):
            self.header = self.header.encode(HTTP_HEADER_ENCODING)

        return self.header

    def get_raw_token(self, header):
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        parts = self.header.split()

        if len(parts) == 0:
            return None
        AUTH_HEADER_TYPE_BYTES = {h.encode(HTTP_HEADER_ENCODING) for h in self.AUTH_HEADER_TYPES}
        if parts[0] not in AUTH_HEADER_TYPE_BYTES:
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
            return self.header

    def get_user(self, header):
        """
        Attempts to find and return a user using the given validated token.
        """
        if self.AUTH_HEADER_TYPES[0] == 'Bearer':

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

            key = self.header.split()
            api_key = str(key[1], 'UTF-8')
            try:
                user_id = UserApiKey.objects.get(api_key=api_key)
            except Exception as e:
                raise ValidationError("Key contained no recognizable user identification")

            try:
                if user_id.expiry_date is not None:
                    if user_id.expiry_date < date.today() or user_id.is_deleted is not False:
                        raise InvalidToken('Invalid Token. Token Expired')
                user = self.user_model.objects.get(**{api_settings.USER_ID_FIELD: user_id.user.id})
            except self.user_model.DoesNotExist:
                raise AuthenticationFailed(_("User not found"), code="user_not_found")

            if not user.is_active:
                raise AuthenticationFailed(_("User is inactive"), code="user_inactive")
            return user
