from tokenize import TokenError

from django.http import HttpResponse
from django.shortcuts import render
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.settings import api_settings
from rest_framework_api_key.models import APIKey
from django.contrib.auth import authenticate
# Create your views here.
from rest_framework import status, HTTP_HEADER_ENCODING
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_api_key.models import APIKey
from rest_framework_api_key.permissions import HasAPIKey
from rest_framework_simplejwt.authentication import JWTAuthentication, AUTH_HEADER_TYPES, AUTH_HEADER_TYPE_BYTES
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.tokens import RefreshToken

from auth_user.models import User
from auth_user.serializers import UserRegistrationSerializer, UserProfileSerializer, UserLoginSerializer


def get_tokens_for_user(user):
    """
    Manually generating token
    :param user: user
    :return: refresh token and access token
    """
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    """
    View for User Registration
    """

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'token': token, 'data': serializer.data, 'msg': "User created successfully."},
                            status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    """
    View for User Login View
    """

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token': token, 'msg': "LOGGED_IN"}, status=status.HTTP_200_OK)
            else:
                return Response({'errors': {'non_field_errors': ["INVALID_EMAIL_OR_PASSWORD"]}},
                                status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)


class UserProfileView(APIView):
    """
    User Profile View
    """
    # permission_classes = [HasAPIKey]

    permission_classes = [IsAuthenticated]

    def get_object(self, request):
        try:
            return User.objects.get(id=request.user.id)

        except User.DoesNotExist:
            return HttpResponse(status=status.HTTP_404_NOT_FOUND)

    def get(self, request):
        """Retrieve a project based on the request API key."""
        get_key = request.META.get("HTTP_X_API_KEY")
        if get_key:
            key = get_key.split()[1]
            api_key_user = User.objects.get(api_key=key)
            serializer = UserProfileSerializer(api_key_user)
        else:
            user = self.get_object(request)
            serializer = UserProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
