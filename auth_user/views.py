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
            print('serializer valid')
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
        print("inside get")
        key = request.META["HTTP_AUTHORIZATION"].split()[1]
        print("key")
        api_key_user = User.objects.get(api_key='389e9c90-ea8f-4f1a-9883-d312795a22f1')
        print(api_key_user, "llll")
        serializer = UserProfileSerializer(api_key_user)
        return Response(serializer.data, status=status.HTTP_200_OK)
