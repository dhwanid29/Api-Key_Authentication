from django.http import HttpResponse
from django.contrib.auth import authenticate
from rest_framework import status, generics, mixins
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from auth_user.models import User, UserApiKey
from auth_user.serializers import UserRegistrationSerializer, UserProfileSerializer, UserLoginSerializer, \
    UserApiKeySerializer, ViewApiKeySerializer, DeleteApiKeySerializer


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
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'data': serializer.data, 'msg': "User created successfully."},
                            status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    """
    View for User Login View
    """
    authentication_classes = []
    permission_classes = []

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
    permission_classes = [IsAuthenticated]

    def get_object(self, request):
        try:
            return User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return HttpResponse(status=status.HTTP_404_NOT_FOUND)

    def get(self, request):
        """Retrieve a project based on the request API key."""
        user = self.get_object(request)
        serializer = UserProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class GenerateApiKeyView(generics.GenericAPIView, mixins.CreateModelMixin, mixins.DestroyModelMixin):
    """
    View to generate api key
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Retrieve a project based on the request API key."""
        serializer = UserApiKeySerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid():
            serializer.save(validated_data=serializer.validated_data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_403_FORBIDDEN)


class ApiKeyDeleteView(generics.GenericAPIView, mixins.DestroyModelMixin):
    """
    View to delete api key
    """
    permission_classes = [IsAuthenticated]
    serializer_class = DeleteApiKeySerializer

    def get_object(self, request):
        try:
            return User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return HttpResponse(status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            api_key = serializer.data.get('api_key')
            key = UserApiKey.objects.filter(api_key=api_key).first()
            if not key:
                raise ValueError('Please enter valid Api-Key.')
            serializer = self.get_serializer(key, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(is_deleted=True)
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({'msg': serializer.errors}, status=status.HTTP_404_NOT_FOUND)


class ApiKeyView(generics.GenericAPIView, mixins.ListModelMixin):
    """
    View to view api key
    """
    permission_classes = [IsAuthenticated]
    serializer_class = ViewApiKeySerializer

    def get(self, request, *args, **kwargs):
        queryset = UserApiKey.objects.filter(user=request.user.id)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
