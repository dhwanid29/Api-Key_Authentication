from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from auth_user.views import UserRegistrationView, UserProfileView, UserLoginView, GenerateApiKeyView, \
    ApiKeyDeleteView, ApiKeyView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name="register"),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('generate_api_key/', GenerateApiKeyView.as_view(), name='generate_api_key'),
    path('delete_api_key/', ApiKeyDeleteView.as_view(), name="delete_api_key"),
    path('view_api_key/', ApiKeyView.as_view(), name='view_api_key')
]
