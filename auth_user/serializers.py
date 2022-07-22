import uuid

from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from auth_user.models import User, UserApiKey
from auth_user.utils import ExpiryDuration
from auth_user.validations import validate_date


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for User Registration
    """
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for User Profile View
    """

    class Meta:
        model = User
        fields = ['email']


class UserLoginSerializer(serializers.ModelSerializer):
    """
    Serializer for User Login
    """
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email', 'password']


class UserApiKeySerializer(serializers.Serializer):
    """
    Serializer for Generating Api Key
    """
    EXPIRE_IN_TIME = (
        ("1 Day", "1 Day"),
        ("1 Week", "1 Week"),
        ("1 Month", "1 Month"),
        ("6 Months", "6 Months"),
        ("1 Year", "1 Year"),
        ("Never Expire", "Never Expire"),
        ("Custom Date", "Custom Date"),
    )
    expire_time_type = serializers.ChoiceField(choices=EXPIRE_IN_TIME)
    custom_date = serializers.DateField(required=False)

    class Meta:
        model = UserApiKey
        fields = ['expire_time_type', 'custom_date']

    def validate(self, attrs):
        expire_time_type = attrs.get('expire_time_type')
        custom_date = attrs.get('custom_date')
        if custom_date:
            validate_date(custom_date)
        if expire_time_type == 'Custom Date' and custom_date:
            return attrs
        elif expire_time_type == 'Custom Date' and not custom_date:
            raise ValidationError('Please enter custom date.')
        else:
            return attrs

    def save(self, validated_data):
        user = self.context.get('user')
        expire_time_type = validated_data.get('expire_time_type')
        expiry_duration = ExpiryDuration()
        if expire_time_type == '1 Week':
            expiry_date = expiry_duration.get_expiry_date_after_one_week()
        elif expire_time_type == '1 Day':
            expiry_date = expiry_duration.get_expiry_date_after_one_day()
        elif expire_time_type == '1 Month':
            expiry_date = expiry_duration.get_expiry_date_after_one_month()
        elif expire_time_type == '6 Months':
            expiry_date = expiry_duration.get_expiry_date_after_six_months()
        elif expire_time_type == '1 Year':
            expiry_date = expiry_duration.get_expiry_date_after_one_year()
        elif expire_time_type == 'Never Expire':
            expiry_date = None
        elif expire_time_type == 'Custom Date':
            expiry_date = validated_data['custom_date']
        else:
            raise ValidationError('Please enter correct choice!')
        return UserApiKey.objects.create(expiry_date=expiry_date, user=user)


class DeleteApiKeySerializer(serializers.ModelSerializer):
    """
    Serializer to delete Api Key
    """
    api_key = serializers.UUIDField()

    class Meta:
        model = UserApiKey
        fields = ['api_key', 'is_deleted']


class ViewApiKeySerializer(serializers.ModelSerializer):
    """
    Serializer to view Api Key
    """

    class Meta:
        model = UserApiKey
        fields = ['api_key', 'expiry_date']
