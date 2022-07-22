import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from auth_user.manager import UserManager


class User(AbstractBaseUser):
    """
    Model to save user details and generating api key for each user
    """
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=50)
    is_admin = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

    def has_perm(self):
        return True

    def has_module_perms(self):
        return True

    @property
    def is_staff(self):
        return self.is_admin


class UserApiKey(models.Model):

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    api_key = models.UUIDField(default=uuid.uuid4, editable=False)
    created_date = models.DateField(auto_now_add=True)
    expiry_date = models.DateField(null=True)
    is_deleted = models.BooleanField(default=False)
