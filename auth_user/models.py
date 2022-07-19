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
    api_key = models.UUIDField(default=uuid.uuid4, editable=False)
    is_admin = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin