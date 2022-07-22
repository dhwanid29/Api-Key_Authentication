from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):
    def create_user(self, **kwargs):
        """
        Creates and saves a User with the given email, username and password.
        """
        if not kwargs.get('email'):
            raise ValueError("EMAIL_REQUIRED")

        kwargs.pop('password2', None)
        user = self.model(**kwargs)

        user.set_password(kwargs.get('password'))
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, api_key, password=None):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email=email,
            password=password,
            username=username,
            api_key=api_key
        )
        user.is_admin = True
        user.save(using=self._db)
        return user
