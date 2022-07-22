from datetime import datetime

from rest_framework.exceptions import ValidationError


def validate_date(date_string):
    """
    Function to validate the username
    :param: takes in date parameter and validates it
    :return: validated date
    """
    date_format = '%Y-%m-%d'
    try:
        date = datetime.strptime(str(date_string), date_format)
        if date < date.today():
            raise ValidationError('Please enter valid future date.')
    except ValueError:
        raise ValidationError("Invalid Date. Please enter date in YYYY-MM-DD format.")
