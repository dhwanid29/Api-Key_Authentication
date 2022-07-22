from datetime import datetime, timedelta, date


class ExpiryDuration:

    def get_expiry_date_after_one_day(self):
        expiry_date = datetime.today() + timedelta(days=1)
        return expiry_date

    def get_expiry_date_after_one_week(self):
        expiry_date = datetime.today() + timedelta(days=7)
        return expiry_date

    def get_expiry_date_after_one_month(self):
        expiry_date = date.today() + timedelta(days=30)
        return expiry_date

    def get_expiry_date_after_six_months(self):
        expiry_date = datetime.today() + timedelta(days=180)
        return expiry_date

    def get_expiry_date_after_one_year(self):
        expiry_date = datetime.today() + timedelta(days=365)
        return expiry_date

