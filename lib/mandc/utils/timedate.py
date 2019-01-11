from datetime import datetime, timedelta, tzinfo

class UTC(tzinfo):
    """ UTC tzinfo """

    def utcoffset(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return timedelta(0)
