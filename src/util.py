from datetime import datetime

class Util:

    def friendly_date_str(d: datetime):
        return d.strftime('%b %d %Y')