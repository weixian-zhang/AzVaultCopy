from datetime import datetime
from pytz import timezone

class Util:

    @staticmethod
    def friendly_date_str(d: datetime):
        if d:
          return d.strftime('%b %d %Y')
    
       
    @staticmethod
    def as_timezone(d: datetime, tz = 'Asia/Kuala_Lumpur'):
         return d.astimezone(timezone(tz))
    

    @staticmethod
    def is_object_expired(expires_on, timezone = 'Asia/Kuala_Lumpur'):
         if not expires_on:
              return False
         
         if Util.as_timezone(datetime.now()) >= Util.as_timezone(expires_on, timezone):
              return True
         return False