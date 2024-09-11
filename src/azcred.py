from azure.core.credentials import AccessToken, TokenCredential
import json
import base64

# https://github.com/Azure/azure-sdk-for-python/issues/9075

class ExistingTokenCredential (TokenCredential):
     
     def __init__(self, token: str) -> None:
         self.token = token

     def _extract_expiries_on(self, token):
        tokenSplit = token.split(".")

        token_mid_section = tokenSplit[1]

        decoded_json_str = base64.b64decode(f"{token_mid_section}{'=' * (4 - len(token_mid_section) % 4)}").decode("utf-8")

        json_token = json.loads(decoded_json_str)

        return json_token['exp']

     
     def get_token(self, *scopes, **kwargs):
       
       self.expires_on = self._extract_expiries_on(self.token)

       return AccessToken(self.token, self.expires_on)
     
