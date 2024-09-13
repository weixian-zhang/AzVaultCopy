from azure.identity import AzureCliCredential
from azcred import ExistingTokenCredential
from dotenv import load_dotenv
import os

# currently for local dev take environment variables from .env.
# future usage to support service principal credential in environment variables 
load_dotenv()  

# login to 2 tenants
# https://learn.microsoft.com/en-us/answers/questions/1319805/azure-python-sdk-athenticate-to-multiple-tenants-i
# get access token akv scope
# az account get-access-token --scope https://vault.azure.net/.default --query "accessToken"
class Config:

    def __init__(self, src_token='', dest_token='') -> None:
        self.src_token = os.environ.get('src_token') if not src_token else src_token
        self.dest_token = os.environ.get('dest_token') if not dest_token else dest_token
        self.src_vault_name = 'akv-gccs'
        self.dest_vault_name = 'akv-temp-3'
        self.ignore_import_if_exist = True
        self.export_only = False
        self.out_dir = ''

        self.source_azure_cred = ExistingTokenCredential(self.src_token)
        self.dest_azure_cred =  ExistingTokenCredential(self.dest_token)


    def get_src_vault_url(self):
        return f'https://{self.src_vault_name}.vault.azure.net'
    
    def get_dest_vault_url(self):
        return f'https://{self.dest_vault_name}.vault.azure.net'
