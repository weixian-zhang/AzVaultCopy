from azure.identity import AzureCliCredential
from azcred import ExistingTokenCredential

# login to 2 tenants
# https://learn.microsoft.com/en-us/answers/questions/1319805/azure-python-sdk-athenticate-to-multiple-tenants-i
# get access token akv scope
# az account get-access-token --scope https://vault.azure.net/.default --query "accessToken"
class Config:

    def __init__(self) -> None:
        self.src_token = ''
        self.dest_token = ''
        self._src_vault_name = 'akv-gccs'
        self.dest_vault_name = 'akv-temp-3'
        self.ignore_import_if_exist = True
        self.export_only = False
        self.out_dir = ''

        self.source_azure_cred = ExistingTokenCredential(self.src_token)
        self.dest_azure_cred =  ExistingTokenCredential(self.dest_token)


    def get_src_vault_url(self):
        return f'https://{self._src_vault_name}.vault.azure.net'
    
    def get_dest_vault_url(self):
        return f'https://{self.dest_vault_name}.vault.azure.net'
