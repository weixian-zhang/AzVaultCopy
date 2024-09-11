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
        self.overwrite = False
        self.save_local = False
        self.also_save_local = True
        self.source_azure_cred = None
        self.dest_azure_cred = None

    def init_azure_cred(self):
        self.source_azure_cred = ExistingTokenCredential(self.src_token) #AzureCliCredential(tenant_id=self.src_tenant_id)
        self.dest_azure_cred =  ExistingTokenCredential(self.dest_token) #AzureCliCredential(tenant_id=self.dest_tenant_id)


    def get_src_vault_url(self):
        return f'https://{self._src_vault_name}.vault.azure.net'
    
    def get_dest_vault_url(self):
        return f'https://{self.dest_vault_name}.vault.azure.net'
