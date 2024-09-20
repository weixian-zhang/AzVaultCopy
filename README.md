# AzVaultCopy
Cli tool to export and import secrets and certs from one Key Vault to another on same Entra Tenants or across 2 different Tenants

<br >  

## Features
* Python 3.11 cmdline tool
* exports not only latest objects, but also all older versions that is enabled, Exportable and not expired
* Displays a detailed report of export or import statuses
* supports exporting all versions of certs and secrets on local drive, while importing to destination vault
* supports exporting objects to local drive only and skip importing to destination vault

<br >

## Usage  

1. <code>pip install azvaultcopy</code>  

2. Authentication (repeat 2.1 and 2.2 if destination vault is in a different Entra Tenant)

   2.1 sign in using either  
       - Azure user account <code>az login --tenant {tenant id}</code>  
       - service principal <code>az login --service-principal -u <app-id> -p <password-or-cert> --tenant {tenant id} <tenant></code>
   
   2.2 get access token:  
   <code>az account get-access-token --scope https://vault.azure.net/.default --query "accessToken"</code>
   
4. Authorization - user account or service principal requires following Azure RBAC
    * Key Vault Reader
    * Key Vault Secrets User

3. <code>azvaultcopy copypaste --src_vault {name of source key vault} --dest_vault {name of dest key vault} --src_token {source vault tenant access token} --dest_token {dest vault tenant access token}</code>

<br >

## Report  

![image](https://github.com/user-attachments/assets/ea985de5-861e-4737-b2f2-871c02e4a040)

