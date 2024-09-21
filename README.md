# AzVaultCopy
Cli tool to export and import secrets and certs from one Key Vault to another, either on same Entra Tenant or across 2 different Tenants  

![image](https://github.com/user-attachments/assets/922299fd-5d2b-4425-ad93-5a834a69cca9)


<br >  

## Features
* exports not only latest objects, but also all older versions
* Displays a [detailed report](#report) of export or import statuses
* save to local while import - supports exporting all versions of certs and secrets onto local drive, while importing to destination vault
* export only -[ supports exporting objects to local drive only and skip importing to destination vault

## Limitations & Unsupported Scenario
objects =  certs and secrets  
* Windows only
* cannot import expired objects
* cannot export disabled objects
* Cert that is marked Not Exportable cannot be imported due to missing private-key.
<br >

## Usage  

1. <code>pip install [azvaultcopy](https://pypi.org/project/azvaultcopy/)</code>  

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

|args | type | description |
|:-----------------|:----|:-----------|
| -sv, --src_vault  | TEXT | source vault name |
| -dv, --dest_vault | TEXT | destination vault name |
| -st, --src_token  | TEXT | access token of source Entra Tenant to access source vault |
| -dt, --dest_token | TEXT  | TEXT | access token of destination Entra Tenant to access source vault. |
| -ed, --export_dir | TEXT  | TEXT | certs and secrets are save to this directory |
| -eo, --export_only  | TEXT  | TEXT | while importing to dest vault all certs and secrets are save to local drive, without importing to dest vault |
| -ii, --no_import_if_dest_exist | TEXT  | any cert or secret with same name at dest vault will not be imported |
| --help  |   | help |
                                  
<br >

## Report  

![image](https://github.com/user-attachments/assets/ea985de5-861e-4737-b2f2-871c02e4a040)

