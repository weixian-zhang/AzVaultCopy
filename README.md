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
<code>
Usage: azvaultcopy copypaste [OPTIONS]

Options:
  -sv, --src_vault TEXT           source vault name
  -dv, --dest_vault TEXT          destination vault name
  -st, --src_token TEXT           access token of source Entra Tenant to
                                  access source vault.

                                  az login --tenant {tenant id}

                                  az account get-access-token --scope
                                  https://vault.azure.net/.default --query
                                  "accessToken"
  -dt, --dest_token TEXT          access token of destination Entra Tenant to
                                  access source vault.

                                  az login --tenant {tenant id}

                                  az account get-access-token --scope
                                  https://vault.azure.net/.default --query
                                  "accessToken"
  -ed, --export_dir TEXT          certs and secrets are save to this directory
                                  while importing to dest vault
  -eo, --export_only              all certs and secrets are save to local
                                  drive, WITHOUT importing to dest vault
  -ii, --no_import_if_dest_exist  any cert or secret with same name at dest
                                  vault will not be imported

                                  * When importing an object with the same
                                  name, vault will create a new version.
  -tz, --timezone TEXT            Python timezone name to localize datetime

                                  https://en.wikipedia.org/wiki/List_of_tz_dat
                                  abase_time_zones
  --help                          Show this message and exit.
</code>

<br >

## Report  

![image](https://github.com/user-attachments/assets/ea985de5-861e-4737-b2f2-871c02e4a040)

