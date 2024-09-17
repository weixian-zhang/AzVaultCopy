# AzVaultCopy
Exports secrets and certs from one Key Vault and import to another on same Entra Tenants or across 2 different Tenants

<br >  

## Features
* Python 3.11 cmdline tool
* exports not only latest objects, but also all older versions that is enabled, Exportable and not expired
* Displays a summary report of what has and has not been exported or imported on console
* supports exporting all versions of certs and secrets on local drive, while importing to destination vault
* supports exporting objects to local drive only and skip importing to destination vault

<br >

## Authentication & Authorization  

Repeat the 2 steps if destination vault is in a different Entra Tenant  

1. sign in using either an Azure user account or service principal
   * user account
     <code>az login --tenant {tenant id}</code>
     
   * service principal
     <code>az login --service-principal -u <app-id> -p <password-or-cert> --tenant {tenant id} <tenant></code>
2. get access token:  
<code>az account get-access-token --scope https://vault.azure.net/.default --query "accessToken"</code>  

<br >

## Usage
