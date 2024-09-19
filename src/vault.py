from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient, CertificateContentType, CertificatePolicy
from cryptography import x509
from azure.keyvault.secrets import SecretClient
from config import Config
import base64 
from datetime import datetime
from model import (Cert, CertVersion, RunContext, Secret, SecretVersion, 
                   SourceKeyVault, DestinationVault,VaultObjectType, TrackType)
from log import log
from util import Util

# example
# https://github.com/Azure/azure-sdk-for-python/blob/main/sdk/keyvault/azure-keyvault-certificates/samples/parse_certificate.py
# https://stackoverflow.com/questions/58313018/how-to-get-private-key-from-certificate-in-an-azure-key-vault
class VaultManager:
    """
     * AKV SDK throws error on the following conditions:
          - import expired cert
          - get secret private key when cert is Disabled
          - cert that is not Exportable, secret wil only contains public key. Import cert without private key will throw error
    """
    
    def __init__(self, config: Config, run_context: RunContext) -> None:
        self.config = config
        self.run_context = run_context

        self.src_cert_client = CertificateClient(config.get_src_vault_url(), config.source_azure_cred)
        self.src_secret_client = SecretClient(config.get_src_vault_url(), config.source_azure_cred)

        self.dest_cert_client = CertificateClient(config.get_dest_vault_url(), config.dest_azure_cred)
        self.dest_secret_client = SecretClient(config.get_dest_vault_url(), config.dest_azure_cred)

    
    def list_certs_from_src_vault(self) -> list[Cert]:
        """
        The following secret conditions will be ignored:
        - disabled secrets (AKV API does not support)
        - disabled version (AKV API does not support)
        - expired version
        return: Each cert version will be sorted with "created_on" so that during import,
        oldest will be created first and the last item which is the latest current version in destination vault
        """

        log.info('begin export certs')

        result = []

        for cert_prop in self.src_cert_client.list_properties_of_certificates():
            
            self.run_context.total_certs += 1 # report
            
          #   if not cert_prop.enabled:
          #       log.warn(f'Cert {cert_prop.name} is not enabled, ignoring')
          #       continue

            cert = Cert(cert_prop.name, cert_prop.tags)

            cert_policy = self.src_cert_client.get_certificate_policy(cert_prop.name)

          #   if not cert_policy.exportable:
          #      log.warn(f'Cert {cert.name} is marked Not Exportable, ignoring')
          #      continue

            for version in self.src_cert_client.list_properties_of_certificate_versions(cert_prop.name):
                
                self.run_context.track_version_stats(cert_prop.name, VaultObjectType.Cert, TrackType.Total) # report

                if not version.enabled:
                     cert.versions.append(CertVersion(cert_name=cert_prop.name, version=version.version, cert=b'',
                                 cert_policy=None, type='', expires_on=version.expires_on, 
                                 created_on=version.created_on, enable=version.enabled, is_exported=False, tags=version.tags))
                     #log.warn(f'Cert {cert.name} of version {version.version} is not enabled, ignoring')
                     continue
                
                
                if Util.is_object_expired(version.expires_on, self.config.timezone):
                     cert.versions.append(CertVersion(cert_name=cert_prop.name, version=version.version, cert=b'',
                                 cert_policy=None, type='', expires_on=version.expires_on, 
                                 created_on=version.created_on, enable=version.enabled, is_exported=False, tags=version.tags))
                     #log.warn(f'Cert {cert.name} of version {version.version} was expired on {Util.friendly_date_str(version.expires_on)}, ignoring')
                     continue
                

                # private key stored as secret
                private_key_b64 = self.src_secret_client.get_secret(version.name, version.version).value

                private_key_bytes, decoded_cert_type = self._decode_private_key(private_key_b64)

                version_cert_policy = self._create_version_specific_cert_policy(decoded_cert_type, cert_policy)
                
                cv = CertVersion(cert_name=cert_prop.name, version=version.version, cert=private_key_bytes,
                                 cert_policy=version_cert_policy, type=decoded_cert_type, expires_on= version.expires_on, 
                                 created_on= version.created_on, enable= version.enabled, is_exported=True, tags= version.tags)

                cert.versions.append(cv)
                if not cert.is_exported:
                    cert.is_exported = True 
                self.run_context.track_version_stats(cert_prop.name, VaultObjectType.Cert, TrackType.Exported) # report

                #log.info(f'exported Cert {cert.name} of version {version.version} with private key as {decoded_cert_type} format')
               
            
            #if cert.versions:
            cert.versions = sorted(cert.versions, key=lambda x: x.created_on)
            cert.versions[-1].is_latest_version = True
            result.append(cert)
            #self.run_context.track_exported_cert_version(cert_prop.name, len(cert.versions)) # report

        log.info('export certs completed')

        self.run_context.total_exported_certs = len([x for x in result if x.is_exported]) #self.run_context.count_total_objects_by_exported_versions(result) # report

        return result

   

    def list_secrets_from_src_vault(self) -> list[Secret]:
        """
        the following secret conditions will be ignored:
        - disabled secrets (AKV API does not support)
        - disabled version (AKV API does not support)
        - expired version
        - ignores secret.content_type == 'application/x-pkcs12' and application/x-pem-file created by certificates to store private key

        return: Each secret version will be sorted with "created_on" so that during import,
        oldest will be created first and the last item which is the latest current version in destination vault
        """
        
        log.info('begin exporting secrets')

        result = []

        for secret in self.src_secret_client.list_properties_of_secrets():
            
            if self._is_secret_private_key_created_by_cert(secret.content_type):
                continue
            
            self.run_context.total_secrets += 1 # report

          #   if not secret.enabled:
          #       log.warn(f'Secret {secret.name} of version {version.version} is not enabled, ignoring')
          #       continue
            
            vault_secret = Secret(secret.name, secret.tags)
            
            for version in self.src_secret_client.list_properties_of_secret_versions(secret.name):
                
                self.run_context.track_version_stats(secret.name, VaultObjectType.Secret, TrackType.Total) # report
              
                if not version.enabled:
                    vault_secret.versions.append(SecretVersion(secret_name=secret.name, version=version.version, value='', 
                                   content_type=version.content_type, expires_on=version.expires_on, 
                                   activates_on=version.not_before,created_on=version.created_on,
                                   enabled=version.enabled, is_exported=False, tags=version.tags))
                    #log.warn(f'Secret {secret.name} of version {version.version} is not enabled, ignoring')
                    continue
                
                if Util.is_object_expired(version.expires_on, self.config.timezone):
                     vault_secret.versions.append(SecretVersion(secret_name=secret.name, version=version.version, value='', 
                                   content_type=version.content_type, expires_on=version.expires_on, 
                                   activates_on=version.not_before,created_on=version.created_on,
                                   enabled=version.enabled, is_exported=False, tags=version.tags))
                     #log.warn(f'Secret {secret.name} of version {version.version} was expired on {Util.friendly_date_str(version.expires_on)}, ignoring')
                     continue
                
                secret_value  = self.src_secret_client.get_secret(version.name, version.version).value

                sv = SecretVersion(secret_name=secret.name, version=version.version, value=secret_value, 
                                   content_type=version.content_type, expires_on=version.expires_on, 
                                   activates_on=version.not_before,created_on=version.created_on,
                                   enabled=version.enabled, is_exported=True, tags=version.tags)

                vault_secret.versions.append(sv)
                if not vault_secret.is_exported:
                    vault_secret.is_exported = True
                self.run_context.track_version_stats(secret.name, VaultObjectType.Secret, TrackType.Exported) # report

                # log.info(f'exported Secret {secret.name} of version {version.version}')

          #   if vault_secret.versions:
            vault_secret.versions = sorted(vault_secret.versions, key = lambda x: x.created_on)
            vault_secret.versions[-1].is_latest_version = True
            result.append(vault_secret)
            #self.run_context.track_exported_secret_version(secret.name, len(vault_secret.versions)) # report

        log.info('export secrets completed')

        self.run_context.total_exported_secrets = len([x for x in result if x.is_exported]) #self.run_context.count_total_objects_by_exported_versions(result) # report

        return result

    
    

    def list_certs_from_dest_vault(self) -> tuple[set, set]:
         """
         returns a set containing all certs and deleted certs
         """

         log.info('exporting certs from dest vault')

         certs, deleted_certs = set(), set()

         for c in self.dest_cert_client.list_properties_of_certificates():
              certs.add(c.name)

         for dc in self.dest_cert_client.list_deleted_certificates():
              deleted_certs.add(dc.name)
         
         log.info('export dest vault certs completed')

         return certs, deleted_certs
    

    def list_secrets_from_dest_vault(self) -> tuple[set, set]:
         """
         returns 2 sets containing all secrets and deleted secrets
         """
         
         log.info('exporting secrets from dest vault')

         secrets, deleted_secrets = set(), set()

         for s in self.dest_secret_client.list_properties_of_secrets():
              secrets.add(s.name)

         for ds in self.dest_secret_client.list_deleted_secrets():
              deleted_secrets.add(ds.name)
         
         log.info('export dest vault secrets completed')

         return secrets, deleted_secrets
    

    def import_certs(self)-> list[CertVersion]: # src_vault: SourceKeyVault, dest_vault: DestinationVault) -> list[CertVersion]:
          """
          - import will be ignored if dest vault contains object with same name
          - if dest vault contains same object name, and --ignore-import-if-exists is set to True, 
               will import object to dest vault causing a new version to be created
          """
         
          log.info('begin importing certs')

          imported_version_result = [] # support unit testing
          
          exported_certs = [x for x in self.run_context.src_vault.certs if x.is_exported]
          for cert in exported_certs:

               try:

                    is_version_imported = False # report
                    self.run_context.track_object_exist_in_dest_vault(cert, VaultObjectType.Cert) # report 
                    self.run_context.track_object_deleted_in_dest_vault(cert, VaultObjectType.Cert) # report

                    if self.config.no_import_if_dest_exist and cert.name in self.run_context.dest_vault.cert_names:
                         #log.warn(f'cert {cert.name} is found in dest vault {self.run_context.dest_vault.name}, import is ignored with --no_import_if_dest_exist flag on', 'ImportCert')
                         continue
                    
                    if cert.name in self.run_context.dest_vault.deleted_cert_names:
                         #log.warn(f'cert {cert.name} is found in dest vault {self.run_context.dest_vault.name} as deleted, import is ignored', 'ImportCert')
                         continue
                    
                    for version in [x for x in cert.versions if x.is_exported]:

                         try:
                         
                              self.dest_cert_client.import_certificate(cert.name, version.cert, policy=version.cert_policy,
                                                                      enabled=version.enable, tags=version.tags)
                              imported_version_result.append(version)

                              is_version_imported = True # report
                              version.is_imported = True
                              version.is_cert_marked_as_exportable = True # report
                              self.run_context.track_version_stats(cert.name, VaultObjectType.Cert, TrackType.Imported) # report

                              log.info(f'Cert: {cert.name} with version: {version.version} is successful', 'ImportCert')
                              
                         except Exception as e:
                              err = str(e).lower()
                              if 'no certificate with private key' in err or 'private key is not' in err:
                                   log.warn(f'cert {cert.name} of version {version.version} is not Exportable and has no private key, ignoring import', 'ImportCert')
                              else:
                                   log.err(f'error when importing cert {cert.name} of version {version.version} {e}', 'ImportCert')


                    if is_version_imported: # report
                         cert.is_imported = True
                         self.run_context.total_imported_certs += 1 

               except Exception as e:
                    log.err(f'error when importing cert {cert.name} {e}', 'ImportCert')


          log.info('import certs completed', 'ImportCert')

          return imported_version_result
         
         

    def import_secrets(self): #src_vault: SourceKeyVault, dest_vault: DestinationVault):
         """
         - import will be ignored if dest vault contains object with same name
         - if dest vault contains same object name, and --ignore-import-if-exists is set to True, 
           will import object to dest vault causing a new version to be created
         """
         
         log.info('begin import secrets', 'ImportSecret')

         imported_version_result = []

         exported_secrets = [x for x in self.run_context.src_vault.secrets if x.is_exported]
         for secret in exported_secrets:
              
               try:
                    is_version_imported = False
                    self.run_context.track_object_exist_in_dest_vault(secret, VaultObjectType.Secret) # report 
                    self.run_context.track_object_deleted_in_dest_vault(secret, VaultObjectType.Secret) # report
                   
                    if self.config.no_import_if_dest_exist and secret.name in self.run_context.dest_vault.secret_names:
                         #log.warn(f'secret {secret.name} is found in dest vault {self.run_context.dest_vault.name}, import is ignored with --no_import_if_dest_exist flag on', 'ImportSecret')
                         continue

                    if secret.name in self.run_context.dest_vault.deleted_secret_names:
                         #log.warn(f'secret {secret.name} is found in dest vault {self.run_context.dest_vault.name} as deleted, import is ignored', 'ImportSecret')
                         continue
                    
                    for version in [x for x in secret.versions if x.is_exported]:
                         
                              try:
                                   self.dest_secret_client.set_secret(secret.name, 
                                                                      version.value,
                                                                      content_type=version.content_type,
                                                                      enabled=version.enabled,
                                                                      expires_on=version.expires_on,
                                                                      not_before=version.activates_on,
                                                                      tags=version.tags)
                                   
                                   imported_version_result.append(version)

                                   is_version_imported = True # report
                                   self.run_context.track_version_stats(secret.name, VaultObjectType.Secret, TrackType.Imported) # report
                                   # self.run_context.track_imported_secret_version(secret.name, 1) # report

                                   #log.info(f'imported Secret: {secret.name} version: {version.version} is successful')

                              except Exception as e:
                                   log.err(f'error when importing secret {secret.name} of version {version.version} {e}', 'ImportSecret')


                    if is_version_imported: # report
                         secret.is_imported = True
                         self.run_context.total_imported_secrets += 1 

               except Exception as e:
                    log.err(f'error when importing secret {secret.name}. {e}', 'ImportSecret')


         log.info('import secrets completed')

         return imported_version_result


    
    def _decode_private_key(self, private_key: str) -> tuple[bytes, str]:
          """
          key vault supports 2 types of cert format, PEM or PFX

          content_type cannot be used to reliably determine if cert if od PEM or PFX format.
          Reason is Key ault SDK returns use latest content_type for all versions regardless if older version is a different content type
          e.g: latest version is PEM and older versions are PFX, content_type will always be PEM for all versions
          """
          
          def _is_pem_format(private_key: str):
               if '-----BEGIN' in private_key:
                    return True
               else:
                    return False


          is_pem =  _is_pem_format(private_key)

          if is_pem:
              cert_type = 'PEM'
              private_key_bytes = private_key.encode()
          else:
               cert_type = 'PFX'
               private_key_bytes = base64.b64decode(private_key)
               
     
          return private_key_bytes, cert_type
    
    
    def _create_version_specific_cert_policy(self, cert_type, cert_policy: CertificatePolicy):
          """
          Cert Policy is needed during importing of certs, specifically when 1 cert has multiple Versions with each version,
          having different cert type.
          
          Common scneario is when 1 cert has all versions with same cert type be it all PEM or all PFX.
          Since key vault allows same cert have different cert type for each version, this logic also need to support this edge case.
          
          The challenge is key vault SDK only returns cert cert for the latest cert version, regardless of previous versions having different cert types.
          "import_certificate" function will throw an error as it uses the cert type of "first import cert",
          therefore, subsequent versions of differernt cert type will encounter error.
          """
          cp = CertificatePolicy(cert_policy.issuer_name)

          cp.__dict__.update(cert_policy.__dict__)
          
          if cert_type == 'PFX':
               setattr(cp, '_content_type', CertificateContentType.pkcs12)
          else:
               setattr(cp, '_content_type', CertificateContentType.pem)

          return cp

    def _is_secret_private_key_created_by_cert(self, content_type: str):
        if content_type in ['application/x-pkcs12', 'application/x-pem-file']:
            return True
        return False

        
    


    
                

     
    
    

    