from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient, CertificateContentType, CertificatePolicy
from cryptography import x509
from azure.keyvault.secrets import SecretClient
from config import Config
import base64 
from datetime import datetime
from model import Cert, CertVersion, Secret, SecretVersion, SourceKeyVault, DestinationVault
from pytz import timezone
from log import log
from util import Util

# example
# https://github.com/Azure/azure-sdk-for-python/blob/main/sdk/keyvault/azure-keyvault-certificates/samples/parse_certificate.py
# https://stackoverflow.com/questions/58313018/how-to-get-private-key-from-certificate-in-an-azure-key-vault
class VaultManager:
    
    def __init__(self, config: Config) -> None:
        self.config = config

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
            
            if not cert_prop.enabled:
                log.warn(f'Cert {cert.name} is not enabled, ignoring')

            cert = Cert(cert_prop.name, cert_prop.tags)

            for version in self.src_cert_client.list_properties_of_certificate_versions(cert_prop.name):
                
                if not version.enabled:
                     log.warn(f'Cert {cert.name} of version {version.version} is not enabled, ignoring')
                     continue
                
                cert_policy = self.src_cert_client.get_certificate_policy(cert_prop.name)

                if not cert_policy.exportable:
                     log.warn(f'Cert {cert.name} of version {version.version} is marked Not Exportable, ignoring')
                     continue
                
                if self._is_object_expired(version.expires_on):
                     log.warn(f'Cert {cert.name} of version {version.version} was expired on {Util.friendly_date_str(version.expires_on)}, ignoring')
                     continue
                

                
                # private key stored as secret
                private_key_b64 = self.src_secret_client.get_secret(version.name, version.version).value
                
                private_key_bytes, cert_type = self._decode_private_key(private_key_b64)

                cp = CertificatePolicy(cert_policy.issuer_name)
                cp.__dict__.update(cert_policy.__dict__)
                
                if cert_type == 'PFX':
                    setattr(cp, '_content_type', CertificateContentType.pkcs12)
                else:
                    setattr(cp, '_content_type', CertificateContentType.pem)
                
                cv = CertVersion(version=version.version, cert=private_key_bytes, cert_policy=cp,
                                 type=cert_type, expires_on= version.expires_on, 
                                 created_on= version.created_on, enable= version.enabled, tags= version.tags)

                cert.versions.append(cv)

                log.info(f'Cert {cert.name} of version {version.version} has private key exported as {cert_type} format')
               
            
            if cert.versions:
               cert.versions = sorted(cert.versions, key=lambda x: x.created_on)
               result.append(cert)

        log.info('export certs completed')

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
        
        log.info('begin export secrets')

        result = []

        for secret in self.src_secret_client.list_properties_of_secrets():

            vault_secret = Secret(secret.name, secret.tags)

            if not secret.enabled:
                log.warn(f'Secret {secret.name} of version {version.version} is not enabled, ignoring')
                continue
            
            if self._is_secret_private_key_created_by_cert(secret.content_type):
                continue

            for version in self.src_secret_client.list_properties_of_secret_versions(secret.name):
      
                if not version.enabled:
                    log.warn(f'Secret {secret.name} of version {version.version} is not enabled, ignoring')
                    continue
                
                if version.expires_on and self._is_object_expired(version.expires_on):
                     log.warn(f'Secret {secret.name} of version {version.version} was expired on {Util.friendly_date_str(version.expires_on)}, ignoring')
                     continue
                
                secret_value  = self.src_secret_client.get_secret(version.name, version.version).value

                sv = SecretVersion(version.version, secret_value, version.content_type, version.expires_on, version.created_on, version.enabled, version.tags)

                vault_secret.versions.append(sv)

                log.info(f'Secret {secret.name} of version {version.version} is exported successfully')

            if vault_secret.versions:
               vault_secret.versions = sorted(vault_secret.versions, key = lambda x: x.created_on)
               result.append(vault_secret)

        log.info('export secrets completed')

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
         
         log.info('export dest certs completed')

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
         
         log.info('export dest secrets completed')

         return secrets, deleted_secrets
    

    def import_certs(self, src_vault: SourceKeyVault, dest_vault: DestinationVault):
         """
         - import will be ignored if dest vault contains object with same name
         - if dest vault contains same object name, and --ignore-import-if-exists is set to True, 
           will import object to dest vault causing a new version to be created
         """
         
         log.info('begin importing certs')

         for cert in src_vault.certs:

            if self.config.no_import_if_dest_exist and cert.name in dest_vault.cert_names:
                   log.warn(f'Cert {cert.name} is found in dest vault {dest_vault.name}, import is ignored with --no_import_if_dest_exist flag on')
                   continue
            
            if cert.name in dest_vault.deleted_cert_names:
              log.warn(f'cert {cert.name} is found in dest vault {dest_vault.name} as deleted, import is ignored')
              continue
              
            for version in cert.versions:
                
                log.info(f'importing cert: {cert.name} version: {version.version}')
                
                self.dest_cert_client.import_certificate(cert.name, version.cert, policy=version.cert_policy,
                                                         enabled=version.enable, tags=version.tags)

                log.info(f'Cert: {cert.name} version: {version.version} imported successfully')

         log.info('import certs completed')


    def import_secrets(self, src_vault: SourceKeyVault, dest_vault: DestinationVault):
         """
         - import will be ignored if dest vault contains object with same name
         - if dest vault contains same object name, and --ignore-import-if-exists is set to True, 
           will import object to dest vault causing a new version to be created
         """
         
         log.info('begin import secrets')

         for secret in src_vault.secrets:
              
              if self.config.no_import_if_dest_exist and secret.name in dest_vault.secret_names:
                   log.warn(f'secret {secret.name} is found in dest vault {dest_vault.name}, import is ignored with --no_import_if_dest_exist flag on')
                   continue

              if secret.name in dest_vault.deleted_secret_names:
                   log.warn(f'secret {secret.name} is found in dest vault {dest_vault.name} as deleted, import is ignored')
                   continue

              for version in secret.versions:
                   
                   log.info(f'importing secret: {secret.name} version: {version.version}')

                   self.dest_secret_client.set_secret(secret.name, 
                                                      version.value,
                                                      content_type=version.content_type,
                                                      enabled=version.enabled,
                                                      expires_on=version.expires_on, 
                                                      tags=version.tags)

                   log.info(f'Secret: {secret.name} version: {version.version} imported successfully')

         log.info('import secrets completed')



    def _decode_private_key(self, private_key: str) -> tuple[bytes, str]:
          """
          key vault supports 2 types of cert format, PEM or PFX

          content_type cannot be used to reliably determine if cert if od PEM or PFX format.
          Reason is Key ault SDK returns use latest content_type for all versions regardless if older version is a different content type
          e.g: latest version is PEM and older versions are PFX, content_type will always be PEM for all versions
          """
          #from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates, load_pkcs12

          # def _try_b64_decode_private_key_str(private_key) -> tuple[bool, bytes]:
          #      try:
          #           private_key_bytes = base64.b64decode(private_key)
          #           return True, private_key_bytes
          #      except:
          #           return False, b''
          
          def _determine_if_pem_format(private_key: str):
               if '-----BEGIN' in private_key:
                    return True
               else:
                    return False


          is_pem =  _determine_if_pem_format(private_key)  #private_key.encode()

          if is_pem:
              cert_type = 'PEM'
              private_key_bytes = private_key.encode()
          else:
               cert_type = 'PFX'
               private_key_bytes = base64.b64decode(private_key)
               
          
          # try:
          # #     private_key, public_certificate, additional_certificates = load_key_and_certificates(
          # #           data=private_key_bytes,
          # #           password=None
          # #     )
              
          #     private_key_bytes = base64.b64decode(private_key) 
              
          # except Exception as e:
          #     private_key_bytes = private_key.encode()
          #     cert_type = 'PEM'
          
              
          return private_key_bytes, cert_type
    
    

    def _is_secret_private_key_created_by_cert(self, content_type: str):
        if content_type in ['application/x-pkcs12', 'application/x-pem-file']:
            return True
        return False

        
    def _is_object_expired(self, expires_on):
         
         if self._as_utc_8(datetime.now()) >= self._as_utc_8(expires_on):
              return True
         return False


    def _as_utc_8(self, d: datetime):
         return d.astimezone(timezone('Asia/Kuala_Lumpur'))
                

     
    
    

    