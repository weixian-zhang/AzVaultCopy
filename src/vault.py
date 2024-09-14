from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient, CertificateContentType
from azure.keyvault.secrets import SecretClient
from config import Config
import base64 
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import load_pem_private_key
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
                
                private_key_bytes, cert_type = b'', 'pem'
                if cert_policy.content_type == CertificateContentType.pkcs12:
                    private_key_bytes = base64.b64decode(private_key_b64) 
                    cert_type = 'PFX'
                else:
                    private_key_bytes = private_key_b64.encode()
                    cert_type = 'PEM'
                
                cv = CertVersion(version.version, private_key_bytes, cert_type, version.expires_on, version.created_on, version.enabled, version.tags)

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
        - ignores secret.content_type == 'application/x-pkcs12' created by certificates to store private key

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
    

    def list_certs_from_dest_vault(self) -> set:
         """
         returns 2 sets containing certs and deleted certs
         """

         log.info('exporting certs from dest vault')

         certs = set()

         for c in self.dest_cert_client.list_properties_of_certificates():
              certs.add(c.name)

         for dc in self.dest_cert_client.list_deleted_certificates():
              certs.add(dc.name)
         
         log.info('export dest certs completed')

         return certs
    

    def list_secrets_from_dest_vault(self) -> set:
         """
         all secrets with the following conditions will be retrieved
         - disabled
         - expired
         - deleted

         returns 2 sets containing secrets and deleted secrets
         """
         
         log.info('exporting secrets from dest vault')

         secrets = set()

         for s in self.dest_secret_client.list_properties_of_secrets():
              secrets.add(s.name)

         for ds in self.dest_secret_client.list_deleted_secrets():
              secrets.add(ds.name)
         
         log.info('export dest secrets completed')

         return secrets
    

    def import_certs(self, src_vault: SourceKeyVault, dest_vault: DestinationVault):
         """
         - import will be ignored if dest vault contains a deleted object with same name
         - if dest vault contains same object name, and --ignore-import-if-exists is set to True, 
           will import object to dest vault causing a new version to be created
         """
         
         log.info('begin importing certs')

         for cert in src_vault.certs:

            if cert.name in dest_vault.deleted_cert_names:
              log.warn(f'cert {cert.name} is found deleted in dest vault {dest_vault.name}, import is ignored')
              continue
              
            for version in cert.versions:
                
                log.info(f'importing cert: {cert.name} version: {version.version}')
                
                self.dest_cert_client.import_certificate(cert.name, version.cert, enabled=version.enable, tags=version.tags)

                log.info(f'Cert: {cert.name} version: {version.version} imported successfully')

         log.info('import certs completed')


    def import_secrets(self, src_vault: SourceKeyVault, dest_vault: DestinationVault):
         """
         - import will be ignored if dest vault contains a deleted object with same name
         - if dest vault contains same object name, and --ignore-import-if-exists is set to True, 
           will import object to dest vault causing a new version to be created
         """
         
         log.info('begin import secrets')

         for secret in src_vault.secrets:
              
              if secret.name in dest_vault.deleted_secret_names:
                   log.warn(f'secret {secret.name} is found deleted in dest vault {dest_vault.name}, import is ignored')
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
                

                
#  pfx_private_key, pfx_public_certificate, pfx_additional_certificates = pkcs12.load_key_and_certificates(
               #      data=private_key_bytes,
               #      password=None
               #  )

               #  pfx_cert_bytes = pkcs12.serialize_key_and_certificates(subject.encode(), 
               #                                                         pfx_private_key, 
               #                                                         pfx_public_certificate, 
               #                                                         pfx_additional_certificates)
                

               #  pem_private_key = load_pem_private_key(data=private_key_bytes, password=None)
               #  pem_private_bytes = pem_private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
               #  pem_public_bytes = pem_private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.PKCS1)
               #  pem_cert_bytes = pem_public_bytes + pem_private_bytes

                


               #  public_key_bytes_pem = pfx_public_certificate.public_bytes(Encoding.PEM)
               #  private_key_bytes_pem = pfx_private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
               #  additional_cert_bytes = b''
               #  for ca in pfx_additional_certificates:
               #          additional_cert_bytes += ca.public_bytes(Encoding.PEM)

               #  cert_bytes = public_key_bytes_pem + private_key_bytes_pem + additional_cert_bytes

                

               

               #  pkcs12_bytes = serialize_key_and_certificates(subject, private_key, public_certificate, additional_certificates)


    # def list_secrets_from_src_vault(self):

    #     with self.otel_tracer.start_as_current_span(f'VaultManager.list_expiring_secrets.{self.vault_name}') as cs:

    #         #cs.add_event(f'VaultManager.list_expiring_secrets.{self.vault_name}')
        
    #         expiring_items = []

    #         for secret in self.secret_client.list_properties_of_secrets():

    #             # ignore disabled and secret that is private key belonging to Certificate
    #             if not secret.enabled or secret.content_type == 'application/x-pkcs12':
    #                 continue

    #             ei = ExpiringObject(secret.name, 'secret')

    #             for version in self.secret_client.list_properties_of_secret_versions(secret.name):

    #                 if not version.enabled:
    #                     continue

    #                 if LogicUtil.is_expiring(version.expires_on, self.appconfig.num_of_days_notify_before_expiry):
    #                     ev = ExpiringVersion(version.version, version.expires_on, version.created_on)
    #                     ei.versions.append(ev)

    #             if ei.versions:
    #                 ei.set_latest_version()
    #                 expiring_items.append(ei)

            
    #         return expiring_items
    

    # def list_certs_from_src_vault(self):
        
    #     with self.otel_tracer.start_as_current_span(f'VaultManager.list_expiring_certs.{self.vault_name}') as cs:

    #         #cs.add_event(f'VaultManager.list_expiring_certs.{self.vault_name}')

    #         expiring_items = []

    #         for cert in self.cert_client.list_properties_of_certificates():

    #             if not cert.enabled:
    #                 continue

    #             ei = ExpiringObject(cert.name, 'cert')

    #             for version in self.cert_client.list_properties_of_certificate_versions(cert.name):

    #                 if not version.enabled:
    #                     continue

    #                 if LogicUtil.is_expiring(version.expires_on, self.appconfig.num_of_days_notify_before_expiry):
    #                     ev = ExpiringVersion(version.version, version.expires_on, version.created_on)
    #                     ei.versions.append(ev)

    #             if ei.versions:
    #                 ei.set_latest_version()
    #                 expiring_items.append(ei)
            
    #         return expiring_items
    
    

    