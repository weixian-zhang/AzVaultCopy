from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.secrets import SecretClient
from config import Config
import base64 
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from datetime import datetime
from model import Cert, CertVersion, Secret, SecretVersion, SourceKeyVault, DestinationVault
from pytz import timezone
from log import log

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
        return: list[Cert] will be sorted with "created_on" so that during import,
        oldest will be created first and the last item will be the latest current version in destination vault
        """

        log.info('begin export certs')

        result = []

        for cert_prop in self.src_cert_client.list_properties_of_certificates():

            cert = Cert(cert_prop.name, cert_prop.tags)

            for version in self.src_cert_client.list_properties_of_certificate_versions(cert_prop.name):
                
                cert_policy = self.src_cert_client.get_certificate_policy(cert_prop.name)

                # check expiring
                if not cert_policy.exportable:
                     log.warn(f'Cert {cert.name} of version {version.version} is marked Not Exportable, ignoring')
                     continue
                if self._is_cert_expired(version.expires_on):
                     log.warn(f'Cert {cert.name} of version {version.version} is expired, ignoring')
                     continue
                
                private_key_b64 = self.src_secret_client.get_secret(version.name, version.version).value

                private_key_b64_decoded = base64.b64decode(private_key_b64)
                
                private_key, public_certificate, additional_certificates = load_key_and_certificates(
                    data=private_key_b64_decoded,
                    password=None
                )
                
                public_key_bytes = public_certificate.public_bytes(Encoding.PEM)
                private_key_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
                additional_cert_bytes = b''
                for ca in additional_certificates:
                        additional_cert_bytes += ca.public_bytes(Encoding.PEM)

                cert_bytes = public_key_bytes + private_key_bytes + additional_cert_bytes

                cv = CertVersion(version.version, version.expires_on, version.created_on, version.enabled, version.tags)
                cv.public_key = public_key_bytes
                cv.private_key = private_key_bytes
                cv.cert =  cert_bytes

                cert.versions.append(cv)


            cert.versions = sorted(cert.versions, key=lambda x: x.created_on)
            result.append(cert)

        log.info('export certs completed')

        return result
    

    def list_secrets_from_src_vault(self) -> list[Secret]:
        """
        will ignore secret.content_type == 'application/x-pkcs12' created by certificates to store private key
        """
        
        log.info('begin export secrets')

        result = []

        for secret in self.src_secret_client.list_properties_of_secrets():

            vault_secret = Secret(secret.name, secret.tags)

            if not secret.enabled or secret.content_type == 'application/x-pkcs12':
                continue

            for version in self.src_secret_client.list_properties_of_secret_versions(secret.name):
                
                secret_value  = self.src_secret_client.get_secret(version.name, version.version).value

                sv = SecretVersion(version.version, secret_value, version.content_type, version.expires_on, version.created_on, version.enabled, version.tags)

                vault_secret.versions.append(sv)

            
            vault_secret.versions = sorted(vault_secret.versions, key = lambda x: x.created_on)

            result.append(vault_secret)

        log.info('export secrets completed')

        return result
    

    def list_certs_from_dest_vault(self) -> list[set, set]:
         """
         returns 2 sets containing certs and deleted certs
         """

         log.info('exporting certs from dest vault')

         certs, deleted = set(), set()

         for c in self.dest_cert_client.list_properties_of_certificates():
              certs.add(c.name)

         for dc in self.dest_cert_client.list_deleted_certificates():
              deleted.add(dc.name)
         
         log.info('export dest certs completed')

         return certs, deleted
    

    def list_secrets_from_dest_vault(self) -> list[set, set]:
         """
         returns 2 sets containing secrets and deleted secrets
         """
         
         log.info('exporting secrets from dest vault')

         secrets, deleted = set(), set()

         for s in self.dest_secret_client.list_properties_of_secrets():
              secrets.add(s.name)

         for ds in self.dest_secret_client.list_deleted_secrets():
              deleted.add(ds.name)
         
         log.info('export dest secrets completed')

         return secrets, deleted
    

    def import_certs(self, src_vault: SourceKeyVault, dest_vault: DestinationVault):
         """
         - import will be ignored if dest vault contains a deleted object with same name
         - if dest vault contains same object name, and --ignore-import-if-exists is set to True, 
           will import object to dest vault causing a new version to be created
         """
         
         for cert in src_vault.certs:

            if cert.name in dest_vault.deleted_cert_names:
              log.warn(f'cert {cert.name} is found deleted in dest vault {dest_vault.name}, import is ignored')
              continue
              
            for version in cert.versions:
                
                log.info(f'importing cert: {cert.name} version: {version.version}')
                
                self.dest_cert_client.import_certificate(cert.name, version.cert, enabled=version.enable, tags=version.tags)

                log.info(f'Cert: {cert.name} version: {version.version} imported successfully')


    def import_secrets(self, src_vault: SourceKeyVault, dest_vault: DestinationVault):
         """
         - import will be ignored if dest vault contains a deleted object with same name
         - if dest vault contains same object name, and --ignore-import-if-exists is set to True, 
           will import object to dest vault causing a new version to be created
         """
         
         for secret in src_vault.secrets:
              
              if secret.name in dest_vault.deleted_secret_names:
                   log.warn(f'csecret {secret.name} is found deleted in dest vault {dest_vault.name}, import is ignored')
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
        
    def _is_cert_expired(self, expires_on):
         
         if self._as_utc_8(datetime.now()) >= self._as_utc_8(expires_on):
              return True
         return False


    def _as_utc_8(self, d: datetime):
         return d.astimezone(timezone('Asia/Kuala_Lumpur'))
                

                
#                public_key_bytes = '' #public_key_b64.encode() #base64.b64decode(public_key_b64)

                # with open(f'C:\\Users\\weixzha\\Desktop\\{version.name}_{version.version}.pem', 'wb') as pem_file:
                #     pem_file.write(private_key_b64.encode())
                    # Write the private key with appropriate PEM headers
                    # pem_file.write(b'-----BEGIN PRIVATE KEY-----\n')
                    # pem_file.write(base64.encodebytes(private_key_bytes))
                    # pem_file.write(b'-----END PRIVATE KEY-----\n\n')
                    
                    # # Write the public key with appropriate PEM headers
                    # pem_file.write(b'-----BEGIN PUBLIC KEY-----\n')
                    # pem_file.write(base64.encodebytes(public_key_bytes))
                    # pem_file.write(b'-----END PUBLIC KEY-----\n')

#                 '''

                # get private key

                # 

                # pass

                # get public key from key

                # get private key from secret
            

        # src_cert = self.src_cert_client.get_certificate('azfw-tls-inspection')
        # dest_cert = self.dest_cert_client.get_certificate('cert-4')

        # src_secret = self.src_secret_client.get_secret('test-azworkbench-com278c825a-2e2f-48ef-a861-68f74cbd66db')
        # src_cert = self.dest_secret_client.get_secret('temp3-secret-1')


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
    
    

    