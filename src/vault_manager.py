from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient, CertificatePolicy
from azure.keyvault.secrets import SecretClient
from config import Config
import base64 
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from datetime import datetime
from model import Cert, CertVersion, Secret, SecretVersion
from pytz import timezone

# example
# https://github.com/Azure/azure-sdk-for-python/blob/main/sdk/keyvault/azure-keyvault-certificates/samples/parse_certificate.py
# https://stackoverflow.com/questions/58313018/how-to-get-private-key-from-certificate-in-an-azure-key-vault
class VaultManager:
    
    def __init__(self, config: Config,) -> None:
        self.config = config

        self.src_cert_client = CertificateClient(config.get_src_vault_url(), config.source_azure_cred)
        self.src_secret_client = SecretClient(config.get_src_vault_url(), config.source_azure_cred)
        #self.src_key_client = KeyClient(config.get_src_vault_url(), config.source_azure_cred)

        self.dest_cert_client = CertificateClient(config.get_dest_vault_url(), config.dest_azure_cred)
        self.dest_secret_client = SecretClient(config.get_dest_vault_url(), config.dest_azure_cred)

    
    def list_certs(self) -> list[Cert]:
        """
        return: list[Cert] will be sorted with "created_on" so that during import,
        oldest will be created first and the last item will be the latest current version in destination vault
        """

        result = []

        for cert_prop in self.src_cert_client.list_properties_of_certificates():

            cert = Cert(cert_prop.name, cert_prop.tags)

            for version in self.src_cert_client.list_properties_of_certificate_versions(cert_prop.name):
                
                cert_policy = self.src_cert_client.get_certificate_policy(cert_prop.name)

                # check expiring
                if not cert_policy.exportable:
                     # TODO: log
                     continue
                if self._is_cert_expired(version.expires_on):
                     # TODO: log
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

        return result
    

    def list_secrets(self) -> list[Secret]:
        """
        will ignore secret.content_type == 'application/x-pkcs12' created by certificates to store private key
        """
        
        result = []

        for secret in self.src_secret_client.list_properties_of_secrets():

            vault_secret = Secret(secret.name, secret.tags)

            if not secret.enabled or secret.content_type == 'application/x-pkcs12':
                continue

            for version in self.src_secret_client.list_properties_of_secret_versions(secret.name):
                 
                secret_value  = self.src_secret_client.get_secret(version.name, version.version).value

                sv = SecretVersion(version.version, secret_value, version.expires_on, version.created_on, version.tags)

                vault_secret.versions.append(sv)

            
            vault_secret.versions = sorted(vault_secret.versions, key = lambda x: x.created_on)

            result.append(vault_secret)

        return result


            
        





    
    def _is_cert_expired(self, expires_on):
         
         if datetime.now().astimezone(timezone('Asia/Kuala_Lumpur')) >= expires_on.astimezone(timezone('Asia/Kuala_Lumpur')):
              return True
         return False
                
                
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


    # def list_secrets(self):

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
    

    # def list_certs(self):
        
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
    
    

    