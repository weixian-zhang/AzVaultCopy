import pytest
from unittest.mock import patch, Mock
from config import Config
from vault import VaultManager
from azure.keyvault.certificates import CertificateContentType, CertificatePolicy, CertificateProperties
from datetime import datetime
import os
import base64
config = Config(src_vault_name='akv-export', dest_vault_name='akv-temp-3')
vm = VaultManager(config)

pfx_cert = b''
pem_cert = b''
cwd = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(cwd, 'cert.pfx'), "rb") as f:
    pfx_bytes = f.read()
    b64c = base64.b64encode(pfx_bytes)
    pfx_cert = b64c.decode("utf-8")
with open(os.path.join(cwd, 'cert.pem'), "r") as f:
    pem_cert = f.read()

class TestVaultCerts:
    """
    unit test cases

    certs:
      
      export
        1 export 2 certs with 2 versions that are:
            - enabled
            - not expired
            - exportable
            - not deleted

          1.1 a cert with 2 versions should be sorted ascending by created_on:
              reason: latest version should be "last" so that when importing, the latest version will be inserted last,
              and becomes the latest/current version in destination vault
        
        2 ignore cert that is disabled
        3 ignore cert version that is disabled
        4 ignore cert version that is not exportable
          *note: AKV SDK only returns CertificatePolicy.exportable for the latest version, rest of older versions has no way to get their
           cert policy. To support importing older versions for completeness, when importing older versions that is not Exportable,
           catch exception "No private key is found" to determine if older cert versions are exportable or not

        5 ignore destination vault certs that were deleted

        6 with 2 cert versions, export only 1 version with conditions:
          - export 1 version that is Enabled
          - ignore 1 version that is Disabled

        7 with 2 cert versions, export only 1 version with conditions:
          - export 1 version that is Exportable
          - ignore 1 version that is Not Exportable

        8 with 2 cert versions, export only 1 version with conditions:
          - export 1 version that is Expired
          - ignore 1 version that is Not Expired

      import
        with patch("azure.keyvault.secrets.CertificateClient.import_certificate", return_value=key_vault_secret) as import_certificate:   
            import_certificate.side_effect = Exception('no certificate with private key private key is not')

        9 able to import 2 versions with mix of PFX and PEM format with, PEM being the latest version

        10 able to import 2 versions with mix of PFX and PEM format with, PEM being the latest version

    """

    def test_1_with_2_cert_versions_export_only_1_version_that_is_Enabled(self):
        """
        1 export 2 certs with 2 versions that are:
            - enabled
            - not expired
            - exportable
            - not deleted

          1.1 a cert with 2 versions should be sorted ascending by created_on:
              reason: latest version should be "last" so that when importing, the latest version will be inserted last,
              and becomes the latest/current version in destination vault
        """
        
        # mock.method.return_value = True
        cert_prop_1 = Mock()
        cert_prop_1.name = 'cert_1'
        cert_prop_1.enabled = True
        cert_prop_1.tags = {}

        version_1 = Mock()
        version_1.name = 'version_1'
        version_1.enabled = True
        version_1.version = 'v1'
        version_1.expires_on = datetime(2025,10,1)
        version_1.created_on = datetime(2024,1,1, 1, 0, 0)
        
        cert_prop_2 = Mock()
        cert_prop_2.name = 'cert_2'
        cert_prop_2.enabled = True
        cert_prop_2.tags = {}

        version_2 = Mock()
        version_2.name = 'version_2'
        version_2.enabled = True
        version_2.version = 'v2'
        version_2.expires_on = datetime(2025,10,1)
        version_2.created_on = datetime(2024,1,1, 2, 0, 0)

        key_vault_secret = Mock()
        key_vault_secret.value = pfx_cert

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12
        
        
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[cert_prop_1, cert_prop_2]):
          with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
            with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions", return_value=[version_1, version_2]):
              with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                 
                 result = vm.list_certs_from_src_vault()

                 for c in result:
                    assert len(c.versions) == 2
                    assert c.versions[1].created_on > c.versions[0].created_on

                 assert len(result) == 2


    def test_2_ignore_cert_that_is_Disabled(self):
        """
        2 ignore cert that is disabled
        """
        
        # mock.method.return_value = True
        cert_prop_1 = Mock()
        cert_prop_1.name = 'cert_1'
        cert_prop_1.enabled = False
        cert_prop_1.tags = {}

        version_1 = Mock()
        version_1.name = 'version_1'
        version_1.enabled = True
        version_1.version = 'v1'
        version_1.expires_on = datetime(2025,10,1)
        version_1.created_on = datetime(2024,1,1, 1, 0, 0)
        
        key_vault_secret = Mock()
        key_vault_secret.value = pfx_cert

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12
        
        
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[cert_prop_1]):
          with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
            with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions", return_value=[version_1]):
              with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                 
                 result = vm.list_certs_from_src_vault()

                #  for c in result:
                #     assert len(c.versions) == 2
                #     assert c.versions[1].created_on > c.versions[0].created_on

                 assert len(result) == 0



    def test_3_ignore_cert_version_that_is_Disabled(self):
        """
        3 ignore cert version that is disabled
        """
        
        # mock.method.return_value = True
        cert_prop_1 = Mock()
        cert_prop_1.name = 'cert_1'
        cert_prop_1.enabled = True
        cert_prop_1.tags = {}

        version_1 = Mock()
        version_1.name = 'version_1'
        version_1.enabled = True
        version_1.version = 'v1'
        version_1.expires_on = datetime(2025,10,1)
        version_1.created_on = datetime(2024,1,1, 1, 0, 0)

        version_2 = Mock()
        version_2.name = 'version_2'
        version_2.enabled = False
        version_2.version = 'v2'
        version_2.expires_on = datetime(2025,10,1)
        version_2.created_on = datetime(2024,1,1, 1, 0, 0)
        
        key_vault_secret = Mock()
        key_vault_secret.value = pfx_cert

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12
        
        
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[cert_prop_1]):
          with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
            with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions", return_value=[version_1, version_2]):
              with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                 
                 result = vm.list_certs_from_src_vault()
                 
                 assert len(result) == 1
                 assert len(result[0].versions) == 1



    def test_4_ignore_cert_version_that_is_Exportable(self):
        """
        4 ignore cert version that is not exportable
        """
        
        # mock.method.return_value = True
        cert_prop_1 = Mock()
        cert_prop_1.name = 'cert_1'
        cert_prop_1.enabled = True
        cert_prop_1.tags = {}

        version_1 = Mock()
        version_1.name = 'version_1'
        version_1.enabled = True
        version_1.version = 'v1'
        version_1.expires_on = datetime(2025,10,1)
        version_1.created_on = datetime(2024,1,1, 1, 0, 0)

        version_2 = Mock()
        version_2.name = 'version_2'
        version_2.enabled = False
        version_2.version = 'v2'
        version_2.expires_on = datetime(2025,10,1)
        version_2.created_on = datetime(2024,1,1, 1, 0, 0)
        
        key_vault_secret = Mock()
        key_vault_secret.value = pfx_cert

        cert_policy = Mock()
        cert_policy.exportable = False
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12
        
        
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[cert_prop_1]):
          with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
            with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions", return_value=[version_1, version_2]):
              with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                 
                    result = vm.list_certs_from_src_vault()
                    
                    assert len(result) == 0


    def test_5_get_destination_vault_certs_that_are_Active_and_Deleted(self):
        """
        5. get destination vault certs that are both Active and Deleted
        """
        
        cert_prop_1 = Mock()
        cert_prop_1.name = 'cert_1'
        cert_prop_1.enabled = True
        cert_prop_1.tags = {}

        cert_prop_2 = Mock()
        cert_prop_2.name = 'cert_2'
        cert_prop_2.enabled = True
        cert_prop_2.tags = {}

        deleted_cert_1 = Mock()
        deleted_cert_1.name = 'deleted_cert_1'

        deleted_cert_2 = Mock()
        deleted_cert_2.name = 'deleted_cert_2'
        
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[cert_prop_1, cert_prop_2]):
          with patch("azure.keyvault.certificates.CertificateClient.list_deleted_certificates", return_value=[deleted_cert_1, deleted_cert_2]):
                 
              active_certs, deleted_certs = vm.list_certs_from_dest_vault()
                    
              assert len(active_certs) == 2
              assert len(deleted_certs) == 2
                 



    

