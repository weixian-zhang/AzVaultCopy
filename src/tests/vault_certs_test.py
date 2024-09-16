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
      - export 2 certs with 2 versions that are:
          - enabled
          - not expired
          - exportable
          - not deleted

      - a cert with 2 versions should be sorted ascending by created_on:
          reason: latest version should be "last" so that when importing, the latest version will be inserted last,
          and becomes the latest/current version in destination vault
      
      - ignore cert that is disabled
      - ignore cert that is not exportable
      - ignore cert that was deleted

      - with 2 cert versions, export only 1 version with conditions:
        - export 1 version that is Enabled
        - ignore 1 version that is Disabled

      - with 2 cert versions, export only 1 version with conditions:
        - export 1 version that is Exportable
        - ignore 1 version that is Not Exportable

      - with 2 cert versions, export only 1 version with conditions:
        - export 1 version that is Expired
        - ignore 1 version that is Not Expired

      - able to import version with PFX format

      - able to import version with PEM format

      
    """

    def test_with_2_cert_versions_export_only_1_version_that_is_Enabled(self):
        
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
    

