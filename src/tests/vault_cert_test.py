from unittest.mock import patch, Mock
from config import Config
from vault import VaultManager
from azure.keyvault.certificates import CertificateContentType
from datetime import datetime
import os
import base64
from model import SourceKeyVault, DestinationVault, Cert, CertVersion

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

with open(os.path.join(cwd, 'cert_public_key_only.pem'), "r") as f:
    pem_cert_public_key_only = f.read()


class TestVaultCerts:
    """
    unit test cases

    certs:
      
      export
        1. export 2 certs with 2 versions that are:
            - enabled
            - not expired
            - exportable
            - not deleted

          1.1 a cert with 2 versions should be sorted ascending by created_on:
              reason: latest version should be "last" so that when importing, the latest version will be inserted last,
              and becomes the latest/current version in destination vault
        
        2. ignore cert that is disabled

        3. ignore cert version that is disabled

        4. ignore cert version that is not exportable

        5. ignore destination vault certs that were deleted


        6. out of 2 cert versions, export 1 version that is not Expired:
          - export 1 version that is Expired
          - ignore 1 version that is Not Expired

      import

        7. able to import 2 versions with mix of PFX and PEM format with, PEM being the latest version

        8. during import, able to handle if an older version has No Private Key with only Public Key,
           due to cert version is marked Not Exportable.
           
           *note: AKV SDK only returns CertificatePolicy.exportable for the latest version,
           rest of older versions has no way to determine if Exportable or not.
           If a cert is Not Exportable, the secret-private-key will only contains Public Key.
           This will post an issue during import-certificate which AKV expects any cert pem/pfx to have private key

           To support importing older versions for completeness, when importing older versions that is Not Exportable,
           catch exception thrown by CertificateClient.import_certificate with error: 
           "No private key is found" to determine if older cert versions are exportable or not
        
        9. ignore import if --no_import_if_dest_exist flag is True

        10. ignore import if cert is deleted at dest vault

    """

    def test_1_with_2_cert_versions_export_only_1_version_that_is_Enabled(self):
        """
        1. export 2 certs with 2 versions that are:
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
        2. ignore cert that is disabled
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

                 assert len(result) == 0



    def test_3_ignore_cert_version_that_is_Disabled(self):
        """
        3. ignore cert version that is disabled
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
        4. ignore cert version that is not exportable
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
                 

    def test_6_out_of_2_versions_export_only_1_version_that_is_Not_Expired(self):
        """
        6. with 2 cert versions, export only 1 version with conditions:
          - export 1 version that is Expired
          - ignore 1 version that is Not Expired 
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
        version_1.expires_on = datetime(2024,9,1) # expired
        version_1.created_on = datetime(2024,1,1, 1, 0, 0) 

        version_2 = Mock()
        version_2.name = 'version_2'
        version_2.enabled = True
        version_2.version = 'v2'
        version_2.expires_on = datetime(2026,10,1) # not expired
        version_2.created_on = datetime(2024,1,1, 1, 0, 0)
        
        key_vault_secret = Mock()
        key_vault_secret.value = pem_cert

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pem
        cert_policy.content_type = CertificateContentType.pem
        
        
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[cert_prop_1]):
          with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
            with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions", return_value=[version_1, version_2]):
              with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                 
                    result = vm.list_certs_from_src_vault()
                    
                    assert len(result) == 1
                    assert len(result[0].versions) == 1
                    assert result[0].versions[0].expires_on == datetime(2026,10,1)



    def test_7_out_of_2_versions_export_only_1_version_that_is_Not_Expired(self):
        """
        7. able to import 2 versions with mix of PFX and PEM format with, PEM being the latest version
        """
        
        # source vault prep

        src_vault = SourceKeyVault('src-vault')

        cert_1 = Cert('cert-1')

        cert_policy_1 = Mock()
        cert_policy_1.exportable = True
        cert_policy_1._content_type = CertificateContentType.pkcs12
        cert_policy_1.content_type = CertificateContentType.pkcs12

        cert_policy_2 = Mock()
        cert_policy_2.exportable = True
        cert_policy_2._content_type = CertificateContentType.pem
        cert_policy_2.content_type = CertificateContentType.pem

        version_1 = CertVersion('cert-1', 'v1', pem_cert, 'PEM', cert_policy=cert_policy_1, 
                                expires_on=datetime(2026,9,1), created_on=datetime(2024,1,1, 1, 0, 0),enable=True, tags={} )

        version_2 = CertVersion('cert-1', 'v2', pem_cert, 'PFX', cert_policy=cert_policy_2, 
                                expires_on=datetime(2026,9,1), created_on=datetime(2024,1,1, 1, 0, 0),enable=True, tags={} )
        
        cert_1.versions.append(version_1)
        cert_1.versions.append(version_2)

        src_vault.certs.append(cert_1)


        # dest vault prep

        dest_vault = DestinationVault('src-vault')

        
        with patch("azure.keyvault.certificates.CertificateClient.import_certificate") as import_certificate:   
          #import_certificate.side_effect = Exception('no certificate with private key private key is not')

          result = vm.import_certs(src_vault=src_vault, dest_vault=dest_vault)
          
          assert len(result) == 2





    def test_8_able_to_process_cert_without_private_key_without_error(self):
        """
        8. during import, able to handle if an older version has No Private Key with only Public Key,
           due to cert version is marked Not Exportable.
           
           *note: AKV SDK only returns CertificatePolicy.exportable for the latest version,
           rest of older versions has no way to determine if Exportable or not.
           If a cert is Not Exportable, the secret-private-key will only contains Public Key.
           This will post an issue during import-certificate which AKV expects any cert pem/pfx to have private key

           To support importing older versions for completeness, when importing older versions that is Not Exportable,
           catch exception thrown by CertificateClient.import_certificate with error: 
           "No private key is found" to determine if older cert versions are exportable or not
        """
        
        # source vault prep

        src_vault = SourceKeyVault('src-vault')

        cert_1 = Cert('cert-1')

        cert_policy_1 = Mock()
        cert_policy_1.exportable = True
        cert_policy_1._content_type = CertificateContentType.pkcs12
        cert_policy_1.content_type = CertificateContentType.pkcs12

        cert_policy_2 = Mock()
        cert_policy_2.exportable = True
        cert_policy_2._content_type = CertificateContentType.pem
        cert_policy_2.content_type = CertificateContentType.pem

        version_1 = CertVersion('cert-1', 'v1', pem_cert_public_key_only, 'PEM', cert_policy=cert_policy_1, 
                                expires_on=datetime(2026,9,1), created_on=datetime(2024,1,1, 1, 0, 0),enable=True, tags={} )

        version_2 = CertVersion('cert-1', 'v2', pem_cert, 'PFX', cert_policy=cert_policy_2, 
                                expires_on=datetime(2026,9,1), created_on=datetime(2024,1,1, 1, 0, 0),enable=True, tags={} )
        
        # cert_1.versions.append(version_2)
        cert_1.versions.append(version_1)

        src_vault.certs.append(cert_1)


        # dest vault prep

        dest_vault = DestinationVault('src-vault')

        
        with patch("azure.keyvault.certificates.CertificateClient.import_certificate") as import_certificate:   

          import_certificate.side_effect = Exception('no certificate with private key private key is not')#Mock(side_effect=side_effect_throw_err_on_2nd_iteration())

          result = vm.import_certs(src_vault=src_vault, dest_vault=dest_vault)
          
          assert len(result) == 0


    def test_9_ignore_import_if_No_Import_If_Dest_Exist_Flag_is_True(self):
        """
        9. ignore import if --no_import_if_dest_exist flag is True
        """
        
        config.no_import_if_dest_exist = True

        src_vault = SourceKeyVault('src-vault')

        # cert 1, exists in dest vault and should be ignored
        cert_1 = Cert('cert-1')

        cert_policy_1 = Mock()
        cert_policy_1.exportable = True
        cert_policy_1._content_type = CertificateContentType.pkcs12
        cert_policy_1.content_type = CertificateContentType.pkcs12


        version_1 = CertVersion('cert-1', 'v1', pem_cert, 'PEM', cert_policy=cert_policy_1, 
                                expires_on=datetime(2026,9,1), created_on=datetime(2024,1,1, 1, 0, 0),enable=True, tags={} )

        
        cert_1.versions.append(version_1)


        # cert 2, should be imported
        cert_2 = Cert('cert-2')

        cert_policy_2 = Mock()
        cert_policy_2.exportable = True
        cert_policy_2._content_type = CertificateContentType.pkcs12
        cert_policy_2.content_type = CertificateContentType.pkcs12


        version_2 = CertVersion('cert-1', 'v1', pem_cert, 'PEM', cert_policy=cert_policy_2, 
                                expires_on=datetime(2026,9,1), created_on=datetime(2024,1,1, 1, 0, 0),enable=True, tags={} )

        cert_2.versions.append(version_2)


        src_vault.certs.append(cert_1)
        src_vault.certs.append(cert_2)


        # dest vault prep

        dest_vault = DestinationVault('src-vault')
        dest_vault.cert_names = ['cert-1']

        
        with patch("azure.keyvault.certificates.CertificateClient.import_certificate") as import_certificate:   

          result = vm.import_certs(src_vault=src_vault, dest_vault=dest_vault)
          
          assert len(result) == 1


    
    def test_10_ignore_import_if_cert_is_deleted_at_dest_vault(self):
        """
        10. ignore import if cert is deleted at dest vault
        """
        
        config.no_import_if_dest_exist = True

        src_vault = SourceKeyVault('src-vault')

        # cert 1, exists in dest vault and should be ignored
        cert_1 = Cert('cert-1')

        cert_policy_1 = Mock()
        cert_policy_1.exportable = True
        cert_policy_1._content_type = CertificateContentType.pkcs12
        cert_policy_1.content_type = CertificateContentType.pkcs12


        version_1 = CertVersion('cert-1', 'v1', pem_cert, 'PEM', cert_policy=cert_policy_1, 
                                expires_on=datetime(2026,9,1), created_on=datetime(2024,1,1, 1, 0, 0),enable=True, tags={} )
        cert_1.versions.append(version_1)


        # cert 2, should be imported
        cert_2 = Cert('cert-2')

        cert_policy_2 = Mock()
        cert_policy_2.exportable = True
        cert_policy_2._content_type = CertificateContentType.pkcs12
        cert_policy_2.content_type = CertificateContentType.pkcs12


        version_2 = CertVersion('cert-1', 'v1', pem_cert, 'PEM', cert_policy=cert_policy_2, 
                                expires_on=datetime(2026,9,1), created_on=datetime(2024,1,1, 1, 0, 0),enable=True, tags={})
        cert_2.versions.append(version_2)


        src_vault.certs.append(cert_1)
        src_vault.certs.append(cert_2)

        # dest vault prep

        dest_vault = DestinationVault('src-vault')
        dest_vault.deleted_cert_names = ['cert-1']

        
        with patch("azure.keyvault.certificates.CertificateClient.import_certificate") as import_certificate:   
          #import_certificate.side_effect = Exception('no certificate with private key private key is not')

          result = vm.import_certs(src_vault=src_vault, dest_vault=dest_vault)
          
          assert len(result) == 1

    

    
        

