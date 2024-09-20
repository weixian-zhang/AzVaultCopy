from unittest.mock import patch, Mock
from src.config import Config
from src.vault import VaultManager
from azure.keyvault.certificates import CertificateContentType
from datetime import datetime
import os
import base64
from src.model import SourceKeyVault, DestinationVault, Cert, CertVersion, RunContext, Secret, SecretVersion, RunContext
from src.export_import import ExportImporter

config = Config(src_vault_name='akv-export', dest_vault_name='akv-temp-3')


pfx_cert = b''
pfx_cert_str = ''
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


class TestCertReportStats:
    """
    unit test cases

    cert object level
        1. total certs matches total exported certs

    cert version stats and detail
        2. version disabled
            2.1 exported certs is less than total exported certs
            2.2 matrix flags are correctly set

        3. version expired
            3.1 imported cert is less than exported cert due to expired cert cannot be import
            3.2 matrix flags are correctly set
                - is_imported = false
                - is_marked_as_exportable = false
                - is_expired = true
    
        4. all versions are imported
            4.1 total versions = exported = imported versions
            4.2 matrix flags are correctly set
                - is_imported = true
                - is_exported = true

    
    secret object level
        5. total matches total exported secrets

        6. version disabled
            6.1 exported secrets is less than total exported secrets
            6.2 matrix flags are correctly set

        7. version expired
            7.1 imported cert is less than exported cert due to expired cert cannot be import
            7.2 matrix flags are correctly set
                - is_imported = false
                - is_marked_as_exportable = false
                - is_expired = true

        8. all versions are imported
            4.1 total versions = exported = imported versions
            4.2 matrix flags are correctly set
                - is_imported = true
                - is_exported = true

    """


    def test_1_total_versions_matches_exported_certs(self):
        """
        1. total certs matches total exported certs
        """
        export_importer = ExportImporter(config)
        run_context = export_importer.run_context
        config.export_only = True

        cert_prop_1 = Mock()
        cert_prop_1.name = 'cert_1'
        cert_prop_1.enabled = True
        cert_prop_1.tags = {}

        cert_prop_2 = Mock()
        cert_prop_2.name = 'cert_2'
        cert_prop_2.enabled = True
        cert_prop_2.tags = {}

        version_1_1 = Mock()
        version_1_1.name = 'version_1_1'
        version_1_1.enabled = True
        version_1_1.version = 'v11'
        version_1_1.expires_on = datetime(2025,10,1)
        version_1_1.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_1.is_exported = False
        version_1_1.is_imported = False

        version_1_2 = Mock()
        version_1_2.name = 'version_1_2'
        version_1_2.enabled = True
        version_1_2.version = 'v12'
        version_1_2.expires_on = datetime(2025,10,1)
        version_1_2.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_2.is_exported = False
        version_1_2.is_imported = False
        
        version_2_1 = Mock()
        version_2_1.name = 'version_2_1'
        version_2_1.enabled = True
        version_2_1.version = 'v2'
        version_2_1.expires_on = datetime(2025,10,1)
        version_2_1.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_1.is_exported = False
        version_2_1.is_imported = False

        version_2_2 = Mock()
        version_2_2.name = 'version_2_2'
        version_2_2.enabled = True
        version_2_2.version = 'v2'
        version_2_2.expires_on = datetime(2025,10,1)
        version_2_2.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_2.is_exported = False
        version_2_2.is_imported = False

        key_vault_secret = Mock()
        key_vault_secret.value = pfx_cert

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12


        def yield_cert_version(cert_name):
            if cert_name == 'cert_1':
                yield version_1_1
                yield version_1_2
            else:
                yield version_2_1
                yield version_2_2

        
        # patch akv cert api
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[cert_prop_1, cert_prop_2]):
            with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
                with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions") as cert_client_list_versions:
                    with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                        # patch akv secret api
                         with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[]):
                            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions", return_value=[]):
                        
                                    cert_client_list_versions.side_effect = yield_cert_version
                                    
                                    export_importer.run()

                                    assert run_context.total_certs == run_context.total_exported_certs

                                    assert len([x for x in run_context.src_vault.certs if x.is_exported]) == 2

                                    for x in run_context.src_vault.certs:
                                        assert len([x for x in x.versions if x.is_exported]) == 2



    def test_2_version_disabled_exported_certs_less_than_total(self):
        """
        2. version disabled
            2.1 exported certs is less than total exported certs
            2.2 matrix flags are correctly set
        """
        export_importer = ExportImporter(config)
        run_context = export_importer.run_context

        config.export_only = True

        # certs
        cert_prop_1 = Mock()
        cert_prop_1.name = 'cert_1'
        cert_prop_1.enabled = True
        cert_prop_1.tags = {}

        cert_prop_2 = Mock()
        cert_prop_2.name = 'cert_2'
        cert_prop_2.enabled = True
        cert_prop_2.tags = {}

        # versions
        version_1_1 = Mock()
        version_1_1.name = 'version_1_1'
        version_1_1.enabled = True
        version_1_1.version = 'v11'
        version_1_1.expires_on = datetime(2025,10,1)
        version_1_1.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_1.is_exported = False
        version_1_1.is_imported = False

        version_1_2 = Mock()
        version_1_2.name = 'version_1_2'
        version_1_2.enabled = False # disabled
        version_1_2.version = 'v12'
        version_1_2.expires_on = datetime(2025,10,1)
        version_1_2.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_2.is_exported = False
        version_1_2.is_imported = False
        
        version_2_1 = Mock()
        version_2_1.name = 'version_2_1'
        version_2_1.enabled = True
        version_2_1.version = 'v2'
        version_2_1.expires_on = datetime(2025,10,1)
        version_2_1.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_1.is_exported = False
        version_2_1.is_imported = False

        version_2_2 = Mock()
        version_2_2.name = 'version_2_2'
        version_2_2.enabled = False # disabled
        version_2_2.version = 'v2'
        version_2_2.expires_on = datetime(2025,10,1)
        version_2_2.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_2.is_exported = False
        version_2_2.is_imported = False

        key_vault_secret = Mock()
        key_vault_secret.value = pfx_cert

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12


        def yield_cert_version(cert_name):
            if cert_name == 'cert_1':
                yield version_1_1
                yield version_1_2
            else:
                yield version_2_1
                yield version_2_2

        
        # patch akv cert api
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[cert_prop_1, cert_prop_2]):
            with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
                with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions") as cert_client_list_versions:
                    with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                        # patch akv secret api
                         with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[]):
                            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions", return_value=[]):
                        
                                    cert_client_list_versions.side_effect = yield_cert_version
                                    
                                    export_importer.run()

                                    assert run_context.total_exported_certs == 2
                                    assert run_context.total_certs == 2
                                    assert run_context.total_certs == run_context.total_exported_certs

                                    assert len([x for x in run_context.src_vault.certs if x.is_exported]) == 2

                                    for x in run_context.src_vault.certs:
                                        assert len([x for x in x.versions if x.is_exported]) == 1



    def test_3_version_expired_import_less_than_exported(self):
        """
        3. version expired
            3.1 imported cert is less than exported cert due to expired cert cannot be import
            3.2 matrix flags are correctly set
                - is_imported
        """
        export_importer = ExportImporter(config)
        run_context = export_importer.run_context

        config.export_only = False

        # certs
        cert_prop_1 = Mock()
        cert_prop_1.name = 'cert_1'
        cert_prop_1.enabled = True
        cert_prop_1.tags = {}

        cert_prop_2 = Mock()
        cert_prop_2.name = 'cert_2'
        cert_prop_2.enabled = True
        cert_prop_2.tags = {}

        # versions

        version_1_2 = Mock()
        version_1_2.name = 'version_1_2'
        version_1_2.enabled = True
        version_1_2.version = 'version_1_2'
        version_1_2.expires_on = datetime(2024,6,1) # expired
        version_1_2.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_2.is_exported = False
        version_1_2.is_imported = False
        

        version_2_2 = Mock()
        version_2_2.name = 'version_2_2'
        version_2_2.enabled = True
        version_2_2.version = 'version_1_2'
        version_2_2.expires_on = datetime(2024,6,1)  # expired
        version_2_2.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_2.is_exported = False
        version_2_2.is_imported = False

        key_vault_secret = Mock()
        key_vault_secret.value = pfx_cert

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12


        run_context.dest_vault = DestinationVault('')
        run_context.dest_vault.cert_names = []
        run_context.dest_vault.deleted_cert_names = []
        run_context.dest_vault.secret_names = []
        run_context.dest_vault.deleted_secret_names = []


        def yield_cert_version(cert_name):
            if cert_name == 'cert_1':
                yield version_1_2
            else:
                yield version_2_2

        
        # patch akv cert api
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[cert_prop_1, cert_prop_2]):
            with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
                with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions") as cert_client_list_versions:
                    # ignore dest vault list cert names
                    with patch('src.export_import.ExportImporter.export_from_dest_vault'):
                        # patch akv secret api
                        with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[]):
                                with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions", return_value=[]):
                                    with patch("azure.keyvault.certificates.CertificateClient.import_certificate") as import_certificate:

                                        import_certificate.side_effect = Exception('no certificate with private key private key is not')
                            
                                        cert_client_list_versions.side_effect = yield_cert_version
                                        
                                        export_importer.run()

                                        assert run_context.total_certs > run_context.total_exported_certs

                                        assert len([x for x in run_context.src_vault.certs if x.is_imported]) == 0

                                        for x in run_context.src_vault.certs:
                                            assert len([x for x in x.versions if x.is_imported]) == 0

                                            for v in x.versions:
                                                if v.version == 'version_1_2':
                                                    assert v.is_expired
                                                    assert not v.is_cert_marked_as_exportable
                                                if v.version == 'version_2_2':
                                                    assert v.is_expired
                                                    assert not v.is_cert_marked_as_exportable



    def test_4_all_versions_are_imported(self):
        """
        4. all versions are imported
            4.1 total versions = exported = imported versions
            4.2 matrix flags are correctly set
                - is_imported = true
                - is_exported = true
        """
        export_importer = ExportImporter(config)
        run_context = export_importer.run_context
        config.export_only = False

        # certs
        cert_prop_1 = Mock()
        cert_prop_1.name = 'cert_1'
        cert_prop_1.enabled = True
        cert_prop_1.tags = {}

        cert_prop_2 = Mock()
        cert_prop_2.name = 'cert_2'
        cert_prop_2.enabled = True
        cert_prop_2.tags = {}

        # versions

        version_1_2 = Mock()
        version_1_2.name = 'version_1_2'
        version_1_2.enabled = True
        version_1_2.version = 'version_1_2'
        version_1_2.expires_on = datetime(2026,6,1)
        version_1_2.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_2.is_exported = False
        version_1_2.is_imported = False
        

        version_2_2 = Mock()
        version_2_2.name = 'version_2_2'
        version_2_2.enabled = True
        version_2_2.version = 'version_1_2'
        version_2_2.expires_on = datetime(2026,6,1)
        version_2_2.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_2.is_exported = False
        version_2_2.is_imported = False

        key_vault_secret = Mock()
        key_vault_secret.value = pfx_cert

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12


        run_context.dest_vault = DestinationVault('')
        run_context.dest_vault.cert_names = []
        run_context.dest_vault.deleted_cert_names = []
        run_context.dest_vault.secret_names = []
        run_context.dest_vault.deleted_secret_names = []


        def yield_cert_version(cert_name):
            if cert_name == 'cert_1':
                yield version_1_2
            else:
                yield version_2_2

        
        # patch akv cert api
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[cert_prop_1, cert_prop_2]):
            with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
                with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions") as cert_client_list_versions:
                    # ignore dest vault list cert names
                    with patch('src.export_import.ExportImporter.export_from_dest_vault'):
                        # patch akv secret api
                        with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[]):
                                with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions", return_value=[]):
                                    with patch("azure.keyvault.certificates.CertificateClient.import_certificate") as import_certificate:

                                        #import_certificate.side_effect = Exception('no certificate with private key private key is not')
                            
                                        cert_client_list_versions.side_effect = yield_cert_version
                                        
                                        export_importer.run()

                                        assert run_context.total_certs == run_context.total_exported_certs

                                        assert len([x for x in run_context.src_vault.certs if x.is_imported]) == 2

                                        for x in run_context.src_vault.certs:
                                            assert len([x for x in x.versions if x.is_imported]) == 1

                                            for v in x.versions:
                                                if v.version == 'version_1_2':
                                                    assert v.is_imported == True
                                                    assert v.is_exported == True
                                                if v.version == 'version_2_2':
                                                    assert v.is_imported == True
                                                    assert v.is_exported == True



    def test_secret_5_total_versions_matches_exported_secrets(self):
        """
        5. total certs matches total exported certs
        """
        export_importer = ExportImporter(config)
        run_context = export_importer.run_context
        config.export_only = True

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12

        # secret

        secret_1 = Mock()
        secret_1.name = 'secret_1'
        secret_1.enabled = True
        secret_1.tags = {}
        secret_1.is_exported = False
        secret_1.is_imported = False


        secret_2 = Mock()
        secret_2.name = 'secret_2'
        secret_2.enabled = True
        secret_2.tags = {}
        secret_2.is_exported = False
        secret_2.is_imported = False


        version_1_1 = Mock()
        version_1_1.name = 'version_1_1'
        version_1_1.enabled = True
        version_1_1.version = 'version_1_1'
        version_1_1.expires_on = datetime(2026,10,1)
        version_1_1.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_1.content_type = None
        version_1_1.is_exported = False
        version_1_1.is_imported = False

        version_1_2 = Mock()
        version_1_2.name = 'version_1_2'
        version_1_2.enabled = True
        version_1_2.version = 'version_1_2'
        version_1_2.expires_on = datetime(2026,10,1)
        version_1_2.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_2.content_type = None
        version_1_2.is_exported = False
        version_1_2.is_imported = False

        version_2_1 = Mock()
        version_2_1.name = 'version_2_1'
        version_2_1.enabled = True
        version_2_1.version = 'version_2_1'
        version_2_1.expires_on = datetime(2026,10,1)
        version_2_1.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_1.content_type = ''
        version_2_1.is_exported = False
        version_2_1.is_imported = False

        version_2_2 = Mock()
        version_2_2.name = 'version_2_2'
        version_2_2.enabled = True
        version_2_2.version = 'version_2_2'
        version_2_2.expires_on = datetime(2026,10,1)
        version_2_2.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_2.content_type = ''
        version_2_2.is_exported = False
        version_2_2.is_imported = False
        
        key_vault_secret = Mock()
        key_vault_secret.value = 'I am a secret'


        def yield_version(cert_name):
            if cert_name == 'secret_1':
                yield version_1_1
                yield version_1_2
            else:
                yield version_2_1
                yield version_2_2

        
        # patch akv cert api
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[]):
            with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
                with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions") as cert_client_list_versions:
                    # patch akv secret api
                        with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[secret_1, secret_2]):
                            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions") as secret_client_list_versions:
                                with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                                    
                                    secret_client_list_versions.side_effect = yield_version
                                    
                                    export_importer.run()

                                    assert run_context.total_secrets == run_context.total_exported_secrets

                                    assert len([x for x in run_context.src_vault.secrets if x.is_exported]) == 2

                                    for x in run_context.src_vault.secrets:
                                        assert len([x for x in x.versions if x.is_exported]) == 2


    
    def test_secret_6_version_disabled_total_less_than_exported(self):
        """
        6. version disabled
            6.1 exported secrets is less than total exported secrets
            6.2 matrix flags are correctly set
        """
        export_importer = ExportImporter(config)
        run_context = export_importer.run_context
        config.export_only = True

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12

        # secret

        secret_1 = Mock()
        secret_1.name = 'secret_1'
        secret_1.enabled = True
        secret_1.tags = {}
        secret_1.is_exported = False
        secret_1.is_imported = False


        secret_2 = Mock()
        secret_2.name = 'secret_2'
        secret_2.enabled = False
        secret_2.tags = {}
        secret_2.is_exported = False
        secret_2.is_imported = False


        version_1_1 = Mock()
        version_1_1.name = 'version_1_1'
        version_1_1.enabled = True
        version_1_1.version = 'version_1_1'
        version_1_1.expires_on = datetime(2026,10,1)
        version_1_1.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_1.content_type = None
        version_1_1.is_exported = False
        version_1_1.is_imported = False

        version_1_2 = Mock()
        version_1_2.name = 'version_1_2'
        version_1_2.enabled = False
        version_1_2.version = 'version_1_2'
        version_1_2.expires_on = datetime(2026,10,1)
        version_1_2.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_2.content_type = None
        version_1_2.is_exported = False
        version_1_2.is_imported = False

        version_2_1 = Mock()
        version_2_1.name = 'version_2_1'
        version_2_1.enabled = False
        version_2_1.version = 'version_2_1'
        version_2_1.expires_on = datetime(2026,10,1)
        version_2_1.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_1.content_type = ''
        version_2_1.is_exported = False
        version_2_1.is_imported = False

        version_2_2 = Mock()
        version_2_2.name = 'version_2_2'
        version_2_2.enabled = True
        version_2_2.version = 'version_2_2'
        version_2_2.expires_on = datetime(2026,10,1)
        version_2_2.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_2.content_type = ''
        version_2_2.is_exported = False
        version_2_2.is_imported = False
        
        key_vault_secret = Mock()
        key_vault_secret.value = 'I am a secret'


        def yield_version(cert_name):
            if cert_name == 'secret_1':
                yield version_1_1
                yield version_1_2
            else:
                yield version_2_1
                yield version_2_2

        
        # patch akv cert api
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[]):
            with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
                with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions") as cert_client_list_versions:
                    # patch akv secret api
                        with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[secret_1, secret_2]):
                            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions") as secret_client_list_versions:
                                with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                                    
                                    secret_client_list_versions.side_effect = yield_version
                                    
                                    export_importer.run()

                                    assert run_context.total_secrets == run_context.total_exported_secrets

                                    assert len([x for x in run_context.src_vault.secrets if x.is_exported]) == 2

                                    for x in run_context.src_vault.secrets:
                                        if x.name == 'secret_1':
                                            assert len([x for x in x.versions if x.is_exported]) == 1
                                        else:
                                            assert len([x for x in x.versions if x.is_exported]) == 1


                                        for v in x.versions:
                                            if v.version == 'version_1_2':
                                                assert not v.is_expired
                                                assert not v.is_exported
                                                assert not v.is_imported
                                            if v.version == 'version_2_1':
                                                assert not v.is_expired
                                                assert not v.is_exported
                                                assert not v.is_imported



    def test_secret_7_version_expired_exported_less_than_total(self):
        """
        7. version expired
            7.1 imported cert is less than exported cert due to expired cert cannot be import
            7.2 matrix flags are correctly set
                - is_imported = false
                - is_marked_as_exportable = false
                - is_expired = true
        """

        export_importer = ExportImporter(config)
        run_context = export_importer.run_context
        config.export_only = False

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12

        # secret

        secret_1 = Mock()
        secret_1.name = 'secret_1'
        secret_1.enabled = True
        secret_1.tags = {}
        secret_1.is_exported = False
        secret_1.is_imported = False


        secret_2 = Mock()
        secret_2.name = 'secret_2'
        secret_2.enabled = True
        secret_2.tags = {}
        secret_2.is_exported = False
        secret_2.is_imported = False


        version_1_1 = Mock()
        version_1_1.name = 'version_1_1'
        version_1_1.enabled = True
        version_1_1.version = 'version_1_1'
        version_1_1.expires_on = datetime(2023,10,1) # expired
        version_1_1.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_1.content_type = None
        version_1_1.is_exported = False
        version_1_1.is_imported = False

        version_1_2 = Mock()
        version_1_2.name = 'version_1_2'
        version_1_2.enabled = True
        version_1_2.version = 'version_1_2'
        version_1_2.expires_on = datetime(2026,10,1)
        version_1_2.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_2.content_type = None
        version_1_2.is_exported = False
        version_1_2.is_imported = False

        version_2_1 = Mock()
        version_2_1.name = 'version_2_1'
        version_2_1.enabled = True
        version_2_1.version = 'version_2_1'
        version_2_1.expires_on = datetime(2026,10,1)
        version_2_1.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_1.content_type = ''
        version_2_1.is_exported = False
        version_2_1.is_imported = False

        version_2_2 = Mock()
        version_2_2.name = 'version_2_2'
        version_2_2.enabled = True
        version_2_2.version = 'version_2_2'
        version_2_2.expires_on = datetime(2023,10,1) # expired
        version_2_2.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_2.content_type = ''
        version_2_2.is_exported = False
        version_2_2.is_imported = False
        
        key_vault_secret = Mock()
        key_vault_secret.value = 'I am a secret'

        run_context.dest_vault = DestinationVault('')
        run_context.dest_vault.cert_names = []
        run_context.dest_vault.deleted_cert_names = []
        run_context.dest_vault.secret_names = []
        run_context.dest_vault.deleted_secret_names = []


        def yield_version(cert_name):
            if cert_name == 'secret_1':
                yield version_1_1
                yield version_1_2
            else:
                yield version_2_1
                yield version_2_2

        
        # patch akv cert api
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[]):
            with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
                with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions") as cert_client_list_versions:
                    # ignore dest vault list cert names
                    with patch('src.export_import.ExportImporter.export_from_dest_vault'):
                        # patch akv secret api
                        with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[secret_1, secret_2]):
                            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions") as secret_client_list_versions:
                                with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                                    with patch("azure.keyvault.secrets.SecretClient.set_secret"):

                                        secret_client_list_versions.side_effect = yield_version
                                        
                                        export_importer.run()

                                        assert run_context.total_secrets == run_context.total_exported_secrets

                                        assert len([x for x in run_context.src_vault.secrets if x.is_exported]) == 2

                                        for x in run_context.src_vault.secrets:
                                            assert len([x for x in x.versions if x.is_exported]) == 1

                                            for v in x.versions:
                                                if v.version == 'version_1_1':
                                                    assert v.is_expired
                                                    assert not v.is_exported
                                                    assert not v.is_imported
                                                elif v.version == 'version_2_2':
                                                    assert v.is_expired
                                                    assert not v.is_exported
                                                    assert not v.is_imported
                                                else:
                                                    assert not v.is_expired
                                                    assert v.is_exported
                                                    assert v.is_imported
                                                


    def test_8_all_versions_are_imported(self):
        """
        8. all versions are imported
            4.1 total versions = exported = imported versions
            4.2 matrix flags are correctly set
                - is_imported = true
                - is_exported = true
        """

        export_importer = ExportImporter(config)
        run_context = export_importer.run_context
        config.export_only = False

        cert_policy = Mock()
        cert_policy.exportable = True
        cert_policy._content_type = CertificateContentType.pkcs12
        cert_policy.content_type = CertificateContentType.pkcs12

        # secret

        secret_1 = Mock()
        secret_1.name = 'secret_1'
        secret_1.enabled = True
        secret_1.tags = {}
        secret_1.is_exported = False
        secret_1.is_imported = False


        secret_2 = Mock()
        secret_2.name = 'secret_2'
        secret_2.enabled = True
        secret_2.tags = {}
        secret_2.is_exported = False
        secret_2.is_imported = False


        version_1_1 = Mock()
        version_1_1.name = 'version_1_1'
        version_1_1.enabled = True
        version_1_1.version = 'version_1_1'
        version_1_1.expires_on = datetime(2027,10,1)
        version_1_1.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_1.content_type = None
        version_1_1.is_exported = False
        version_1_1.is_imported = False

        version_1_2 = Mock()
        version_1_2.name = 'version_1_2'
        version_1_2.enabled = True
        version_1_2.version = 'version_1_2'
        version_1_2.expires_on = datetime(2027,10,1)
        version_1_2.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1_2.content_type = None
        version_1_2.is_exported = False
        version_1_2.is_imported = False

        version_2_1 = Mock()
        version_2_1.name = 'version_2_1'
        version_2_1.enabled = True
        version_2_1.version = 'version_2_1'
        version_2_1.expires_on = datetime(2027,10,1)
        version_2_1.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_1.content_type = ''
        version_2_1.is_exported = False
        version_2_1.is_imported = False

        version_2_2 = Mock()
        version_2_2.name = 'version_2_2'
        version_2_2.enabled = True
        version_2_2.version = 'version_2_2'
        version_2_2.expires_on = datetime(2027,10,1)
        version_2_2.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2_2.content_type = ''
        version_2_2.is_exported = False
        version_2_2.is_imported = False
        
        key_vault_secret = Mock()
        key_vault_secret.value = 'I am a secret'

        run_context.dest_vault = DestinationVault('')
        run_context.dest_vault.cert_names = []
        run_context.dest_vault.deleted_cert_names = []
        run_context.dest_vault.secret_names = []
        run_context.dest_vault.deleted_secret_names = []


        def yield_version(cert_name):
            if cert_name == 'secret_1':
                yield version_1_1
                yield version_1_2
            else:
                yield version_2_1
                yield version_2_2

        
        # patch akv cert api
        with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[]):
            with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
                with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions") as cert_client_list_versions:
                    # ignore dest vault list cert names
                    with patch('src.export_import.ExportImporter.export_from_dest_vault'):
                        # patch akv secret api
                        with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[secret_1, secret_2]):
                            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions") as secret_client_list_versions:
                                with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                                    with patch("azure.keyvault.secrets.SecretClient.set_secret"):

                                        secret_client_list_versions.side_effect = yield_version
                                        
                                        export_importer.run()

                                        assert run_context.total_secrets == run_context.total_exported_secrets

                                        assert len([x for x in run_context.src_vault.secrets if x.is_exported]) == 2

                                        for x in run_context.src_vault.secrets:
                                            assert len([x for x in x.versions if x.is_exported]) == 2

                                            for v in x.versions:
                                                assert not v.is_expired
                                                assert v.is_exported
                                                assert v.is_imported




    def test_9_ignore_secrets_created_by_cert_to_store_private_keys(self):
            """
            9. ignore secrets created by cert to store private key
            """

            export_importer = ExportImporter(config)
            run_context = export_importer.run_context
            config.export_only = False

            cert_policy = Mock()
            cert_policy.exportable = True
            cert_policy._content_type = CertificateContentType.pkcs12
            cert_policy.content_type = CertificateContentType.pkcs12

            # secret

            secret_1 = Mock()
            secret_1.name = 'secret_1'
            secret_1.enabled = True
            secret_1.tags = {}
            secret_1.content_type = 'application/x-pem-file'
            secret_1.is_exported = False
            secret_1.is_imported = False

            secret_2 = Mock()
            secret_2.name = 'secret_2'
            secret_2.enabled = True
            secret_2.tags = {}
            secret_2.is_exported = False
            secret_2.is_imported = False
            secret_2.content_type = 'application/x-pkcs12'

            secret_3 = Mock()
            secret_3.name = 'secret_3'
            secret_3.enabled = True
            secret_3.tags = {}
            secret_3.is_exported = False
            secret_3.is_imported = False
            secret_3.content_type = None

            version_1_1 = Mock()
            version_1_1.name = 'version_1_1'
            version_1_1.enabled = True
            version_1_1.version = 'version_1_1'
            version_1_1.expires_on = datetime(2026,10,1)
            version_1_1.created_on = datetime(2024,1,1, 1, 0, 0)
            version_1_1.content_type = None
            version_1_1.is_exported = False
            version_1_1.is_imported = False

            version_1_2 = Mock()
            version_1_2.name = 'version_1_2'
            version_1_2.enabled = True
            version_1_2.version = 'version_1_2'
            version_1_2.expires_on = datetime(2026,10,1)
            version_1_2.created_on = datetime(2024,1,1, 1, 0, 0)
            version_1_2.content_type = None
            version_1_2.is_exported = False
            version_1_2.is_imported = False

            version_2_1 = Mock()
            version_2_1.name = 'version_2_1'
            version_2_1.enabled = True
            version_2_1.version = 'version_2_1'
            version_2_1.expires_on = datetime(2026,10,1)
            version_2_1.created_on = datetime(2024,1,1, 2, 0, 0)
            version_2_1.content_type = ''
            version_2_1.is_exported = False
            version_2_1.is_imported = False

            version_2_2 = Mock()
            version_2_2.name = 'version_2_2'
            version_2_2.enabled = True
            version_2_2.version = 'version_2_2'
            version_2_2.expires_on = datetime(2026,10,1)
            version_2_2.created_on = datetime(2024,1,1, 2, 0, 0)
            version_2_2.content_type = ''
            version_2_2.is_exported = False
            version_2_2.is_imported = False
            
            key_vault_secret = Mock()
            key_vault_secret.value = 'I am a secret'

            run_context.dest_vault = DestinationVault('')
            run_context.dest_vault.cert_names = []
            run_context.dest_vault.deleted_cert_names = []
            run_context.dest_vault.secret_names = []
            run_context.dest_vault.deleted_secret_names = []


            def yield_version(cert_name):
                if cert_name == 'secret_1':
                    yield version_1_1
                    yield version_1_2
                else:
                    yield version_2_1
                    yield version_2_2

            
            # patch akv cert api
            with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificates", return_value=[]):
                with patch("azure.keyvault.certificates.CertificateClient.get_certificate_policy", return_value = cert_policy):
                    with patch("azure.keyvault.certificates.CertificateClient.list_properties_of_certificate_versions") as cert_client_list_versions:
                        # ignore dest vault list cert names
                        with patch('src.export_import.ExportImporter.export_from_dest_vault'):
                        # patch akv secret api
                            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[secret_1, secret_2, secret_3]):
                                with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions") as secret_client_list_versions:
                                    with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                                        with patch("azure.keyvault.secrets.SecretClient.set_secret"):

                                            secret_client_list_versions.side_effect = yield_version
                                            
                                            export_importer.run()

                                            assert run_context.total_exported_secrets == 1
                                            assert run_context.total_secrets == 1
                                            assert run_context.total_secrets == run_context.total_exported_secrets
                                            
                                


                                 

    