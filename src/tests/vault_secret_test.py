from unittest.mock import patch, Mock
from config import Config
from vault import VaultManager
from model import SourceKeyVault, DestinationVault, Secret, SecretVersion, RunContext
from datetime import datetime

config = Config(src_vault_name='akv-export', dest_vault_name='akv-temp-3')
run_context = RunContext(config)
vm = VaultManager(config, run_context)


class TestVaultSecret:
    """
    unit test cases

    export

        1. exports all secrets that are:
        - enabled
        - not expired
        - not a private key created by cert

        2. export secret versions that are Enabled and ignore Disabled

        3. export secret versions that are Not Expired, ignore versions that are Expired

        4. export secret versions that are Not cert's private key
        * cert stores public key + private key as secret and cert itself stores the certificate properties
            while exporting secrets need to filter away private key secrets

    import

        5. ignore import if --no_import_if_dest_exist flag is True

        6. ignore import if secret is deleted in destination vault

    """



    def test_1_export_all_secrets(self):
        """
        1. exports all secrets that are:
            - enabled
            - not expired
            - not a private key created by cert
        """
        
        # mock.method.return_value = True
        secret_1 = Mock()
        secret_1.name = 'secret_1'
        secret_1.enabled = True
        secret_1.tags = {}

        secret_2 = Mock()
        secret_2.name = 'secret_2'
        secret_2.enabled = True
        secret_2.tags = {}

        version_1 = Mock()
        version_1.name = 'version_1'
        version_1.enabled = True
        version_1.version = 'v1'
        version_1.expires_on = datetime(2026,10,1)
        version_1.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1.content_type = None

        version_2 = Mock()
        version_2.name = 'version_2'
        version_2.enabled = True
        version_2.version = 'v2'
        version_2.expires_on = datetime(2025,10,1)
        version_2.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2.content_type = ''
        
        key_vault_secret = Mock()
        key_vault_secret.value = 'I am a secret'
        
        with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[secret_1, secret_2]):
            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions", return_value=[version_1, version_2]):
                 with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                 
                    result = vm.list_secrets_from_src_vault()

                    assert len(result) == 2

                    for c in result:
                        assert len(c.versions) == 2


    def test_2_export_secrets_that_are_enabled_ignored_disabled(self):
        """
        2. export secret versions that are Enabled and ignore Disabled
        """
        
        # mock.method.return_value = True
        secret_1 = Mock()
        secret_1.name = 'secret_1'
        secret_1.enabled = True
        secret_1.tags = {}

        secret_2 = Mock()
        secret_2.name = 'secret_2'
        secret_2.enabled = True
        secret_2.tags = {}

        version_1 = Mock()
        version_1.name = 'version_1'
        version_1.enabled = True
        version_1.version = 'v1'
        version_1.expires_on = datetime(2026,10,1)
        version_1.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1.content_type = None

        version_2 = Mock()
        version_2.name = 'version_2'
        version_2.enabled = False
        version_2.version = 'v2'
        version_2.expires_on = datetime(2025,10,1)
        version_2.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2.content_type = ''
        
        key_vault_secret = Mock()
        key_vault_secret.value = 'I am a secret'
        
        with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[secret_1, secret_2]):
            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions", return_value=[version_1, version_2]):
                 with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                 
                    result = vm.list_secrets_from_src_vault()

                    assert len(result) == 2

                    for c in result:
                        assert len(c.versions) == 1


    def test_3_export_secret_versions_that_are_Not_Expired_ignore_Expired(self):
        """
        3. export secret versions that are Not Expired, ignore versions that are Expired
        """
        
        # mock.method.return_value = True
        secret_1 = Mock()
        secret_1.name = 'secret_1'
        secret_1.enabled = True
        secret_1.tags = {}

        secret_2 = Mock()
        secret_2.name = 'secret_2'
        secret_2.enabled = True
        secret_2.tags = {}

        version_1 = Mock()
        version_1.name = 'version_1'
        version_1.enabled = True
        version_1.version = 'v1'
        version_1.expires_on = datetime(2026,10,1) # not expired
        version_1.created_on = datetime(2024,1,1, 1, 0, 0)
        version_1.content_type = None

        version_2 = Mock()
        version_2.name = 'version_2'
        version_2.enabled = True
        version_2.version = 'v2'
        version_2.expires_on = datetime(2024,1,1)  # expired
        version_2.created_on = datetime(2024,1,1, 2, 0, 0)
        version_2.content_type = ''
        
        key_vault_secret = Mock()
        key_vault_secret.value = 'I am a secret'
        
        with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[secret_1]):
            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions", return_value=[version_1, version_2]):
                 with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                 
                    result = vm.list_secrets_from_src_vault()

                    assert len(result) == 1

                    assert len(result[0].versions) == 1


    def test_4_export_secret_versions_that_are_not_cert_private_key(self):
        """
        4. export secret versions that are Not cert's private key
        * cert stores public key + private key as secret and cert itself stores the certificate properties
            while exporting secrets need to filter away private key secrets
        """
        
        # mock.method.return_value = True
        secret_1 = Mock()
        secret_1.name = 'secret_1'
        secret_1.enabled = True
        secret_1.tags = {}
        secret_1.content_type = 'application/x-pem-file'

        secret_2 = Mock()
        secret_2.name = 'secret_2'
        secret_2.enabled = True
        secret_2.tags = {}
        secret_2.content_type = 'application/x-pkcs12'

        secret_3 = Mock()
        secret_3.name = 'secret_3'
        secret_3.enabled = True
        secret_3.tags = {}
        secret_3.content_type = None
        
        version_1 = Mock()
        version_1.name = 'version_1'
        version_1.enabled = True
        version_1.version = 'v1'
        version_1.expires_on = datetime(2026,10,1) # not expired
        version_1.created_on = datetime(2024,1,1, 1, 0, 0)
        

        version_2 = Mock()
        version_2.name = 'version_2'
        version_2.enabled = True
        version_2.version = 'v2'
        version_2.expires_on = datetime(2026,1,1)  # expired
        version_2.created_on = datetime(2024,1,1, 2, 0, 0)
       

        version_3 = Mock()
        version_3.name = 'version_3'
        version_3.enabled = True
        version_3.version = 'v3'
        version_3.expires_on = datetime(2026,10,1) # not expired
        version_3.created_on = datetime(2024,1,1, 1, 0, 0)
        version_3.content_type = None
        
        key_vault_secret = Mock()
        key_vault_secret.value = 'I am a secret'
        
        with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secrets", return_value=[secret_1, secret_2, secret_3]):
            with patch("azure.keyvault.secrets.SecretClient.list_properties_of_secret_versions", return_value=[version_1, version_2, version_3]):
                 with patch("azure.keyvault.secrets.SecretClient.get_secret", return_value=key_vault_secret):
                 
                    result = vm.list_secrets_from_src_vault()

                    assert len(result) == 1

                    assert len(result[0].versions) == 3



    def test_5_ignore_import_if_No_Import_If_Dest_Exist_Flag_is_True(self):
        """
        5. ignore import if --no_import_if_dest_exist flag is True
        """

        config.no_import_if_dest_exist = True
        
        src_vault = SourceKeyVault('src_vault')
        
        # secret 1
        version_1 = SecretVersion(secret_name='secret_1', version='v1', value='am a secret',
                                  content_type='', expires_on=datetime(2026,1,1), 
                                  activates_on=None, created_on=datetime(2024,9,1),enabled=True)
        secret_1 = Secret('secret_1')
        secret_1.versions.append(version_1)
        
        
        # secret 2, exists in dest vault and should be ignored
        version_2 = SecretVersion(secret_name='secret_2', version='v2', value='am a secret',
                                  content_type='', expires_on=datetime(2026,1,1), 
                                  activates_on=None, created_on=datetime(2024,9,1),enabled=True)
        secret_2 = Secret('secret_2')
        secret_2.versions.append(version_2)
        

        src_vault.secrets.append(secret_1)
        src_vault.secrets.append(secret_2)


        dest_vault = DestinationVault('dest_vault')
        dest_vault.secret_names = ['secret_2']


        run_context.src_vault = src_vault
        run_context.dest_vault = dest_vault


        with patch("azure.keyvault.secrets.SecretClient.set_secret"):
        
            result = vm.import_secrets()

            assert len(result) == 1

    
    def test_6_ignore_import_if_secret_is_deleted_indest_vault(self):
        """
         6. ignore import if secret is deleted in destination vault
        """

        config.no_import_if_dest_exist = True
        
        src_vault = SourceKeyVault('src_vault')
        
        # secret 1
        version_1 = SecretVersion(secret_name='secret_1', version='v1', value='am a secret',
                                  content_type='', expires_on=datetime(2026,1,1), 
                                  activates_on=None, created_on=datetime(2024,9,1),enabled=True)
        secret_1 = Secret('secret_1')
        secret_1.versions.append(version_1)
        
        
        # secret 2, deleted in dest vault and should be ignored
        version_2 = SecretVersion(secret_name='secret_2', version='v2', value='am a secret',
                                  content_type='', expires_on=datetime(2026,1,1), 
                                  activates_on=None, created_on=datetime(2024,9,1),enabled=True)
        secret_2 = Secret('secret_2')
        secret_2.versions.append(version_2)
        

        src_vault.secrets.append(secret_1)
        src_vault.secrets.append(secret_2)


        dest_vault = DestinationVault('dest_vault')
        dest_vault.deleted_secret_names = ['secret_2']

        run_context.src_vault = src_vault
        run_context.dest_vault = dest_vault


        with patch("azure.keyvault.secrets.SecretClient.set_secret"):
        
            result = vm.import_secrets()

            assert len(result) == 1
        

                    