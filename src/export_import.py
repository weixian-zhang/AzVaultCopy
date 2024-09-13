from model import SourceKeyVault, DestinationVault
from vault import VaultManager
from config import Config
from log import log

class ExportImporter:
    
    def __init__(self, config: Config) -> None:
        self.config = config
        self.vm = VaultManager(config)
        self.sv = SourceKeyVault(config.src_vault_name)
        self.dv = DestinationVault(config.dest_vault_name)

    def run(self):
        
        self.export_from_source_vault()

        self.import_to_dest_vault()


    def export_from_source_vault(self):

        self.sv.certs = self.vm.list_certs_from_src_vault()
        
        self.sv.secrets = self.vm.list_secrets_from_src_vault()
        
        dest_certs, dest_deleted_certs = self.vm.list_certs_from_dest_vault()
        self.dv.cert_names = dest_certs
        self.dv.deleted_cert_names = dest_deleted_certs
        
        dest_secrets, dest_deleted_secrets = self.vm.list_secrets_from_dest_vault()
        self.dv.secret_names = dest_secrets
        self.dv.deleted_secret_names = dest_deleted_secrets
        


    def import_to_dest_vault(self):
          
        self.vm.import_certs(self.sv, self.dv)

        log.info('import certs completed')
        log.info('begin import secrets')

        self.vm.import_secrets(self.sv, self.dv)

        log.info('import secrets completed')

        
    

        # file_name = f'C:\\Users\\weixzha\\Desktop\\{version.name}_{version.version}.pem'
    # with open(file_name, 'wb') as pem_file:
    #     pem_file.write(cert_bytes)

    # with open(file_name, "rb") as f:
    #     pfx_cert_bytes = f.read()

    # try:
    #     self.dest_cert_client.import_certificate(version.name, cert_bytes) #pfx_cert_bytes)
    # except Exception as e:
    #     pass
