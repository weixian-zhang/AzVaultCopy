from model import SourceKeyVault
from vault import VaultManager
from config import Config
from log import log

class ExportImporter:
    
    def __init__(self, config: Config) -> None:
        self.config = config
        self.vm = VaultManager(config)
        self.svc = SourceKeyVault()

    def run(self):
        
        self.export_from_source_vault()

        self.import_to_dest_vault()


    def export_from_source_vault(self):

        log.info('begin export certs')

        self.svc.certs = self.vm.list_certs()

        log.info('export certs completed')
        log.info('begin export secrets')

        self.svc.secrets = self.vm.list_secrets()

        log.info('export secrets completed')


    def import_to_dest_vault(self):
          
        log.info('begin import certs')

        self.vm.import_certs(self.svc.certs)

        log.info('import certs completed')
        log.info('begin import secrets')

        self.vm.import_secrets(self.svc.secrets)

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
