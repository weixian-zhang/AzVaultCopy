from model import SourceKeyVault, DestinationVault, RunContext
from vault import VaultManager
from config import Config
from log import log
from dir import ExportDirectory
import os
from report import ReportRenderer
class ExportImporter:
    
    def __init__(self, config: Config) -> None:
        self.config = config
        self.run_context = RunContext(config)
        self.vm = VaultManager(config, self.run_context)
        self.sv = SourceKeyVault(config.src_vault_name)
        self.dv = DestinationVault(config.dest_vault_name)

    def run(self):

        self.run_context.started()
        
        self.export_from_source_vault()

        if self.config.export_dir:
            self.save_export_objects_to_local()

        if not self.config.export_only:
            self.export_from_dest_vault()
            self.import_to_dest_vault()

        self.run_context.ended()

        log.info('generating summary', 'Report')
        rr = ReportRenderer(self.run_context)

        rr.print()


    def export_from_source_vault(self):
        """
        if --export-only flag is True,  will skip fetching destination secrets and certs from dest vault
        """

        self.sv.certs = self.vm.list_certs_from_src_vault()
        
        self.sv.secrets = self.vm.list_secrets_from_src_vault()

        self.run_context.src_vault = self.sv
            

    def export_from_dest_vault(self):
        certs, deleted_certs = self.vm.list_certs_from_dest_vault()
        self.dv.cert_names = certs
        self.dv.deleted_cert_names = deleted_certs
        
        secrets, deleted_secrets = self.vm.list_secrets_from_dest_vault()
        self.dv.secret_names = secrets
        self.dv.deleted_secret_names = deleted_secrets

        self.run_context.dest_vault = self.dv

    def import_to_dest_vault(self):
          
        self.vm.import_certs()

        self.vm.import_secrets()

    
    def save_export_objects_to_local(self):
        
        ed = ExportDirectory(self.config)
        
        for cert in self.sv.certs:
            if not cert.versions:
                continue
            cert_dir = ed.get_export_path('cert', cert.name)
            for version in cert.versions:
                file_name = f'{cert.name}_{version.version}.{version.type.lower()}'
                file_path = os.path.join(cert_dir, file_name)
                ed.save_cert(file_path, version.cert)

        for secret in self.sv.secrets:
            if not secret.versions:
                continue
            secret_dir = ed.get_export_path('secret', secret.name)
            for version in secret.versions:
                file_name = f'{secret.name}_{version.version}.txt'
                file_path = os.path.join(secret_dir, file_name)
                ed.save_secret(file_path, version.value)

        

        
    

        # file_name = f'C:\\Users\\weixzha\\Desktop\\{version.name}_{version.version}.pem'
    # with open(file_name, 'wb') as pem_file:
    #     pem_file.write(cert_bytes)

    # with open(file_name, "rb") as f:
    #     pfx_cert_bytes = f.read()

    # try:
    #     self.dest_cert_client.import_certificate(version.name, cert_bytes) #pfx_cert_bytes)
    # except Exception as e:
    #     pass
