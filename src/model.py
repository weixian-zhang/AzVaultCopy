from datetime import datetime

class CertVersion:
    def __init__(self, cert_name, version, cert, type, cert_policy, expires_on, created_on, enable, tags={}) -> None:
        self.cert_name = cert_name
        self.version = version
        self.cert: bytes = cert # public + private + additional keys
        self.type = type
        self.cert_policy = cert_policy
        self.expires_on : datetime = expires_on
        self.created_on = created_on
        self.enable = enable
        self.tags: dict = tags

class Cert:
    def __init__(self, name, tags = {}) -> None:
        self.name = name
        self.versions : list[CertVersion] = []
        self.tags = tags

class SecretVersion:
    def __init__(self, secret_name, version, value, content_type, expires_on, activates_on, created_on, enabled, tags={}) -> None:
        self.secret_name = secret_name
        self.version = version
        self.value = value
        self.content_type = content_type
        self.expires_on = expires_on
        self.activates_on = activates_on
        self.created_on = created_on
        self.enabled= enabled
        self.tags = tags

class Secret:
    def __init__(self, name, tags = {}) -> None:
        self.name = name
        self.versions : list[SecretVersion] = []
        self.tags = tags

class SourceKeyVault:

    def __init__(self, name) -> None:
        self.name = name
        self.secrets : list[Secret] = []
        self.certs : list[Cert] = []

class DestinationVault:
    """
    consist of secrets and certs that are either Enabled, Disabled, Expired or Deleted
    """
    def __init__(self, name) -> None:
        self.name = name
        self.cert_names = set()
        self.deleted_cert_names = set()
        self.secret_names = set()
        self.deleted_secret_names = set([])

class RunContext:
    def __init__(self,config) -> None:
        self.started_on = None
        self.ended_on = None
        self.config = config

        self.total_certs = 0
        self.exported_certs = 0
        self.not_exported_certs = 0
        self.cert_export_import_stats = {}   # cert name is key and value is tuple(total versions, total exported, total imported)
        self.total_certs = 0

        self.total_secrets = 0
        self.exported_secrets = 0
        self.not_exported_secrets = 0
        self.secret_export_import_stats = {} # cert name is key and value is tuple(total versions, total exported, total imported)
        self.imported_secrets = 0

    def track_started_on(self):
        self.started_on = datetime.now()

    def track_ended_on(self):
        self.ended_on = datetime.now()

    # track Certs stats for reporting
     
    def track_total_cert_version_to_be_exported(self, cert_name):
        if cert_name not in self.cert_export_import_stats:
            self.cert_export_import_stats[cert_name] = [1,0,0]  
            return
        
        total, exp, imp = self.cert_export_import_stats[cert_name]
        total += 1

        self.cert_export_import_stats[cert_name] = [total, exp, imp]

    
    def track_exported_cert_version(self, cert_name, count):
        """
        Safely assume cert_export_import_stats will contain cert name already due to order of execution
        """
        if cert_name not in self.cert_export_import_stats:
            raise Exception('cert name not exist in cert_export_import_stats when setting exported version count')
        
        total, exp, imp = self.cert_export_import_stats[cert_name]
        exp = count

        self.cert_export_import_stats[cert_name] = [total, exp, imp]


    def track_imported_cert_version(self, cert_name, count):
        """
        Safely assume cert_export_import_stats will contain cert name already due to order of execution
        """
        if cert_name not in self.cert_export_import_stats:
            raise Exception('cert name not exist in cert_export_import_stats when setting exported version count')
        
        total, exp, imp = self.cert_import_map[cert_name]
        imp += count

        self.cert_import_map[cert_name] = (total, exp, imp)



    def is_cert_having_version_imported(self, cert_name):
        if cert_name not in self.secret_export_import_stats:
            return False
        
        _, exported, _ = self.secret_export_import_stats[cert_name]

        if exported > 0:
            return True
        
        return False


    # track Secrets stats for reporting

    def track_total_secret_version_to_be_exported(self, secret_name):
        if secret_name not in self.secret_export_import_stats:
            self.secret_export_import_stats[secret_name] = [1,0,0]   
            return
        
        total, exp, imp = self.secret_export_import_stats[secret_name]
        total += 1

        self.secret_export_import_stats[secret_name] = [total, exp, imp]

    
    def track_exported_secret_version(self, secret_name, count):
        """
        Safely assume secret_export_import_stats will contain cert name already due to order of execution
        """
        if secret_name not in self.secret_export_import_stats:
            raise Exception('secret name not exist in secret_export_import_stats when tracking exported version count')
        
        total, exp, imp = self.secret_export_import_stats[secret_name]
        exp = count

        self.secret_export_import_stats[secret_name] = (total, exp, imp)



    def track_imported_secret_version(self, secret_name, count):
        """
        exported_certs will be the total number of certs to be imported
        """
        if secret_name not in self.secret_export_import_stats:
            self.secret_export_import_stats[secret_name] = (self.exported_secrets, 0)
        
        total, exp, imp = self.secret_export_import_stats[secret_name]
        imp += count

        self.secret_export_import_stats[secret_name] = [total, exp, imp]
    
    

    def is_secret_having_version_imported(self, secret_name):
        if secret_name not in self.secret_import_map:
            return False
        
        _, _, imported = self.secret_export_import_stats[secret_name]

        if imported > 0:
            return True
        
        return False
    

        