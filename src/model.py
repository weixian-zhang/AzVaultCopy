from datetime import datetime
from src.util import Util
from enum import Enum

def _is_expired(expires_on):
        if Util.is_object_expired(expires_on):
            return True
        return False

class VaultObjectType(Enum):
    Cert = 1
    Secret = 2
class TrackType(Enum):
    Total = 1
    Exported = 2
    Imported = 3

class CertVersion:
    def __init__(self, cert_name, version, cert, type, cert_policy, expires_on, created_on, enable, is_exported, tags={}) -> None:
        self.cert_name = cert_name
        self.version = version
        self.cert: bytes = cert # public + private + additional keys
        self.type = type
        self.cert_policy = cert_policy

        # report properties
        self.expires_on : datetime = expires_on
        self.created_on = created_on
        self.is_expired = _is_expired(self.expires_on)
        self.is_cert_marked_as_exportable = False  # for older versions, only know during import when no private key error is thrown
        self.enable = enable
        self.is_latest_version = False
        self.is_imported = False
        self.is_exported = is_exported
        self.tags: dict = tags
        

class Cert:
    def __init__(self, name, tags = {}) -> None:
        self.name = name
        self.is_exists_in_dest_vault = False
        self.is_deleted_in_dest_vault = False
        self.versions : list[CertVersion] = []
        self.is_exported = False
        self.is_imported = False
        self.tags = tags

class SecretVersion:
    def __init__(self, secret_name, version, value, content_type, expires_on, 
                 activates_on, created_on, enabled, is_exported, tags={}) -> None:
        self.secret_name = secret_name
        self.version = version
        self.value = value
        self.content_type = content_type
        self.expires_on = expires_on
        self.activates_on = activates_on
        self.created_on = created_on
        self.is_expired = _is_expired(self.expires_on )
        self.enabled= enabled
        self.is_exported = is_exported
        self.is_imported=False
        self.is_latest_version = False
        self.tags = tags

class Secret:
    def __init__(self, name, tags = {}) -> None:
        self.name = name
        self.versions : list[SecretVersion] = []
        self.is_exported = False
        self.is_imported = False
        self.is_exists_in_dest_vault = False
        self.is_deleted_in_dest_vault = False
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
        self.src_vault: SourceKeyVault = None
        self.dest_vault: DestinationVault = None

        self.total_certs = 0
        self.total_exported_certs = 0
        self.cert_export_import_stats = {}   # cert name is key and value is tuple(total versions, total exported, total imported)
        self.total_imported_certs = 0

        self.total_secrets = 0
        self.total_exported_secrets = 0
        self.secret_export_import_stats = {} # cert name is key and value is tuple(total versions, total exported, total imported)
        self.total_imported_secrets = 0

    def started(self):
        self.started_on = datetime.now()

    def ended(self):
        self.ended_on = datetime.now()


    def track_version_stats(self, name, obj_type: VaultObjectType, track_type: TrackType, count=1):
        """
        track different counts of cert versions: Total, Exported and Imported
        """
        if obj_type == VaultObjectType.Cert and name not in self.cert_export_import_stats:
            self.cert_export_import_stats[name] = [0,0,0] 
        elif obj_type == VaultObjectType.Secret and name not in self.secret_export_import_stats:
            self.secret_export_import_stats[name] = [0,0,0] 

        stats_map = {}

        if obj_type == VaultObjectType.Cert:
            stats_map = self.cert_export_import_stats
        else: 
            stats_map = self.secret_export_import_stats


        total, exp, imp = stats_map[name]
        
        if track_type == TrackType.Total:
            total += count
        elif track_type == TrackType.Exported:
            exp += count
        else:
            imp += count

        stats_map[name] = [total, exp, imp]

        if obj_type == VaultObjectType.Cert:
            self.cert_export_import_stats = stats_map
        else: 
            self.secret_export_import_stats = stats_map


    def track_object_exist_in_dest_vault(self, obj: Cert|Secret, obj_type: VaultObjectType):
        if obj_type == VaultObjectType.Cert and obj.name in self.dest_vault.cert_names:
            obj.is_exists_in_dest_vault = True
        else:
            if obj.name in self.dest_vault.secret_names:
                obj.is_exists_in_dest_vault = True


    def track_object_deleted_in_dest_vault(self, obj: Cert|Secret, obj_type: VaultObjectType):
        if obj_type == VaultObjectType.Cert and obj.name in self.dest_vault.deleted_cert_names:
            obj.is_deleted_in_dest_vault = True
        else:
            if obj.name in self.dest_vault.deleted_secret_names:
                obj.is_deleted_in_dest_vault = True

    # def count_total_objects_by_exported_versions(self, objs: list[CertVersion|SecretVersion]) -> int:
    #      count = 0
    #      for x in objs:
    #           if len([v for v in x.versions if v.is_exported]) > 0:
    #                count += 1
    #      return count
    
    # def count_total_objects_by_imported_versions(self, objs: list[CertVersion|SecretVersion]) -> int:
    #      count = 0
    #      for x in objs:
    #           if len([v for v in x.is_exported if v.is_imported]) > 0:
    #                count += 1
    #      return count

    
    # def start_track_cert(self, cert_name):
    #     if cert_name not in  self.cert_export_import_stats:
    #         self.cert_export_import_stats[cert_name] = [0,0,0]

    # def track_exported_cert_versions(self, cert_name, count=1):
    #     if cert_name not in self.cert_export_import_stats:
    #         self.cert_export_import_stats[cert_name] = [1,0,0]  
    #         return
        
    #     total, exp, imp = self.cert_export_import_stats[cert_name]
    #     exp += count

    #     self.cert_export_import_stats[cert_name] = [total, exp, imp]

    
    # def track_exported_cert_version(self, cert_name, count):
    #     """
    #     Safely assume cert_export_import_stats will contain cert name already due to order of execution
    #     """
    #     if cert_name not in self.cert_export_import_stats:
    #         raise Exception('cert name not exist in cert_export_import_stats when setting exported version count')
        
    #     total, exp, imp = self.cert_export_import_stats[cert_name]
    #     exp = count

    #     self.cert_export_import_stats[cert_name] = [total, exp, imp]


    # def track_imported_cert_version(self, cert_name, count):
    #     """
    #     Safely assume cert_export_import_stats will contain cert name already due to order of execution
    #     """
    #     if cert_name not in self.cert_export_import_stats:
    #         raise Exception('cert name not exist in cert_export_import_stats when setting exported version count')
        
    #     total, exp, imp = self.cert_export_import_stats[cert_name]
    #     imp += count

    #     self.cert_export_import_stats[cert_name] = [total, exp, imp]



    # def is_cert_having_version_imported(self, cert_name):
    #     if cert_name not in self.secret_export_import_stats:
    #         return False
        
    #     _, exported, _ = self.secret_export_import_stats[cert_name]

    #     if exported > 0:
    #         return True
        
    #     return False


    # track Secrets stats for reporting

    # def start_track_secret(self, secret_name):
    #     if secret_name not in  self.cert_export_import_stats:
    #         self.secret_export_import_stats[secret_name] = [0,0,0]  

    # def track_total_secret_version_to_be_exported(self, secret_name):
    #     if secret_name not in self.secret_export_import_stats:
    #         self.secret_export_import_stats[secret_name] = [1,0,0]   
    #         return
        
    #     total, exp, imp = self.secret_export_import_stats[secret_name]
    #     total += 1

    #     self.secret_export_import_stats[secret_name] = [total, exp, imp]

    
    # def track_exported_secret_version(self, secret_name, count):
    #     """
    #     Safely assume secret_export_import_stats will contain cert name already due to order of execution
    #     """
    #     if secret_name not in self.secret_export_import_stats:
    #         raise Exception('secret name not exist in secret_export_import_stats when tracking exported version count')
        
    #     total, exp, imp = self.secret_export_import_stats[secret_name]
    #     exp = count

    #     self.secret_export_import_stats[secret_name] = [total, exp, imp]

    # def track_imported_secret_version(self, secret_name, count):
    #     """
    #     total_exported_certs will be the total number of certs to be imported
    #     """
    #     if secret_name not in self.secret_export_import_stats:
    #         self.secret_export_import_stats[secret_name] = (self.total_exported_secrets, 0)
        
    #     total, exp, imp = self.secret_export_import_stats[secret_name]
    #     imp += count

    #     self.secret_export_import_stats[secret_name] = [total, exp, imp]


    # def is_secret_having_version_imported(self, secret_name):
    #     if secret_name not in self.secret_import_map:
    #         return False
        
    #     _, _, imported = self.secret_export_import_stats[secret_name]

    #     if imported > 0:
    #         return True
        
    #     return False
    

        