from datetime import datetime



class CertVersion:
    def __init__(self, version, cert, type, cert_policy, expires_on, created_on, enable, tags) -> None:
        self.version = version
        self.cert: bytes = cert # public + private + additional keys
        self.type = type
        self.cert_policy = cert_policy
        self.expires_on : datetime = expires_on
        self.created_on = created_on
        self.enable = enable
        self.tags: dict = tags if tags else {}

class Cert:
    def __init__(self, name, tags) -> None:
        self.name = name
        self.versions : list[CertVersion] = []
        self.tags = tags if tags else {}

class SecretVersion:
    def __init__(self, version, value, content_type, expires_on, created_on, enabled, tags) -> None:
        self.version = version
        self.value = value
        self.content_type = content_type
        self.expires_on = expires_on
        self.created_on = created_on
        self.enabled= enabled
        self.tags = tags if tags else {}

class Secret:
    def __init__(self, name, tags) -> None:
        self.name = name
        self.versions : list[SecretVersion] = []
        self.tags = tags if tags else {}

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

# class RunContext:
#     def __init__(self) -> None:
#         self.started_on: datetime = datetime.now()
#         self.source_vault = None