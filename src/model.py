from datetime import datetime



class CertVersion:
    def __init__(self, version, expires_on, created_on, enable, tags) -> None:
        self.version = version
        self.public_key: bytes = b''
        self.private_key: bytes = b''
        self.cert: bytes = b'' # public + private + additional keys 
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
    def __init__(self, version, value, expires_on, created_on, tags) -> None:
        self.version = version
        self.value = value
        self.expires_on = expires_on
        self.created_on = created_on
        self.tags = tags if tags else {}

class Secret:
    def __init__(self, name, tags) -> None:
        self.name = name
        self.versions : list[SecretVersion] = []
        self.tags = tags if tags else {}

class SourceKeyVault:

    def __init__(self) -> None:
        self.name = ''
        self.url = ''
        self.subscription_id = ''
        self.resource_group = ''
        self.secrets : list[Secret] = []
        self.certs : list[Cert] = []

class RunContext:
    def __init__(self) -> None:
        self.started_on: datetime = None
        self.source_vault = None