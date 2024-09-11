from datetime import datetime
from azure.keyvault.certificates import CertificatePolicy

class CertVersion:
    def __init__(self, version, expires_on, policy, enable, tags) -> None:
        self.version = version
        self.public_key = ''
        self.private_key = ''
        self.expires_on : datetime = expires_on
        self.policy: CertificatePolicy = policy
        self.enable = enable
        self.tags = tags

class Cert:
    def __init__(self, name, tags) -> None:
        self.name = name
        self.versions : list[CertVersion] = []
        self.tags = tags

class SecretVersion:
    def __init__(self) -> None:
        self.version = ''

class Secret:
    def __init__(self) -> None:
        self.name
        self.versions : list[SecretVersion] = []

class KeyVault:

    def __init__(self) -> None:
        self.name = ''
        self.url = ''
        self.subscription_id = ''
        self.resource_group = ''
        self.secrets : list[Secret] = []
        self.certs : list[Cert] = []

class CopyContext:
    def __init__(self) -> None:
        pass