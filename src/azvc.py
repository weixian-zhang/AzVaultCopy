
import click
from config import Config
from vault_manager import VaultManager
from azcred import ExistingTokenCredential 
# click tutorial
# https://www.youtube.com/watch?v=riQd3HNbaDk&list=PLJ39kWiJXSizF1shhf2rHi-aA1yjt7rtX

config = Config()
config.init_azure_cred()


if __name__ == '__main__':
    pass