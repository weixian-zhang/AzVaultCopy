
import click
from config import Config
from vault import VaultManager
from export_import import ExportImporter
from log import log

# click tutorial
# https://www.youtube.com/watch?v=riQd3HNbaDk&list=PLJ39kWiJXSizF1shhf2rHi-aA1yjt7rtX

# package cmdline app publish to pypi
# https://blog.thesourcepedia.org/build-cli-app-in-python-with-click-and-publish-to-pypi#heading-prepare-for-package

@click.command()
@click.option('--src_vault', '-sv', default='', help='source vault name')
@click.option('--dest_vault', '-dv', default='', help='destination vault name')
@click.option('--src_token', '-st', default='', help='''access token of source Entra Tenant to access source vault.\n
              az login --tenant {tenant id}\n
              az account get-access-token --scope https://vault.azure.net/.default --query "accessToken" 
              ''')
@click.option('--dest_token', '-dt', default='', help='''access token of destination Entra Tenant to access source vault.\n
              az login --tenant {tenant id}\n
              az account get-access-token --scope https://vault.azure.net/.default --query "accessToken" 
              ''')
@click.option('--export_dir', '-ed', default='', help='certs and secrets are save to this directory while importing to dest vault')
@click.option('--export_only', '-eo', is_flag=True, help='all certs and secrets are save to local drive, WITHOUT importing to dest vault')
@click.option('--no_import_if_dest_exist', '-ii', is_flag=True, help='''any cert or secret with same name at dest vault will not be imported\n
              * When importing an object with the same name, vault will create a new version.
              ''')
@click.option('--timezone', '-tz', default='Asia/Kuala_Lumpur', help='''Python timezone name to localize datetime\n
              https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
              ''')
def run(src_vault, dest_vault, src_token, dest_token, export_dir='',export_only=False, no_import_if_dest_exist=False, timezone='Asia/Kuala_Lumpur'):
    try:
    
         config = Config(src_vault, dest_vault, src_token, dest_token, export_dir, export_only, no_import_if_dest_exist)
         ei = ExportImporter(config)
         ei.run()
    except Exception as e:
            log.err(e)

def main(*args):
    run(*args)


if __name__ == '__main__':
    main()