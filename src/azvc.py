
import click
from config import Config
from vault import VaultManager
from export_import import ExportImporter
from log import log
# click tutorial
# https://www.youtube.com/watch?v=riQd3HNbaDk&list=PLJ39kWiJXSizF1shhf2rHi-aA1yjt7rtX



def run():
    try:
         config = Config()
         ei = ExportImporter(config)
         ei.run()
    except Exception as e:
            log.err(e)



if __name__ == '__main__':
    run()