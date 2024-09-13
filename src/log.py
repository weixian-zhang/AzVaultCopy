import logging
from rich.logging import RichHandler



class _Log:

    _instance = None

    def __new__(cls, *args, **kwargs):
        # If no instance of class already exits
        if cls._instance is None:
            cls._instance = object.__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, ) -> None:
        if self._initialized:
            return
        
        #coloredlogs.install(fmt='%(asctime)s | %(levelname)s | %(message)s', datefmt='%b %d %Y %H:%M:%S')

        
        # %(name)s
        logFormatter = logging.Formatter(fmt='%(asctime)s | %(levelname)s | %(message)s', datefmt='%b %d %Y %H:%M:%S')

        self.logger = logging.getLogger(__name__)

        self.logger.addHandler(RichHandler())    


    def info(self, msg: str):
        self.logger.info(msg)

    def warn(self, msg: str):
        self.logger.warning(msg)

    def err(self, error: Exception):
        self.logger.error(error)


log = _Log()
