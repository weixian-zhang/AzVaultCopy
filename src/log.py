import logging
import colorlog



class _Log:
    """
    Class is Singleton, only one instance will ever be created
    """

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
        
        logging.basicConfig(level = logging.INFO)

        self.az_http_logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
        self.az_http_logger.setLevel(level=logging.ERROR)

        self.logger = logging.getLogger(__name__)
        self.logger.propagate = False

        handler = colorlog.StreamHandler()
        handler.setFormatter(colorlog.ColoredFormatter(
            '%(asctime)s%(log_color)s | %(levelname)s | %(message)s', datefmt='%b %d %Y %H:%M:%S'))

        self.logger.addHandler(handler)   


    def info(self, msg: str):
        self.logger.info(msg)

    def warn(self, msg: str):
        self.logger.warning(msg)

    def err(self, error: Exception):
        self.logger.error(error)


log = _Log()
