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
        
        # log custom attribute
        # https://stackoverflow.com/questions/17558552/how-do-i-add-custom-field-to-python-log-format-string
        
        logging.basicConfig(level = logging.INFO)

        self.az_http_logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
        self.az_http_logger.setLevel(level=logging.ERROR)
        self.akv_logger = logging.getLogger('azure.keyvault.certificates')
        self.akv_logger.setLevel(level=logging.ERROR)

        self.logger = logging.getLogger(__name__)
        self.logger.propagate = False

        handler = colorlog.StreamHandler()
        handler.setFormatter(colorlog.ColoredFormatter(fmt= '%(asctime)s%(log_color)s | %(levelname)s | %(m)s | %(message)s', datefmt='%b %d %Y %H:%M:%S'))

        self.logger.addHandler(handler)   


    def info(self, msg: str, module=''):
        extra = self._empty_module()
        if module:
            extra = self._set_module(module)
        self.logger.info(msg, extra=extra)

    def warn(self, msg: str, module=''):
        extra = self._empty_module()
        if module:
            extra = self._set_module(module)
        self.logger.warning(msg, extra=extra)

    def err(self, error: Exception, module=''):
        extra = self._empty_module()
        if module:
            extra = self._set_module(module)
        self.logger.error(error, extra=extra)

    def _empty_module(self):
        return {'m': ''}
    
    def _set_module(self, module):
        return {'m': module}


log = _Log()
