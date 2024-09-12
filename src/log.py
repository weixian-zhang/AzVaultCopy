from loguru import logger
import logging
import sys

class _Log:

    _instance = None

    def __new__(cls, *args, **kwargs):
        # If no instance of class already exits
        if cls._instance is None:
            cls._instance = object.__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        
        logger.add(sys.stderr, format="{time:MMMM D, YYYY HH:mm:ss!UTC} | {message}")

    def info(self, msg: str):
        logger.info(msg)

    def warn(self, msg: str):
        logger.warning(msg)

    def err(self, error: Exception):
        logger.error(error)


log = _Log()
