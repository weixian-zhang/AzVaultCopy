import os
from config import Config

class ExportDirectory:

    # _instance = None

    # def __new__(cls, *args, **kwargs):
    #     # If no instance of class already exits
    #     if cls._instance is None:
    #         cls._instance = object.__new__(cls)
    #         cls._instance._initialized = False
    #     return cls._instance
    
    def __init__(self, config: Config) -> None:

        self.root = ''

        if not config.export_dir:
            return

        self.root = config.export_dir

        self._create_if_not_exist(self.root)

    def root(self):
        """
        ExportDirectory will create root folder if not exists
        """
        if not self.root:
            raise Exception('--export_dir is not set')
        return self.root
    
    def get_export_path(self, *dir):
        """
        ExportDirectory will create folder if not exists
        """
            
        new_path = self.root
        for p in list(dir):
            new_path = os.path.join(new_path, p)
            self._create_if_not_exist(new_path)
        return new_path
    
    def save_cert(self, path, data):
        with open(path, 'wb') as f:
            f.write(data)

    def save_secret(self, path, data):
        with open(path, 'w') as f:
            f.write(str(data))
    
    def _create_if_not_exist(self, path):
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)


