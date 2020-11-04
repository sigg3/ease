from pathlib import Path

class Settings():
    # Name/Logo and Window Title
    # leave as-is, do not translate
    name = "EASE"
    title = "EASE: Encrypt And Send with EASE"

    # Some defaults
    git = "https://github.com/sigg3/ease"
    # homepage = "https://ease.sigg3.net"
    crypt_buffer = 64 * 1024
    language = "English"
    archive = False
    use_tar = True
    compression = False # default: use store (no compression)
    
    def __init__(self, **kwargs):
        # set key-value entries
        self.__dict__.update(kwargs)
        
         # Set "home" dir (our zdefault)
        if Path.home().is_dir():
            self.home_dir = Path.home()
        else:
            self.home_dir = Path.cwd()
        
        # Set current output dir to default
        self.output_dir = self.home_dir

    
    
