from pathlib import Path
import zipfile
import tarfile
import re
import datetime


class UserFile(EaseIO):
    """
    This is where we put logic connected to
    file-handling (what are inputs, outputs and temps
    """
    
    # class attributes
    self.compressed = None
    self.extracted = None
    self.encrypted = None
    self.decrypted = None
    self.zip = None
    self.tar = None
    
    def __init__(self, path_as_string):
        """ Set instance attrs """
        
        # Run super init
        # path_as_string is file path str from GUI
        EaseIO.__init__(self, path_as_string)
        
        if self.is_encrypted:
            self.encrypted = self.path
            if self.aes_ext:
                self.decrypted = self.path.parent / self.path.stem
                #if self.decrypted.suffix in ('.zip' or '.tar'):
                #   self.decrypted = None
        else:
            self.decrypted = self.path
            self.encrypted = set_suffix(self, '.aes')
            #self.encrypted = Path(str(self.path+".aes"))
        
        
        if self.is_archive:
            self.compressed = self.path
            if self.is_zip:
                self.zip = self.path
                # self.tar = set_suffix(self, '.tar') # superfluous
            elif self.is_tar:
                # self.zip = set_suffix(self, '.zip')
                self.tar = self.path
            else:
                raise TypeError "Unknown compression."
            
            if not has_legacy_name(self):
                # We can infer that input is a single_file
                # and that the output name is in the input file name
                pass
            
        else:
            self.extracted = self.path
            self.legacy = get_legacy_name(self)
            self.zip = set_suffix(self, '.zip')
            self.tar = set_suffix(self, '.tar')
    
    
    def has_legacy_name(self):
        legacy = re.compile(r'ease_\d{4}-\d{2}-\d{2}')
        if legacy.search(self.path.name) is None:
            return False
        return True
    
    def get_legacy_name(self):
        tstamp = datetime.datetime.now().isoformat()
        tstamp, _ = tstamp.split(sep="T")
        return self.parent / f"ease_{tstamp}"
        
    
    def set_suffix(self, suffix):
        return Path(str(self.path.parent / self.path.stem) + suffix)
        
        self.output
        self.output_encrypted = 
        self.output_compressed = 
        self.input_encrypted = 
        self.input_compressed = 
        self.input_uncompressed = 
        self.input_decrypted = 


class EaseIO():
    """
    In EASE, all input and output designators are
    attributes of an EaseFile object.
    """
    
    # Class attributes
    is_zip = False
    is_tar = False
    is_archive = False
    is_encrypted = False
    
    
    def __init__(self, path_as_string):
        self.as_string = path_as_string
        self.path = Path(self.as_string)
        
        self.is_archive = check_is_archive()
        self.is_encrypted = check_is_aes()
        
        
        # Determine inputs and outputs
        if ...
        self.input = 
        self.temp = 
        self.output = 
    
    
    def unarchive(self):
        pass
    
    def archive(self):
        """ lol """
        
            
    
    def is_file(self):
        """ Runs Path's is_file """
        return self.path.is_file()
    
    
    def check_is_aes(self):
        """ Check AES header in first bytes """
        with open(self.as_string, "rb") as raw:
            b = str(raw.read(32))
        raw.close()
        
        # Major: actual file type
        if "AES" in b or "aescrypt" in b.lower():
            self.is_aes = True
        else:
            self.is_aes = False
        
        # Minor: filename extension
        self.aes_ext = self.as_string.endswith('.aes')
        
        return self.is_aes
    
    def check_is_archive(self):
        """ Determine if file is archive """
        if zipfile.is_zipfile(self.as_string):
            self.is_archive, self.is_zip = True, True
        elif tarfile.is_tarfile(self.as_string):
            self.is_archive, self.is_tar = True, True
        return self.is_archive
    
    
    def __str__(self, attr):
        """ Returns path as string """
        return str(self.attr)

class UserInput(EaseFile):
    pass


class UserOutput(EaseFile):
    pass

