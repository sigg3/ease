from pathlib import Path
import zipfile
import tarfile
import re
import datetime


class UserFile():
    def __init__(self, input: str):
        self.input = input
        self.as_string = input
        self.is_file = False
        self.output = []
        self.temporary = []
        self.path = None
        self.source_dir = None
        self.basename = None
        if ";" in self.input:
            self.list = self.input.split(sep=";")
            _count = [ x for x in self.list if Path(x).is_file() ]
            if len(_count) == len(self.list):
                self.is_file = True
                self.source_dir = Path(self.list[0]).parent
        else:
            self.list = [ input ]
            self.is_file = self.path.is_file()
            if self.is_file:
                self.path = Path(self.as_string)
                self.source_dir = self.path.parent

        self.target_dir = self.source_dir


class EaseFile(UserFile, ArchiveFile, CryptFile):
    """
    In EASE, all input and output designators are
    attributes of an EaseFile object.
    """

    use_tar = ease.use_tar
    use_zip = False if ease.use_tar else True
    compression = ease.use_compression


    def __init__(
                 self,
                 input: str,
                 compression: bool,
                 use_tar: bool,
                 use_zip: bool
                 ):

        # List of file names
        # self.archived = None
        # self.extracted = None
        # self.encrypted = None
        # self.decrypted = None
        # self.zip = None
        # self.tar = None

        if self.use_tar:
            self.use_archiving = True
        elif self.use_zip:
            self.use_archiving = True
        else:
            self.use_tar = ease.use_tar
            self.use_archiving = ease.archive

        # Basics
        UserFile.__init__(self, input)

        # EASE generic file names
        self.legacy = False
        self.generic = None
        if self.path is not None:
            self.legacy = has_generic_name(self)
            if self.legacy:
                self.generic = self.path
            else:
                self.generic = get_generic_name(self)


        # Archiving
        self.use_archiving = archiving
        if self.list:
            if len(self.list) != 1:
                # Override if >1 file
                self.use_archiving = True
        else:
            raise Exception(f"No input files in: {self.input}")
        ArchiveFile.__init__(self, use_zip, compression)

        # Encryption
        CryptFile.__init__(self)

        # TBD: self.output must be not None

        # TBD: TransmitFile

    def waste_file(self, item):
        ease.temporary.append(item) # ?

    def update(self):
        # update file names
        pass

    def has_generic_name(self):
        """ checks whether file has generic ease name """
        legacy = re.compile(r'ease_\d{4}-\d{2}-\d{2}')
        if legacy.search(self.path.name) is None:
            return False
        return True

    def get_generic_name(self):
        """ generates generic ease name string """
        tstamp = datetime.datetime.now().isoformat()
        tstamp, _ = tstamp.split(sep="T")
        return self.path.parent / f"ease_{tstamp}"

    def set_suffix(self, suffix):
        return Path(str(self.path.parent / self.path.stem) + suffix)

    def __str__(self, attr):
        """ Returns path as string """
        return str(self.attr)


class ArchiveFile():
    def __init__(
                 self,
                 use_zip: bool,
                 compression: bool
                 ):
        self.is_archive = False
        self.use_tar = True
        self.use_compression = False
        self.is_archive = check_is_archive(self)
        if self.is_archive:
            self.compressed = self.path
            if self.use_tar:
                self.tar = self.path
            else:
                self.zip = self.path
        else:
            self.extracted = self.path
            #self.legacy = get_legacy_name(self)
            self.zip = set_suffix(self, '.zip')
            self.tar = set_suffix(self, '.tar')
            self.use_tar = True # default


    def check_is_archive(self):
        """ Determine if file is archive """
        if zipfile.is_zipfile(self.as_string):
            self.is_archive, self.use_zip = True, True
        elif tarfile.is_tarfile(self.as_string):
            self.is_archive, self.use_tar = True, True
        return self.is_archive

    def archive(self, input_files: list):
        """packs input files in tar or zip"""
        if self.is_archive:
            raise Exception("Input already archived ..")
        else:
            _wrk = [ self.path.stem,
                     self.use_tar,
                     self.use_compression,
                     input_files ]

            try:
                run_in_the_background('archive', _wrk)
                # TBD update files now here?
            except Exception as e:
                print(e)

    def extract(self, input_file: str):
        """unpacks input file"""
        if self.is_archive:
            _wrk = [ input_file, self.target_dir ]
            run_in_the_background('unarchive', _wrk)
        else:
            raise Exception("File is not an archive")


class CryptFile():
    """ Depends on run_in_the_background() """
    def __init__(self):
        self.passphrase = None
        self.buffer_size = 64 * 1024
        self.is_encrypted = is_encrypted(self)
        if self.is_encrypted:
            self.encrypted = self.path
            self.aes_ext = is_easefile(self)
            if self.aes_ext:
                self.decrypted = self.path.parent / self.path.stem
                if str(self.decrypted ).endswith('.zip'):
                    self.decrypted = None
                elif str(self.decrypted ).endswith('.tar'):
                    self.decrypted = None
        else:
            self.decrypted = self.path
            self.encrypted = set_suffix(self, '.aes')
            self.aes_ext = False

    def is_encrypted(self):
        """ Check AES file type header """
        with open(self.as_string, "rb") as raw:
            b = str(raw.read(32))
        raw.close()
        if "AES" in b or "aescrypt" in b.lower():
            return True
        return False

    def set_passphrase(self, passphrase: str):
        if len(passphrase) < 6:
            raise Exception("Password too short")
        elif len(passphrase) > 1024:
            raise Exception("Password too long")
        else:
            self.passphrase = passphrase

    def is_easefile(self):
        return self.as_string.endswith('.aes')

    def cryptwork(self, encrypt_file:bool):
        """ run external worker as ordered """
        if self.output is None:
            raise Exception("No output attribute set")
            return False # ??

        # work order
        _wrk = [encrypt_file,
                self.as_string,
                self.output,
                self.passphrase]

        if encrypt_file:
            run_in_the_background('encrypt', _wrk)
        else:
            run_in_the_background('decrypt', _wrk)

    def encrypt(self):
        """ encrypts the file """
        cryptwork(self, True)

    def decrypt(self):
        """ decrypts the file """
        cryptwork(self, False)


class SendFile():
    """ Contains attr and methods for file transmission """
    pass


class LoopControl():
    """
    Used in main() main loop
    Each course of action has a recipe to follow
    """
    def __init__(self, course_of_action: str):
        try:
            LoopControl.course_of_action()
        except:
            if type == 0:
                self.step = self.encrypt()
            elif type == 1:
                self.step = self.decrypt()
            else:
                self.step = self.send()

    def send(self):
        pass

    def decrypt(self):
        pass

    def encrypt(self):
        yield 'identify' # u know, substitute these with functions ...
        yield 'archive'
        yield 'encrypt'


# action = LoopControl(0)
# In [55]: action
# Out[55]: 'identify'
#
# In [56]: action = next(loop.course_of_action)
#
# In [57]: action
# Out[57]: 'archive'
