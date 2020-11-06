from pathlib import Path
import zipfile
import tarfile
import re
import datetime
import settings

# Translations
import gettext
_ = gettext.gettext


class UserFile():
    def __init__(self, input: str):
        self.input = input
        self.as_string = input
        self.is_file = False
        self.output = []
        self.temporary = [] # not in use
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
                raise Exception("Not all inputs are files")
                # TBD
        elif Path(input).is_file():
                self.is_file = True
                self.list = [ input ]
                self.list = [ input ]
                if self.is_file:
                    self.path = Path(input)
                    self.source_dir = self.path.parent
                self.basename = self.path.name
        else:
            self.is_file = False
            raise exception("Input is not a file")

        self.target_dir = self.source_dir

class ArchiveFile():
    def __init__(
                 self,
                 use_zip: bool,
                 compression: bool
                 ):
        self.is_archive = False
        self.use_tar = True
        self.use_compression = False
        self.is_archive = self.check_is_archive()
        if self.is_archive:
            self.compressed = self.path
            if self.use_tar:
                self.tar = self.path
            else:
                self.zip = self.path
        else:
            self.extracted = self.path
            #self.legacy = get_legacy_name(self)
            self.zip = self.set_suffix('.zip')
            self.tar = self.set_suffix('.tar')
            self.use_tar = ease.use_tar# default


    def check_is_archive(self):
        """ Determine if file is archive """
        if zipfile.is_zipfile(self.as_string):
            self.is_archive, self.use_zip = True, True
        elif tarfile.is_tarfile(self.as_string):
            self.is_archive, self.use_tar = True, True
        return self.is_archive

    def archive(self):
        """packs input files in tar or zip"""
        if self.is_archive:
            raise Exception("file_already_archived")
        else:
            _wrk = [ self.path.stem,
                     self.use_tar,
                     self.use_compression,
                     self.list ]

            try:
                run_in_the_background('archive', _wrk)
                # TBD update files now here?
            except Exception as e:
                raise Exception(e)

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
        self.is_encrypted = self.is_encrypted()
        if self.is_encrypted:
            self.encrypted = self.path
            self.aes_ext = self.is_easefile()
            if self.aes_ext:
                self.decrypted = self.path.parent / self.path.stem
                if str(self.decrypted ).endswith('.zip'):
                    self.decrypted = None
                elif str(self.decrypted ).endswith('.tar'):
                    self.decrypted = None
        else:
            self.decrypted = self.path
            self.encrypted = self.set_suffix('.aes')
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
            raise Exception("pass_too_short")
        elif len(passphrase) > 1024:
            raise Exception("pass_too_long")
        else:
            self.passphrase = passphrase

    def is_easefile(self):
        return self.as_string.endswith('.aes')

    def cryptwork(self, encrypt_file:bool):
        """ run external worker as ordered """
        if self.output is None:
            raise Exception("No output attribute set")
            return False # ??

        if encrypt_file:
            _order = 'encrypt'
            _input = str(self.intermediary)
            _output = str(self.encrypted)
        else:
            _order = 'decrypt'
            print('Unfinished code here yall')
            # inputs/outputs here

        # work order
        _work = [encrypt_file,
                _input,
                _output,
                self.passphrase]

        run_in_the_background(_order, _work)


    def encrypt(self):
        """ encrypts the file """
        cryptwork(self, True)

    def decrypt(self):
        """ decrypts the file """
        cryptwork(self, False)


class SendFile():
    """ Contains attr and methods for file transmission """
    pass


class EaseFile(UserFile, ArchiveFile, CryptFile):
    """
    In EASE, all input and output designators are
    attributes of an EaseFile object.
    """

    # use_tar = ease.use_tar
    # use_zip = False if ease.use_tar else True
    # compression = ease.use_compression


    def __init__(
                 self,
                 input: str,
                 compression: bool,
                 use_tar: bool,
                 use_zip: bool
                 ):

        # List of file names


                    # uinput_file is file.input
                    # uinput_folder is file.target_dir
                    #

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
            self.legacy = self.has_generic_name()
            if self.legacy:
                self.generic = self.path
            else:
                self.generic = self.get_generic_name()


        # Archiving
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
        # These are stepping stone files
        self.intermediary = None

        # TBD: TransmitFile

    def waste_file(self, item):
        """ Marks file for delition """
        ease.wastebin.append(item)

    def update(self):
        # update file names
        pass

    def has_generic_name(self):
        """ checks whether file has generic ease name """
        legacy = re.compile(r'ease_\d{4}-\d{2}-\d{2}')
        if legacy.search(self.path.name) is None:
            return False
        return True

    def get_generic_name(self) -> Path:
        """ generates generic ease name string """
        tstamp = datetime.datetime.now().isoformat()
        tstamp, _ = tstamp.split(sep="T")
        return self.path.parent / f"ease_{tstamp}"

    def set_suffix(self, suffix) -> Path:
        return Path(str(self.path.parent / self.path.stem) + suffix)

    def get_unique_middlefix(self) -> Path:
        """
        Returns a "unique" middle name for use in non-unique filenames
        use: my_var = f"{my_file.stem}-{get_unique_suffix()}{my_file.suffix}"
        Requires that my_file is path object and, of course, datetime.
        """
        midfix = int(datetime.datetime.timestamp(datetime.datetime.now()))
        return Path(str(self.path.parent / self.path.stem) + midfix)

    def __str__(self, attr):
        """ Returns path as string """
        return str(self.attr)





class LoopControl():
    """
    Used in main() main loop to generate courses of action
    Each course of action has a recipe to follow
    """
    def __init__(self, course_of_action: str, object_reference: EaseFile):
        self.input = object_reference
        try:
            LoopControl.course_of_action()
        except:
            raise Exception(f"unknown action recipe_: {course_of_action}")

    def identify(self, _coa: str):
        """
        We need to identify least necessary set of:
            source             : source files (list)
            target             : target file (generated)
            target_dir         : target directory (uinput/generated)
            temporary_archive  : tar/zip file path (generated)
        """
        self.source = self.input.list
        if self.input.legacy:
            self.basename = self.input.generic
        else:
            self.basename = self.input.basename

        self.target_dir = self.input.target_dir

#        if _coa == 'encrypt':
#            self.temporary_archive
#            self.target
#            self.source_dir = self.input.source_dir
#            self.target_dir = self.input.target_dir





#        elif _coa == 'decrypt':








    def send(self):
        pass

    def decrypt(self):
        yield self.identify('decrypt')
        pass

    def encrypt(self):
        yield self.identify('encrypt')
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
