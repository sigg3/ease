from pathlib import Path
import zipfile
import tarfile
import re
import datetime


class UserFile():
    def __init__(self, input: str):
        self.input = input
        self.output = None
        self.temporary = None
        self.as_string = input
        self.path = Path(self.as_string)
        self.is_file = self.path.is_file()
        if ";" in self.input:
            self.list = self.input.split(sep=";")
        else:
            self.list = [ input ]

    def set_temp(self, path: str):
        pass

    def set_output(self, path: str):
        pass



class EaseFile(UserFile, ArchiveFile, CryptFile):
    """
    In EASE, all input and output designators are
    attributes of an EaseFile object.
    """

    def __init__(
                 self,
                 input: str,
                 archiving: bool,
                 compression: bool,
                 use_zip: bool
                 ):
        # Names (not sure these are needed)
        self.archived = None
        self.extracted = None
        self.encrypted = None
        self.decrypted = None
        self.zip = None
        self.tar = None

#        self.output
#        self.output_encrypted =
#        self.output_compressed =
#        self.input_encrypted =
#        self.input_compressed =
#        self.input_uncompressed =
#        self.input_decrypted =


        # EASE generic file names
        self.legacy = has_generic_name(self)
        if not self.legacy:
            self.generic = get_generic_name(self)


        # Basics
        UserFile.__init__(self, input)

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
        return self.parent / f"ease_{tstamp}"

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
        self.use_zip = False
        self.use_tar = False
        self.use_compression = False
        self.is_archive = check_is_archive(self)
        if self.is_archive:
            self.compressed = self.path
            if self.use_zip:
                self.zip = self.path
            else:
                self.tar = self.path
        else:
            self.extracted = self.path
            #self.legacy = get_legacy_name(self)
            self.zip = set_suffix(self, '.zip')
            self.tar = set_suffix(self, '.tar')


    def check_is_archive(self):
        """ Determine if file is archive """
        if zipfile.is_zipfile(self.as_string):
            self.is_archive, self.use_zip = True, True
        elif tarfile.is_tarfile(self.as_string):
            self.is_archive, self.use_tar = True, True
        return self.is_archive

    def archive(self, input_files: list):
        """packs input files in tar or zip"""
        #       file_basename: str,
        #       use_tar: bool,
        #       use_compression: bool,
        #       input_files: list):
        pass

    def extract(self):
        """unpacks input file"""
        if check_is_archive(self):
            pass
        else:
            raise Exception("not an archive")

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
