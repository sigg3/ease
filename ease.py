#!/usr/bin/env python3
# coding=utf-8
# EASE: Encrypt and Send with EASE
# Simple utility for symmetric encryption of files or file archives
# prior to distribution over untrusted services (like e-mail).
#
# Copyright (C) 2020 Sigbjørn "sigg3" Smelror <git@sigg3.net>.
#
# EASE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# EASE is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
# URL: <https://www.gnu.org/licenses/old-licenses/gpl-3.0.txt>
#
# Submit issues at: <https://github.com/sigg3/ease>


# Graphical User Interface
import PySimpleGUIQt as sg

# Cryptography
from pyAesCrypt import encryptFile
from pyAesCrypt import decryptFile

# Password stuff
from password_strength import PasswordStats
from zxcvbn import zxcvbn

# Operations
from pathlib import Path
from typing import Tuple, Type
from threading import Thread
import datetime
import time
import zipfile
import tarfile
import webbrowser


# Local stuff
import something
import settings
import IPython

# Translations
import gettext
_ = gettext.gettext


# # TODO:
# Drag and drop:
# 'file:///home/sigg3/christina\r\n'
# add hidden input field to main window, dropping file gathered
# can trigger encrypt or decrypt event

# List of issues, todos and bugs (by priority)
# TODO password evaluation
# zxcvbn-python, add "evaluate" button under passphrase entry on Encrypt
# Note: This is a good candidate for separate module.
# Move zxcvbn-python to separate module.
#
# TODO cut up file
# Separating files, e.g. having a setup_transmitters.py file for
# def setup_transmitters: how does it affect translating?
#
# TODO sending
# Using selenium is not recommended at this stage, because we will need
# a separate geckodriver install (and probably break ToS).
# Using webbrowser instead, we can serve a number of convenient links
# for sharing file(s), and also a button to attach to e-mail message.
#
# TODO
# in pysimplegui june 2020, signalling windows from other threads was added.
# Look into whether this is a worthwhile change to ease.
# In the meantime, existing is_alive method in Thread objects is sufficient.
# cf. create_spinner() and run_in_the_background()

# TODO keyfiles
# while we want to keep things simple, it's only a matter of time before
# someone requests asymmetric encryption
#
# TODO Functional branch
# If we are going to learn methodology, better do it functionally too.




# Classes

def create_main_window() -> Type[sg.Window]:
    """
    Create (and re-create) main (or initial) window
    Return window object to allow for assignment to variable in main.
    """

    # Set icons
    icon_encrypt = ease.icon["icon_encrypt"]
    icon_decrypt = ease.icon["icon_decrypt"]
    icon_send = ease.icon["icon_sendenc"]
    icon_about = ease.icon["icon_easehlp"]


    # Set icon text
    caption_encrypt = _("Encrypt")
    caption_decrypt = _("Decrypt")
    caption_send = _("Send")
    caption_about = _("About")


    # Justify icons using stringName.center(width,fillChar)
    # TODO
    caption_send    = f" {caption_send}"   # space added for English
    caption_about   = f" {caption_about}"  # Qt justification :( # TODO


    # Set layout
    WelcomeLayout = [
                [sg.Text(f"{ease.title}", font=("Sans serif", 16))],
                [sg.Text(" ")],
                [sg.Text(
                    _("Encrypt a file or files securely so it's safe \
to distribute, or decrypt files you have received.")
                    )
                ],
                [sg.Text(
                    _("This utility uses AES256-CBC (pyAesCrypt) to \
encrypt/decrypt files in the AES Crypt file format v.2.")
                    )
                ],
                [sg.Text(" ")],
                [sg.Button(
                    caption_encrypt,
                    image_data=icon_encrypt,
                    key="-button_encrypt-",
                    font=("Helvetica", 16)
                    ),
                 sg.Button(
                    caption_decrypt,
                    image_data=icon_decrypt,
                    key="-button_decrypt-",
                    font=("Helvetica", 16)
                    )
                ],
                [sg.Button(
                    caption_send,
                    image_data=icon_send,
                    key="-button_send-",
                    font=("Helvetica", 16)
                    ),
                 sg.Button(
                    caption_about,
                    image_data=icon_about,
                    key="-button_about-",
                    font=("Helvetica", 16)
                    )
                ],
                [sg.Text(" ")]
                ]

    # Window object
    Welcome = sg.Window(
                        ease.title,
                        layout=WelcomeLayout,
                        resizable=True,
                        return_keyboard_events=False,
                        finalize=True
                        )

    # return object to var
    return Welcome


def create_enc_window() -> Type[sg.Window]:
    """
    Helper function to create (and re-create) encryption window
    Return window object to allow for assignment
    """

    # Set tables
    encrypt_options = [
        [
        sg.CBox(
            _("Enable compression (smaller file size)"),
            default=False,
            key="compression"
            )
        ],
        [
        sg.Radio(
            "tarball",
            "archive_radio",
            key="tar"
            ),
        sg.Radio(
            "zip",
            "archive_radio",
            key="zip"
            )
        ]
    ]

    encrypt_input = [
        [
        sg.InputText(
            key="enc_uinput_files",
            enable_events=True
            ),
        sg.FilesBrowse(
            target="enc_uinput_files"
            )
        ]
    ]

    encrypt_output = [
        [
        sg.InputText(
            ease.output_dir,
            disabled=True,
            key="output_preview_str"
            ),
        sg.FolderBrowse(
            target="output_preview_str"
            )
        ]
    ]

    # Set layout
    EncryptLayout = [
        [sg.Text(
            f"{ease.title}", font=("Sans serif", 16)
            )
        ],
        [sg.Text(" ")],
        [sg.Text(
            _("Securely encrypt file(s), so it is safe to distribute \
over untrusted service (like e-mail).")
            )
        ],
        [sg.Text(
            _("If you select more than one file, they will be gathered \
in an encrypted archive.")
            )
        ],
        [sg.Text(
            _("If your recipient uses Windows, consider using zip \
instead of tar.")
            )
        ],
        [sg.T(" ")],
        [sg.Frame(
            layout=encrypt_input,
            title=_("Select input file(s):")
            )
        ],
        [sg.Frame(
            layout=encrypt_output,
            title=_("Specify where to save the output")
            )
        ],
        [sg.Frame(
            layout=encrypt_options,
            title=_("Archiving options (for groups of files)")
            )
        ],
        [sg.Frame(layout=[
            [sg.T(_("It is recommended to use a full sentence as \
the passphrase."))],
            [sg.In("", key="uinput_passphrase")],
            [sg.T(get_password_strength(""), key="uinput_ppstrength")]
            ],
            title=_("Passphrase")
            )
        ],
        [
        sg.Button(_("Encrypt"), key="-enc_encrypt-"),
        sg.Cancel(_("Cancel"), key="-enc_cancel-")
        ]
    ]

    Encrypt = sg.Window(
                        ease.title,
                        layout=EncryptLayout,
                        resizable=True,
                        return_keyboard_events=True,
                        finalize=True
                        )
    return Encrypt


def create_dec_window() -> Type[sg.Window]:
    """
    Helper function to create (and re-create) decryption window
    Return window object to allow for assignment
    """

    # Set tables
    decrypt_input = [
        [
        sg.InputText(key="dec_uinput_file", enable_events=True),
        sg.FileBrowse(target="dec_uinput_file")
        ]
    ]

    decrypt_options = [
        [sg.CBox(
            _("Automatically decompress decrypted archives"),
            default=True,
            key="uncompress"
            )
        ],
        [sg.CBox(
            _("Remove source .aes file after decryption"),
            default=False,
            key="removesrc"
            )
        ]
    ]

    decrypt_output = [
        [
        sg.InputText(
            ease.output_dir,
            disabled=True,
            key="dec_output_preview_str"
            ),
        sg.FolderBrowse(
            target="dec_output_preview_str"
            )
        ]
    ]

    decrypt_passphrase = [
        [sg.In(
            "",
            key="uinput_passphrase"
            )
        ]
    ]


    # Set layout
    DecryptLayout = [
        [sg.Text(
            f"{ease.title}",
            font=("Sans serif", 16)
            )
        ],
        [sg.Text(" ")],
        [sg.Text(
            _("Decrypt any encrypted .aes file you have received.")
            )
        ],
        [sg.Text(
            _("If the decrypted file is a tarball or zip archive, \
it will be extracted.")
            )
        ],
        [sg.T(" ")],
        [sg.Frame(
            layout=decrypt_input,
            title=_("Select input file(s)")
            )
        ],
        [sg.Frame(
            layout=decrypt_options,
            title=_("Decryption options")
            )
        ],
        [sg.Frame(
            layout=decrypt_output,
            title=_("Specify where to save the output")
            )
        ],
        [sg.Frame(
            layout=decrypt_passphrase,
            title=_("Passphrase")
            )
        ],
        [
        sg.Button(_("Decrypt"), key="-dec_decrypt-"),
        sg.Cancel(_("Cancel"), key="-dec_cancel-")
        ]
    ]

    Decrypt = sg.Window(
                        ease.title,
                        layout=DecryptLayout,
                        resizable=True,
                        return_keyboard_events=False,
                        finalize=True
                        )
    return Decrypt


def create_send_window() -> Type[sg.Window]:
    """
    Helper function to create (and re-create) file send window.
    Return window object to allow assignment
    """

    # Fetch latest transmitter info
    sites = ease.sites

    # Set first item as default
    for sitename in sites.keys():
        siteinfo = get_infostring_from_key(sitename)
        break # we just need the first one for creation

    site_sentence = siteinfo[0]
    site_cap = siteinfo[1]
    site_faq = siteinfo[2]
    xfer_disabled = siteinfo[3]


    # File xfer site info table
    xfer_site = [
        [sg.T(
            f"URL: {sites[sitename]['site_url']}",
            key="-provider_url-"
            )
        ],
        [sg.T(
            site_faq,
            key="-provider_faq-"
            )
        ],
        [sg.T(
            site_sentence,
            key="-provider_info-"
            )
        ],
        [sg.T(
            site_cap,
            key="-provider_capinfo-"
            )
        ]
    ]

    # Window layout
    SendfileLayout = [
        [sg.Text(
            f"{ease.title}",
            font=("Sans serif", 16)
            )
        ],
        [sg.Text(" ")],
        [sg.Text(
            _("Sometimes files are too big for attaching to e-mails.")
            )
        ],
        [sg.Text(
            _("Most of these online file transfer services do not require a login.")
            )
        ],
        [sg.Text(
            _("Select any provider to visit their website or attempt sending.")
            )
        ],
        [sg.Text(" ")],
        [
            sg.Text(
                _("Choose file transfer service: ")
            ),
            sg.Combo(
                 list(sites.keys()),
                 default_value=sitename,
                 key="-send_combo-",
                 readonly=True,
                 enable_events=True)
        ],
        [sg.Frame(
            layout=xfer_site,
            title=" " # title is workaround
            )
        ],
        [sg.Text(" ")],
        [
        sg.Button(
            _("Send"),
            key="-send_send-",
            disabled=xfer_disabled
            ),
        sg.Button(
            _("Open URL"),
            key="-visit_url-"
            ),
        sg.Button(
            _("Cancel"),
            key="-send_cancel-"
            )
        ]
    ]

    SendFile = sg.Window(
                         ease.title,
                         layout=SendfileLayout,
                         resizable=True,
                         return_keyboard_events=False,
                         finalize=True
                         )

    return SendFile


def create_about_window() -> Type[sg.Window]:
    """
    Helper function to create (and re-create) an about window.
    Returns a window object to allow assignment
    """

    contrib = _("Submit issues and new translations at")

    # Window layout
    AboutLayout = [
    [sg.Text(f"{ease.title}", font=("Sans serif", 16))],
    [sg.Text(" ")],
    [sg.Text(_("EASE is written by Sigbjørn Smelror (c) 2020, GNU GPL v.3+, to provide"))],
    [sg.Text(_("a hopefully user-friendly graphical interface to the pyAesCrypt module."))],
    [sg.Text(_("It is distributed in the hope that it will be useful, but without any warranty."))],
    [sg.Text(_("See the GNU General Public License for more details."))],
    [sg.Text(f"{contrib}: {ease.git}")],
    [sg.Text(" ")],
    [sg.Text(_("Usage should be fairly straight-forward: Encrypt -> Send -> Decrypt"))],
    [sg.Text(" ")],
    [sg.Text(_("Encrypting"), font=("Sans serif", 12))],
    [sg.Text(_("The sender clicks the Encrypt button, selects the file(s) to encrypt,"))],
    [sg.Text(_("and encrypts them using a passphrase (password) of his or her choosing."))],
    [sg.Text(_("It is recommended to use a full sentence as the passphrase."))],
    [sg.Text(_("This produces an encrypted AES Crypt v.2 file that has an .aes suffix."))],
    [sg.Text(" ")],
    [sg.Text(_("Sending"), font=("Sans serif", 12))],
    [sg.Text(_("The encrypted .aes file can be distributed over untrusted services like"))],
    [sg.Text(_("e-mail or any of the file transfer services available when clicking Send."))],
    [sg.Text(_("Some services will provide a download link (URL) the recipient can use."))],
    [sg.Text(_("Remember: never send an encrypted file and its passphrase together!"))],
    [sg.Text(" ")],
    [sg.Text(_("Decrypting"), font=("Sans serif", 12))],
    [sg.Text(_("Having received the encrypted .aes file through e-mail or a service (above),"))],
    [sg.Text(_("the recipient simply clicks the Decrypt button, selects the (.aes) file and"))],
    [sg.Text(_("enters the passphrase (password) provided separately by the sender."))],
    [sg.Text(_("And that's it!"))],
    [sg.Text(" ")],
    [sg.Text(_("EASE Crypto relies on pyAesCrypt, password_strength and zxcvbn-python"))],
    [sg.Text(_("Graphical interface is provided by PySimpleGUIQt, translations use gettext."))],
    [sg.Text(_("EASE is not affiliated with any of the file transfer services mentioned, and"))],
    [sg.Text(_("please submit an issue if any of the services are terminated or changed."))],
    [sg.Text(" ")],
    [
    sg.Button(
        _("Homepage"),
        key="-github-"
        ),
    sg.Button(
        _("OK"),
        key="-about_ok-"
        )
    ]
    ]



    About = sg.Window(
                      ease.title,
                      layout=AboutLayout,
                      resizable=False,
                      return_keyboard_events=False,
                      finalize=False
                      )

    return About


def get_infostring_from_key(key: str) -> Tuple[str, str, str, bool]:
    """
    Build string from sites[] dict in setup_transmitters()
    Returns a tuple: f-string of general site info, and a bool
    """

    # fetch data
    sites = ease.sites

    # automated "send" action button disabled/enabled status
    # bool value opposite of bool in sites[key]["automated"]
    xfer_disabled = False if sites[key]["automated"] else True

    # build site info string
    site_sentence = _("Max file size")
    site_sentence += f": {sites[key]['max_size_gb']}, "
    site_sentence += _("Expires (days)")
    site_sentence += f": {sites[key]['days_expire']}, "

    # finish info string
    site_sentence += _("Require log-in")
    site_sentence += ": "
    if sites[key]["require_login"]:
        site_sentence += _("Yes")
        xfer_disabled = True # override (avoids this whole bag of bugs)
    else:
        site_sentence += _("No")

    # get site cap (limitations) info
    limitations = _("Limitations")
    site_cap = sites[key]["limitations"]
    if site_cap is None:
        site_cap = f"{limitations}: N/A"
    else:
        site_cap = f"{limitations}: {site_cap}"

    # get faq (URL)
    site_faq = _("FAQ")
    site_faq += ": "
    site_faq += sites[key]["faq"]

    return site_sentence, site_cap, site_faq, xfer_disabled




def get_folder_from_infiles(input_files: str) -> str:
    """
    Return string of path object's parent if indeed the input is a
    valid path else return safe default from settings.
    """
    try:
        if Path.is_file(Path(input_files)):
            return str(Path(input_files).parent)
        elif Path.is_file(Path(input_files.split(sep=";")[0])):
            return str(Path(input_files.split(sep=";")[0]).parent)
        else:
            return str(ease.output_dir)
    except:
        return str(ease.output_dir)


def get_unique_middlefix() -> int:
    """
    Returns a "unique" middle name for use in non-unique filenames
    use: my_var = f"{my_file.stem}-{get_unique_suffix()}{my_file.suffix}"
    Requires that my_file is path object and, of course, datetime.
    """
    return int(datetime.datetime.timestamp(datetime.datetime.now()))


def get_password_strength(uinput_passphrase: str) -> str:
    """
    We're not evaluating password policies, just providing feedback
    Use: get_password_strength(Encrypt_value['uinput_passphrase'])
    """
    # string wrangling
    entropy = _("Passphrase entropy bits")
    complexity = _("complexity")
    score = _("score")

    if uinput_passphrase is None or uinput_passphrase == "":
        return f"{entropy}: 0.0, {complexity}: 0.00, {score}: 0"

    stats = PasswordStats(uinput_passphrase)
    pass_c = f"{stats.strength():0.2f}"
    pass_e = f"{stats.entropy_bits:0.1f}"
    pass_s = zxcvbn(uinput_passphrase)["score"]

    return f"{entropy}: {pass_e}, {complexity}: {pass_c}, {score}: {pass_s}"


def evaluate_password(input_pass: str):
    """
    Evaluates user passphrase (string) using zxcvbn
    zxcvbn uses gettext, so no need to duplicate translations.
    Until further notice, cf. translate_zxcvbn_strings(). # TODO
    """

    # Evaluate input
    pass_check = zxcvbn(input_pass)


    # Expose selected strings to gettext
    # Password strings

    # debug
    print(f"pass_check = {pass_check}")

    print(pass_check["feedback"]["suggestions"][0])

    # Crack times

    # General
#    str_feed = _("Feedback")
#    str_warn = _("Warning")
#    str_sugg = _("suggestions")

    # Suggestion strings
    str_addword = _("Add another word or two. Uncommon words are better.")



    return str_addword


def translate_zxcvbn_strings():
    """
    Dummy function to expose strings from imported module
    zxcvbn's feedback.py to local gettext extraction
    This dummy function provides a stale workaround. TBD
    """
    # TODO find a smarter solution..
    str_null = _("Use a few words, avoid common phrases."),
    str_null = _("No need for symbols, digits, or uppercase letters.")
    str_null = _("Add another word or two. Uncommon words are better.")
    str_null = _("Straight rows of keys are easy to guess.")
    str_null = _("Short keyboard patterns are easy to guess.")
    str_null = _("Use a longer keyboard pattern with more turns.")
    str_null = _("Repeats like \"aaa\" are easy to guess.")
    str_null = _("Repeats like \"abcabcabc\" are only slightly harder to guess than \"abc\".")
    str_null = _("Avoid repeated words and characters.")
    str_null = _("Sequences like \"abc\" or \"6543\" are easy to guess."),
    str_null = _("Recent years are easy to guess."),
    str_null = _("Avoid recent years."),
    str_null = _("Avoid years that are associated with you."),
    str_null = _("Dates are often easy to guess."),
    str_null = _("Avoid dates and years that are associated with you."),
    str_null = _("This is a top-10 common password.")
    str_null = _("This is a top-100 common password.")
    str_null = _("This is a very common password.")
    str_null = _("This is similar to a commonly used password.")
    str_null = _("A word by itself is easy to guess.")
    str_null = _("Names and surnames by themselves are easy to guess.")
    str_null = _("Common names and surnames are easy to guess.")
    str_null = _("Capitalization doesn't help very much.")
    str_null = _("All-uppercase is almost as easy to guess as all-lowercase.")
    str_null = _("Reversed words aren't much harder to guess.")
    str_null = _("Predictable substitutions like '@' instead of 'a' don't help very much.")
    pass


def archive(file_basename: str,
            use_tar: bool,
            use_compression: bool,
            input_files: list) -> Tuple[list, str]:
    """
    Write tar or zip file, depending on use_tar bool, containing items
    in input_files list with optional (medium) compression. The function
    handles filename too, given a basename. Returns tuple with a list
    of file(s) successfully archived and the final filename we wrote.
    Requires tarfile, zipfile, zlib, Path (pathlib)
    """
    # Setup return vals
    return_list = []
    archive_filename = ""

    # configure parameters for archiving procedure
    if use_tar:
        archivist = tarfile.open
        if use_compression:
            ftype="tar.gz"
            compression = "w:gz"
        else:
            ftype="tar"
            compression = "w"
        use_mode = compression

    else:
        archivist = zipfile.ZipFile
        ftype="zip"
        compression = zipfile.ZIP_STORED
        if use_compression:
            try:
                import zlib
                compression = zipfile.ZIP_DEFLATED
            except (ImportError, AttributeError):
                compression = zipfile.ZIP_STORED
            except Exception as e:
                print(f"Unhandled exception in archive(): {e}")
        use_mode = "w"


    # Set output file (make unique if necessary)
    archive_filename = f"{file_basename}.{ftype}"
    if Path.is_file(Path(archive_filename)):
        archive_filename = f"{file_basename}-{get_unique_middlefix()}.{ftype}"

    # archive input files into archive_file using procedure set
    with archivist(archive_filename, mode=use_mode) as new_archive:
        for file_to_archive in input_files:
            try:
                file_arcname = str(Path(file_to_archive).stem)
                if use_tar:
                    new_archive.add(
                        file_to_archive,
                        arcname=file_arcname # arcname=stem here did not work..
                        )
                else:
                    new_archive.write(
                        file_to_archive,
                        arcname=file_arcname,
                        compress_type=compression
                        )

                return_list.append(file_to_archive)
            except Exception as e:
                print(f"{archivist} could not add {file_to_archive}: {e}")
                pass

    return return_list, archive_filename


def unarchive(archive_filename: str, output_dir: str) -> Tuple[list, list]:
    """
    Extract archive, whether zip or tar to output dir
    Returns lists of file(s) extracted into output dir and skipped files
    """
    # Setup return vals
    extracted = []
    skipped = []

    # Detect what kind of input we have here
    if tarfile.is_tarfile(archive_filename):
        archivist = tarfile.open
        is_tar = True
        use_mode = "r:*"
    elif zipfile.is_zipfile(archive_filename):
        archivist = zipfile.ZipFile
        is_tar = False
        use_mode = "r"
    else:
        raise TypeError(f"Input {archive_filename} not tar or zip.")
        return extracted, skipped

    with archivist(archive_filename, use_mode) as input_archive:
        # get content list
        if is_tar:
            archive_contents = input_archive.getnames()
        else:
            archive_contents = input_archive.namelist()

        # extract 'em
        for archived_item in archive_contents:
            try:
                input_archive.extract(archived_item, path=f"{output_dir}")
                extracted.append(archived_item)
            except:
                skipped.append(archived_item)

    return extracted, skipped



# Threading functions
# The functions below are related to / used by threading

def create_spinner(show_text: str, show_time: float) -> Type[sg.Window]:
    """
    Helper function to create (and re-create) "Working..." popup
    Returns window object. Will be re-created if the user hits X.
    """

    # Make strings available to gettext :P
    patience = _("This might take a while.")
    elapsed = _("Elapsed time")
    secs = _("seconds")

    # create spinner
    spinner_layout = [
        [sg.T(
              f"{show_text}.. {patience}.\n{elapsed}: {show_time} {secs}",
              key="-spinner_text-"
              )
        ]
    ]

    return sg.Window(
                    f"{show_text} ..",
                    layout=spinner_layout,
                    grab_anywhere=True,
                    keep_on_top=True,
                    finalize=True
                    )


def unarchive_worker(
                     archive_filename: str,
                     output_dir: str,
                     out_dict: dict,
                     out_index: str):
    """
    Helper function to run unarchive() in a separate thread using Thread.
    Will save return values from archive into out_dict <dict> index <index>
    """

    try:
        extracted, skipped = unarchive(
                                       archive_filename,
                                       output_dir
                                       )
    except TypeError:
        # not an error, input not an archive. we will not unarchive it
        # use might have sent a file with .tar extension that is not tar ..
        extracted, skipped = [], []
    except Exception as e:
        extracted, skipped  = "error", e # export error str to thread dict

    out_dict[out_index] = extracted, skipped


def archive_worker(file_basename: str,
                   use_tar: bool,
                   use_compression: bool,
                   input_files: list,
                   out_dict: dict,
                   out_index: str):
    """
    Helper function to run archive() in a separate thread using Thread.
    Will save return values from archive into out_dict <dict> index <index>
    """
    out_dict[out_index] = archive(
                                   file_basename,
                                   use_tar,
                                   use_compression,
                                   input_files
                                  )


def aescrypt_worker(encrypt: bool,
                    input_f: str,
                    output_f: str,
                    user_passphrase: str,
                    out_dict: dict,
                    out_index: str):
    """
    Helper function to execute encryp/decryption (depending on encrypt bool)
    in a separate thread. Returns status message to out_dict['out_index']
    """

    # Get universal buffer size
    buffer_size = ease.crypt_buffer

    # Determine method
    if encrypt:
        aes_exec = encryptFile
    else:
        aes_exec = decryptFile

    # Execute work
    try:
        aes_exec(input_f, output_f, user_passphrase, buffer_size)
        out_dict[out_index] = (0, None) # 0 == success
    except IOError as e:
        out_dict[out_index] = (1, e)
    except Exception as e:
        out_dict[out_index] = (2, e)



def run_in_the_background(worker_to_run: str, worker_args: list):
    """
    This is a meta function to execute any of the workers above and the
    surrounding GUI loops (non-blocing blocking) using create_spinner()..
    Since running a thread with the gui and everything is > 5 lines of code
    and we do it 4 times (archiving, extracting, encrypting, decrypting)
    I collected all of them here.

    N return value because the thread saves to ease.thread.
    """

    # set thread parameters
    # dict[index] sent to background task in order to save output
    output_dict = ease
    output_index = "thread"
    daemonize_setting = True

    if worker_to_run == "archive":
        worker_function = archive_worker
        show_text = _("Archiving")
    elif worker_to_run == "unarchive":
        worker_function = unarchive_worker
        show_text = _("Extracting")
    else:
        worker_function = aescrypt_worker
        if worker_to_run == "encrypt":
            show_text = _("Encrypting")
        else:
            show_text = _("Decrypting")


    # (re)set ease dict key 'thread' to store output values from thread
    output_dict[output_index] = None

    # Create arguments for worker
    input_arguments = tuple(worker_args + [output_dict, output_index])

    # Create threading.Thread object
    worker = Thread(
                     target=worker_function,
                     args=input_arguments,
                     daemon=daemonize_setting
                    )

    # Create popup_window working dot dot dot...
    spinner = create_spinner(show_text, 0.2) # 0.2 sec headstart

    # Start worker
    worker.start()

    # Start the timer
    start_time = time.time()

    # Give a head start
    time.sleep(0.2)

    # "non-block blocking" UI (will respawn "working.." popup if closed)
    while worker.is_alive():
        spinner_e, spinner_v = spinner.read(timeout=400)
        if spinner_e is None:
            spinner_e = ""
            spinner_v = ""
            spinner.close()
            time.sleep(0.1)
            elapsed_time = f"{time.time() - start_time:0.1f}"
            spinner = create_spinner(show_text, elapsed_time)

        if spinner_e == "__TIMEOUT__":
            # Make strings available to gettext :P
            str_0 = _("This might take a while.")
            str_1 = _("Elapsed time")
            secs = _("seconds")
            time_elapsed = f"{time.time() - start_time:0.1f}"

            spinner["-spinner_text-"].update(
                f"{show_text}.. {str_0}.\n{str_1}: {time_elapsed} {secs}"
                )


    # join threads
    # (not sure if this is required? TO CHECK) TODO
    worker.join()

    # close GUI window
    spinner.close()

    # debug output
    if output_dict[output_index] is None:
        raise Exception("Thread worker failure")

def main():
    """
    EASE entry point function
    """
    # TO BE DONE
    # Determine whether we are running in cli or not

    # PySimpleGUIQt color theme
    sg.ChangeLookAndFeel(ease.guitheme)

    # Window visibility toggles
    show_encrypt = False
    show_decrypt = False
    show_send = False
    show_about = False

    # Listed files will be removed (unlinked) in event loop
    # These are typically temporary files: e.g. when sending >1 file we
    # create an archive and encrypt that. The unencrypted archive is garbage.
    files_to_remove = ease.wastebin

    # Create main window
    MainWindow = create_main_window()


    # Root event loop
    while True:

        # Clean up temporary files
        if files_to_remove:
            ease.clean_up()

        # Read events and values from Main
        Main_event, Main_value = MainWindow.read()

        #print(f"Main_event  = {Main_event}\nMain_value  = {Main_value}")  # debug

        # The WIN_CLOSED conditional must be separated from another
        # arguments for some inexplicable reason (PySimpleGUI)
        if Main_event == sg.WIN_CLOSED: break

        # Deal with options separately (weird bug with pysimplegui)
        if Main_event == "-button_encrypt-" and show_encrypt is False:
            show_encrypt = True
            MainWindow.Hide() # "closes" main window
            Encrypt = create_enc_window()
            while show_encrypt:
                Encrypt_event, Encrypt_value = Encrypt.read()

                if Encrypt_event == sg.WIN_CLOSED:
                    show_encrypt = False

                if Encrypt_event == "-enc_cancel-":
                    show_encrypt = False
                elif Encrypt_event == "enc_uinput_files":
                    # Update output folder to match parent dir of
                    # files selectes as input (quality of life + 1)
                    Encrypt["output_preview_str"].update(
                        get_folder_from_infiles(
                            Encrypt_value["enc_uinput_files"]
                            )
                    )
                elif Encrypt_event == "-enc_encrypt-":

                    # # TODO
                    # 1. create object
                    # 2. run LoopControl with object

                    # tar/zip selection is bool
                    # and default is to use tar (uncompressed)
                    # TBD remove zip from equation, standardize on tar

                    # create input file object
                    file = EaseFile(
                        Encrypt_value["enc_uinput_files"],
                        Encrypt_value["compression"],
                        Encrypt_value["tar"],
                        Encrypt_value["zip"]
                    )

                    # Retrieve other user input
                    file.target_dir = Path(Encrypt_value["output_preview_str"])
                    if file.target_dir.is_dir():
                        pass
                    else:
                        file.target_dir = file.source_dir

                    try:
                        file.set_passphrase(Encrypt_value["uinput_passphrase"])
                    except Exception as e:
                        if e == "pass_too_short":
                            err_str = _("Error: password too short")
                            sg.popup_error(
                                err_str,
                                title=_("Error")
                                )
                            show_encrypt = False
                            break
                        else:
                            err_str = _("Error: password too long")
                            sg.popup_error(
                                err_str,
                                title=_("Error")
                                )
                            show_encrypt = False

                    # Here now, just execute loop control, u ass:!

                    # uinput_file is file.input
                    # uinput_folder is file.target_dir
                    # uinput_files er file.list
                    #
                    #



                    if file.use_archiving:
                        try:
                            # execute tar/zip in separate thread
                            # save status messages to ease.thread
                            file.archive()
                            archive_list, archive_file = ease.thread
                            number_of_inputs = len(file.list)
                            archived_items = len(archive_list)

                            if archived_items is 0:
                                archive_error = True
                                err_str = _("Could not archive any files")
                            elif archived_items != number_of_inputs:
                                archive_error = True
                                err_str = _("Could not archive all files")
                            else:
                                archive_error = False

                            if archive_error:
                                err_out = archived_items
                                err_ins = number_of_inputs
                                err_abort = _("Aborting")
                                err_msg = f"{err_str}: {err_out} / {err_ins}"
                                sg.popup_error(
                                    f"{err_msg}. {err_abort}!",
                                    title=_("Archiving error")
                                    )
                                if Path(archive_file).is_file():
                                    file.waste_file(archive_file) # 2b removed
                                show_encrypt = False
                                break

                            if Path(archive_file).is_file():
                                file.intermediary = archive_file
                                file.waste_file(archive_file) # 2b removed
                            else:
                                err_msg = _("Error: output archive not a file")
                                err_abort = _("Aborting")
                                sg.popup_error(
                                    f"{err_msg}. {err_abort}!",
                                    title=_("Archiving error")
                                    )
                                show_encrypt = False
                                break

                            # if success, then archive file is encryption src
                        except Exception as e:
                            if e == "file_already_archived":
                                file.intermediary = file.as_string
                            else:
                                err_msg = _("Unknown error")
                                err_abort = _("Aborting")
                                sg.popup_error(
                                    f"{err_msg}: {e}. {err_abort}!",
                                    title=_("Archiving error")
                                    )
                                show_encrypt = False
                                break
                    else:
                        # Not archiving, use file path as string
                        file.intermediary = file.as_string


                    if file.encrypted.is_file():
                        # file already exists, do not overwrite
                        file.encrypted = file.get_unique_middlefix()
                        file.encrypted = Path(file.encrypted) + '.aes'


                    # run aescrypt worker in separate thread
                    # reports back to ease.thread aws tuple
                    # in  file.intermediary
                    # out file.encrypted
                    file.encrypt()

                    # get status
                    encrypt_exit, encrypt_error = ease.thread

                    if enc_exit is 0:
                        # success popup
                        inputs_str = "\n".join(self.list)
                        err_str = _("Successfully encrypted the input file(s)")
                        err_str += f":\n\n{inputs_str}\n\n"
                        err_str += f"({Path(actual_output).name}"
                        sg.popup_ok(
                            err_str,
                            title=_("Success!")
                        )
                    elif enc_exit == 1:
                        err_str = _("I/O error")
                        sg.popup_error(
                            f"{err_str}: {encrypt_error}",
                            title=err_str
                            )
                    elif enc_exit == 2:
                        err_str = _("Encryption error")
                        sg.popup_error(
                            f"{err_str}: {encrypt_error}",
                            title=err_str
                            )
                    else:
                        err_str = _("Unhandled exception")
                        sg.popup_error(
                            f"{err_str}: ease.thread not in 0-2",
                            title=err_str
                            )

                    # Quit to main either way
                    show_encrypt = False
                    break # should not be necessary but sometimes it is ..


                else:
                    # an "else" here is probably input into passphrase box
                    Encrypt["uinput_ppstrength"].update(
                        get_password_strength(Encrypt_value["uinput_passphrase"])
                        )

            # reclaim file namespace for the great nothing
            del file

            # End encryption window
            Encrypt.close()

            # Re-open main window
            MainWindow.UnHide()

        elif Main_event == "-button_decrypt-" and show_decrypt is False:
            show_decrypt = True
            MainWindow.Hide()
            Decrypt = create_dec_window()

            # Do decryption loop
            while show_decrypt:
                Decrypt_event, Decrypt_value = Decrypt.read()

                if Decrypt_event == sg.WIN_CLOSED:
                    show_decrypt = False

                if Decrypt_event == "-dec_cancel-":
                    show_decrypt = False

                if Decrypt_event == "dec_uinput_file":
                     # Update output folder in GUI to match parent
                     # dir of files selectes as input (quality of life + 1)
                    Decrypt["dec_output_preview_str"].update(
                        get_folder_from_infiles(
                            Decrypt_value["dec_uinput_file"]
                            )
                        )

                elif Decrypt_event == "-dec_decrypt-":
                    # user clicked "Decrypt" to execut decryption on input

                    # the file to decrypt
                    uinput_file = Decrypt_value["dec_uinput_file"]

                    # the passphrase to be used
                    uinput_passphrase = Decrypt_value["uinput_passphrase"]

                    # uncompress file after decryption (if an archive)
                    uinput_unarchive = Decrypt_value["uncompress"]

                    # remove source .aes file after successful decryption
                    uinput_cleanup = Decrypt_value["removesrc"]

                    # target directory for decrypted (and extracted) files
                    uinput_outdir = Decrypt_value["dec_output_preview_str"]

                    if Path.is_dir(Path(uinput_outdir)):
                        pass
                    else:
                        err_str = _("Selected directory not a directory")
                        sg.popup_error(
                            f"{err_str}:\n{uinput_outdir}",
                            title=_("Error")
                            )
                        show_decrypt = False
                        break

                    if Path.is_file(Path(uinput_file)):
                        # read first bytes (AES header is a requirement)
                        # cf. https://github.com/marcobellaccini/pyAesCrypt/issues/11
                        with open(uinput_file, "rb") as rawfile: byte = str(rawfile.read(32))

                        if "AES" in byte or "aescrypt" in byte.lower():

                            # We know it's an aes file, but it might have invalid extension
                            output_file = Path(uinput_outdir) / Path(uinput_file).stem
                            if Path(uinput_file).parent == Path(uinput_outdir):
                                if uinput_file.endswith("aes"):
                                    pass
                                else:
                                    # This is an ugly hack
                                    output_file = Path(str(output_file + ".out"))

                            # Create unique output name if out file exists
                            if output_file.is_file():
                                output_alt = output_file.parent / output_file.stem
                                output_alt = f"{output_alt}-{get_unique_middlefix()}"
                                output_file = f"{output_alt}{output_file.suffix}"


                            # Run aescrypt_worker in a separate thread
                            # while displaying a "working..." animated pop-up
                            # and report back to ease.thread attr,
                            run_in_the_background(
                                "decrypt",
                                [
                                    False,
                                    uinput_file,
                                    str(output_file),
                                    uinput_passphrase
                                ]
                            )

                            # parse return from separate thread
                            if ease.thread[0] == 0:
                                pass # success!
                            elif ease.thread[0] == 1:
                                err_str = _("I/O error")
                                sg.popup_error(
                                    f"{err_str}: {ease.thread[1]}",
                                    title=err_str
                                    )
                                uinput_cleanup = False
                                show_decrypt = False
                                break # should be superfluous ..
                            elif ease.thread[0] == 2:
                                err_str = _("Decryption error")
                                sg.popup_error(
                                    f"{err_str}: {ease.thread[1]}",
                                    title=err_str
                                    )
                                uinput_cleanup = False
                                show_decrypt = False
                                break # should be superfluous ..


                            # check if it's an archive
                            # if so, we will extract the archive contents into out_directory
                            if Path(output_file).is_file():
                                if uinput_unarchive:

                                    # Run extraction in the background (threading)
                                    # while showing a "Working ..." pop-up
                                    # Output saved in ease.thread
                                    run_in_the_background(
                                        "unarchive",
                                        [
                                            str(output_file),
                                            uinput_outdir
                                        ]
                                    )

                                    # parse returns from background thread
                                    if type(ease.thread[0]) is list:
                                        pass
                                    elif ease.thread[0] == "error":
                                        err_str = _("Error")
                                        sg.popup_error(
                                            f"{err_str}: {ease.thread[1]}.",
                                            title=err_str
                                            )
                                        uinput_cleanup = False
                                        show_decrypt = False # TODO is this correct??
                                        break
                                    else:
                                        err_str = "Weird unhandled case unarchiving."
                                        sg.popup_error(
                                            err_str, title=_("Error")
                                            )
                                        uinput_cleanup = False

                                    extracted_files = ease.thread[0]
                                    skipped_files = ease.thread[1]
                                    num_extract = len(extracted_files)
                                    num_archived = num_extract + len(skipped_files)


                                    # Determine deletion of temporary "leftover" archive file
                                    if num_archived == 0 and num_extract == 0:
                                        # This file was not archived in the
                                        # first place and so we must skip
                                        # deletion of temp archive file
                                        num_archived, num_extract = 1, 1
                                    else:
                                        # delete obsolete temp archive file
                                        # called "output_file"
                                        # (end-user wants extracted contents)
                                        files_to_remove.append(str(output_file))
                                else:
                                    num_extract, num_archived = 1, 1


                                # Give visual feedback
                                if num_extract == num_archived:
                                    pop_msg = _("Successfully decrypted input file(s)")
                                    pop_ex = num_extract
                                    pop_arc = num_archived
                                    sg.popup_ok(
                                        f"{pop_msg}: {pop_ex} / {pop_arc}",
                                        title=_("Success")
                                    )

                                else:
                                    pop_msg = _("Successfully decrypted input file(s)")
                                    pop_note = _("Skipped items")
                                    pop_ex = num_extract
                                    pop_arc = num_archived
                                    pop_1 = f"{pop_msg}: {pop_ex} / {pop_arc}"
                                    pop_2 = f"{pop_note}:\n{skipped_files}"
                                    sg.popup_ok(
                                        f"{pop_1}\n\n{pop_2}",
                                        title=_("Partial success")
                                    )

                            else:
                                err_str = _("Selected input not recognized as file(s)")
                                sg.popup_error(
                                    f"{err_str}: {output_file}", title=_("Error")
                                    )

                                show_decrypt = False
                                break

                            # Remove .aes file if so configured
                            if uinput_cleanup:
                                files_to_remove.append(uinput_file) # mark for deletion

                            # Quit to main after decryption
                            show_decrypt = False

                        else:
                            err_str = _("File not AES v2 format (pyAesCrypt).")
                            sg.popup_error(
                                err_str,
                                title=_("Error")
                                )
                            show_decrypt = False
                            break
                    else:
                        err_str = _("Selected input not recognized as file(s)")
                        sg.popup_error(
                            f"{err_str}: '{uinput_file}'.", title=_("Error")
                            )
                        show_decrypt = False
                        break

                    # Rest of decrypt stuff goes here

            # End decryption window
            Decrypt.close()

            # Re-open main window
            MainWindow.UnHide()

        elif Main_event == "-button_send-" and show_send is False:
            show_send = True
            MainWindow.Hide()
            Send = create_send_window()

            # Do send file loop
            while show_send:
                Send_event, Send_value = Send.read()
                print(f"Send_event  = {Send_event}\nSend_value  = {Send_value}")  # debug
                if Send_event == sg.WIN_CLOSED:
                    show_send = False

                if Send_event == "-send_cancel-":
                    show_send = False

                if Send_event == "-send_combo-": # dropdown event
                    # get site selected
                    sitename = Send_value["-send_combo-"]

                    # fetch relevant info
                    siteinfo = get_infostring_from_key(sitename)
                    site_sentence = siteinfo[0]
                    site_cap = siteinfo[1]
                    site_faq = siteinfo[2]
                    xfer_disabled = siteinfo[3]
                    site_url = ease.sites[sitename]["site-url"]

                    # update fields in-place
                    Send["-provider_url-"].update(f"URL: {site_url}")
                    Send["-provider_info-"].update(site_sentence)
                    Send["-provider_capinfo-"].update(site_cap)
                    Send["-provider_faq-"].update(site_faq)
                elif Send_event == "-visit_url-":
                    target_key = Send_value["-send_combo-"]
                    try:
                        target_url = ease.sites[target_key]["site_url"]
                    except Exception as e:
                        err_str = _("Error")
                        sg.popup_error(
                                       f"{err_str}: {e}",
                                       title=_("Error")
                                       )
                        show_send = False # quit to main

                    try:
                        webbrowser.open(target_url)
                    except Exception as e:
                        err_str = _("Error")
                        sg.popup_error(
                                       f"{err_str}: {e}",
                                       title=err_str
                                       )
                        show_send = False # quit to main

                elif Send_event == "-send_send-":
                    # TODO
                    pass

            # End Send window
            Send.close()

            # Re-open main window
            MainWindow.UnHide()

        elif Main_event == "-button_about-" and show_about is False:
            show_about = True
            About = create_about_window()

            while show_about:
                About_event, About_value = About.read()
#print(f"About_event  = {About_event}\nAbout_value  = {About_value}")  # debug

                if About_event == sg.WIN_CLOSED:
                    show_about = False

                if About_event == "-about_ok-":
                    show_about = False

                if About_event == "-github-":
                    try:
                        webbrowser.open(ease.git)
                    except Exception as e:
                        err_str = _("Error")
                        sg.popup_error(
                                       f"{err_str}: {e}",
                                       title=err_str
                                       )
                        show_about = False # quit to main

            About.close()


    # Remember to close window
    MainWindow.close()


# Runtime
if __name__ == "__main__":
    # Initiate settings object 'ease'
    #   default: ease = Settings() # default English
    #   norwegian: ease = Settings(language="no")
    ease = settings.Settings(language="en")

    # Configure selected langauge
    language = gettext.translation("base",
                                    localedir="locales",
                                    languages=ease.language)
    # Activate gettext translation
    language.install()
    _ = language.gettext

    # Run main entry
    main()
