#!/usr/bin/env python3
# coding=utf-8
# EaSE: Encrypt and Send with EaSE
# Simple utility for symmetric encryption of files or file archives
# prior to distribution over untrusted services (like e-mail).
#
# Copyright (C) 2020 Sigbjørn "sigg3" Smelror <git@sigg3.net>.
#
# EaSE is free software: you can redistribute it and/or modify it
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

import pyAesCrypt
import PySimpleGUIQt as sg
from pathlib import Path
from password_strength import PasswordStats
from typing import Tuple, Type
from threading import Thread
import datetime, time, zipfile, tarfile, copy, webbrowser

# Enable translation
import gettext
_ = gettext.gettext




# List of issues, todos and bugs (by priority)
# TODO sending
# Using selenium is not recommended at this stage, because we will need
# a separate geckodriver install (and probably break ToS).
# Using webbrowser instead, we can serve a number of convenient links
# for sharing file(s), and also a button to attach to e-mail message.

# TODO
# in pysimplegui june 2020, signalling windows from other threads was added.
# Look into whether this is a worthwhile change to ease.
# In the meantime, existing is_alive method in Thread objects is sufficient.
# cf. create_spinner() and run_in_the_background()

# TODO keyfiles
# while we want to keep things simple, it's only a matter of time before
# someone requests asymmetric encryption


def setup_transmitters() -> dict:
    """
    Returns dict of file transmission alternatives (for sending over WWW).
    Separated into its own function for maintenance reasons.
    Each entry must contain: URL, date (changed), file expire (in days),
    max file size (in GB), require login (bool), automatation enabled (bool),
    cap data string (what are service limitations).
    
    Automation disabled at the time of writing.
    Setting automated to True entails writing an linking to a function to
    deal with automating file upload (e.g. selenium script).
    """
    
    # setup return
    list_of_sites = {}
    
    # sendgb.com (added 2020-09-07)
    sitename = 'sendgb.com'
    list_of_sites[sitename] = {}
    list_of_sites[sitename]['changed'] = '2020-09-07'
    list_of_sites[sitename]['site_url'] = f'https://www.{sitename}'
    list_of_sites[sitename]['days_expire'] = 7
    list_of_sites[sitename]['max_size_gb'] = '5 GB'
    list_of_sites[sitename]['require_login'] = False
    list_of_sites[sitename]['automated'] = False
    list_of_sites[sitename]['limitations'] = 'files stored for 90 days.'
    list_of_sites[sitename]['faq'] = 'https://www.sendgb.com/en/faq.html'
    
    # sendgb.com (added 2020-09-07)
    sitename = 'fromsmash.com'
    list_of_sites[sitename] = {}
    list_of_sites[sitename]['changed'] = '2020-09-07'
    list_of_sites[sitename]['site_url'] = f'https://{sitename}'
    list_of_sites[sitename]['days_expire'] = 14
    list_of_sites[sitename]['max_size_gb'] = 'None'
    list_of_sites[sitename]['require_login'] = False
    list_of_sites[sitename]['automated'] = False
    list_of_sites[sitename]['limitations'] = "files 0-2 GB in size must queue."
    list_of_sites[sitename]['faq'] = 'https://faq.fromsmash.com/'
    
    # sendgb.com (added 2020-09-07)
    sitename = 'surgesend.com'
    list_of_sites[sitename] = {}
    list_of_sites[sitename]['changed'] = '2020-09-07'
    list_of_sites[sitename]['site_url'] = f'https://{sitename}'
    list_of_sites[sitename]['days_expire'] = 7
    list_of_sites[sitename]['max_size_gb'] = '3 GB'
    list_of_sites[sitename]['require_login'] = False
    list_of_sites[sitename]['automated'] = False
    list_of_sites[sitename]['limitations'] = "store up to 5GB per month"
    list_of_sites[sitename]['faq'] = "https://surgesend.com/help"
    
    # dropbox (added 2020-09-08)
    sitename = 'dropbox.com'
    list_of_sites[sitename] = {}
    list_of_sites[sitename]['changed'] = '2020-09-08'
    list_of_sites[sitename]['site_url'] = f'https://{sitename}'
    list_of_sites[sitename]['days_expire'] = 'N/A'
    list_of_sites[sitename]['max_size_gb'] = '2 GB'
    list_of_sites[sitename]['require_login'] = True
    list_of_sites[sitename]['automated'] = False
    list_of_sites[sitename]['limitations'] = "free account gives 2GB storage total"
    list_of_sites[sitename]['faq'] = "https://www.dropbox.com/basic"
    
    
    # return any hits
    return list_of_sites


def create_main_window() -> Type[sg.Window]:
    """
    Create (and re-create) main (or initial) window
    Return window object to allow for assignment to variable in main.
    """
    
    # Set icons
    icon_encrypt = ease['icon_encrypt']
    icon_decrypt = ease['icon_decrypt']
    icon_send = ease['icon_sendenc']
    icon_about = ease['icon_easehlp']
    
    
    # Set icon text
    caption_encrypt = _('Encrypt')
    caption_decrypt = _('Decrypt')
    caption_send    = f" {_('Send')}"   # space added for English
    caption_about   = f" {_('About')}"  # Qt justification :( # TODO
    
    
    # Set layout
    WelcomeLayout = [
                [sg.Text(f"{ease['title']}", font=('Sans serif', 16))],
                [sg.Text(' ')],
                [sg.Text(_("Encrypt a file or files securely so it's safe to distribute, or decrypt files you have received."))],
                [sg.Text(_("This utility uses AES256-CBC (pyAesCrypt) to encrypt/decrypt files in the AES Crypt file format v.2."))],
                [sg.Text(' ')],
                [sg.Button(
                    caption_encrypt,
                    image_data=icon_encrypt,
                    key='-button_encrypt-',
                    font=("Helvetica", 16)
                    ),
                 sg.Button(
                    caption_decrypt,
                    image_data=icon_decrypt,
                    key='-button_decrypt-',
                    font=("Helvetica", 16)
                    )
                ],
                [sg.Button(
                    caption_send,
                    image_data=icon_send,
                    key='-button_send-',
                    font=("Helvetica", 16)
                    ),
                 sg.Button(
                    caption_about,
                    image_data=icon_about,
                    key='-button_about-',
                    font=("Helvetica", 16)
                    )
                ],
                [sg.Text(' ')]
                ]
    
    # Window object
    Welcome = sg.Window(
                        ease['title'],
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
    Return window object to allow for assignment to "global" Window variable
    """
    
    # Set tables
    enc_opts = [
        [
        sg.CBox(_('Enable compression (smaller file size)'), default=False, key='compression')
        ],
        [
        sg.Radio('tarball', 'archive_radio', key='tar'),
        sg.Radio('zip', 'archive_radio', key='zip')
        ]
    ]
    
    enc_in = [
        [
        sg.InputText(key='enc_uinput_files', enable_events=True),
        sg.FilesBrowse(target='enc_uinput_files')
        ]
    ]
    
    enc_out = [
        [
        sg.InputText(ease['output_dir'], disabled=True, key='output_preview_str'),
        sg.FolderBrowse(target='output_preview_str')
        ]
    ]
        
    # Set layout
    EncryptLayout = [
        [sg.Text(f"{ease['title']}", font=('Sans serif', 16))],
        [sg.Text(' ')],
        [sg.Text(_("Securely encrypt file(s), so it is safe to distribute over untrusted service (like e-mail)."))],
        [sg.Text(_("If you select more than one file, they will be gathered in an encrypted archive."))],
        [sg.Text(_("If your recipient uses Windows, consider using zip instead of tar."))],
        [sg.T(' ')],
        [sg.Frame(layout=enc_in, title=_("Select input file(s):"))],
        [sg.Frame(layout=enc_out, title=_("Specify where to save the output"))],
        [sg.Frame(layout=enc_opts, title=_('Archiving options (for groups of files)'))],
        [sg.Frame(layout=[
            [sg.T(_("It is recommended to use a full sentence as the passphrase."))],
            [sg.In('', key='uinput_passphrase')],
            [sg.T(get_password_strength(''), key='uinput_ppstrength')]
            ],
            title=_("Passphrase")
            )
        ],
        [
        sg.Button(_('Encrypt'), key='-enc_encrypt-'),
        sg.Cancel(_("Cancel"), key='-enc_cancel-')
        ]
    ]
    
    Encrypt = sg.Window(
                        ease['title'],
                        layout=EncryptLayout,
                        resizable=True,
                        return_keyboard_events=True,
                        finalize=True
                        )
    return Encrypt




def create_dec_window() -> Type[sg.Window]:
    """
    Helper function to create (and re-create) decryption window
    Return window object to allow for assignment to "global" Window variable
    """
    
    # Set tables
    dec_in = [
        [
        sg.InputText(key='dec_uinput_file', enable_events=True),
        sg.FileBrowse(target='dec_uinput_file')
        ]
    ]
    
    dec_opts = [
        [sg.CBox(_('Automatically decompress decrypted archives'), default=True, key='uncompress')],
        [sg.CBox(_('Remove source .aes file after decryption'), default=False, key='removesrc')]
    ]
    
    dec_out = [
        [
        sg.InputText(ease['output_dir'], disabled=True, key='dec_output_preview_str'),
        sg.FolderBrowse(target='dec_output_preview_str')
        ]
    ]
    
    dec_pass = [
        [sg.In('', key='uinput_passphrase')]
    ]
    
    
    # Set layout
    DecryptLayout = [
        [sg.Text(f"{ease['title']}", font=('Sans serif', 16))],
        [sg.Text(' ')],
        [sg.Text(_("Decrypt any encrypted .aes file you have received."))],
        [sg.Text(_("If the decrypted file is a tarball or zip archive, it will be extracted."))],
        [sg.T(' ')],
        [sg.Frame(layout=dec_in, title=_("Select input file(s)"))],
        [sg.Frame(layout=dec_opts, title=_('Decryption options'))],
        [sg.Frame(layout=dec_out, title=_("Specify where to save the output"))],
        [sg.Frame(layout=dec_pass, title=_("Passphrase"))],
        [
        sg.Button(_('Decrypt'), key='-dec_decrypt-'),
        sg.Cancel(_("Cancel"), key='-dec_cancel-')
        ]
    ]

    Decrypt = sg.Window(
                        ease['title'],
                        layout=DecryptLayout,
                        resizable=True,
                        return_keyboard_events=False,
                        finalize=True
                        )
    return Decrypt


def create_send_window() -> Type[sg.Window]:
    """
    Helper function to create (and re-create) file send window.
    Return window object to allow assignment to "global" Window variable.
    """
    
    # Fetch latest transmitter info
    sites = ease['sites']
    
    # Set first item as default
    for sitename in sites.keys():
        site_sentence, site_cap, site_faq, xfer_disabled = get_infostring_from_key(sitename)
        break # we just need the first one for creation
    
    # File xfer site info table
    xfer_site = [
        [sg.T(f"URL: {sites[sitename]['site_url']}", key='-provider_url-')],
        [sg.T(site_faq, key='-provider_faq-')],
        [sg.T(site_sentence, key='-provider_info-')],
        [sg.T(site_cap, key='-provider_capinfo-')]
    ]
    
    # Window layout
    SendfileLayout = [
        [sg.Text(f"{ease['title']}", font=('Sans serif', 16))],
        [sg.Text(' ')],
        [sg.Text(_("Sometimes files are too big for attaching to e-mails."))],
        [sg.Text(_("Most of these online file transfer services do not require a login."))],
        [sg.Text(_("Select any provider to visit their website or attempt sending."))],
        [sg.Text(' ')],
        [
            sg.Text(_('Choose file transfer service: ')),
            sg.Combo(
                 list(sites.keys()),
                 default_value=sitename,
                 key='-send_combo-',
                 readonly=True,
                 enable_events=True)
        ],
        [sg.Frame(layout=xfer_site, title=' ')], # title is workaround
        [sg.Text(' ')],
        [
        sg.Button(_('Send'), key='-send_send-', disabled=xfer_disabled),
        sg.Button(_('Open URL'), key='-visit_url-'),
        sg.Button(_("Cancel"), key='-send_cancel-')
        ]
    ]
    
    # TODO REWRITE AS A DROP-DOWN THAT RE-DRAWS the frame below
    # Show 1 provider at the time
    # with buttons visit URL and send file below ..
    # TODO
    
    # for sitename in sites.keys():
        
        # site_sentence, xfer_disabled = get_infostring_from_key(sitename)    
        # if is_first_one:
            # # set as default / initial value
        
            # is_first_one = False
        # else:
            
        
        
    
    
    
    # # Populate window with frames containing sites
    # for sitename in sites.keys():
        
        # # build site info string
        # site_sentence = f"{_('Max file size')}: "
        # site_sentence += f"{sites[sitename]['max_size_gb']} GB, "
        # site_sentence += f"{_('Expires (days)')}: "
        # site_sentence += f"{sites[sitename]['days_expire']}, "
        # site_sentence += f"{_('Require log-in')}: "
        
        # if sites[sitename]['require_login']:
            # site_sentence += _('Yes')
        # else:
            # site_sentence += _('No')
        
        # # automation button disabled/enabled status
        # xfer_disabled = False if sites[sitename]['automated'] else True
        
# #        [sg.Button(
# #                    caption_encrypt,
# #                    image_data=icon_encrypt,
# #                    key='-button_encrypt-',
# #                    font=("Helvetica", 16)
# #                    ),
        
        
        # frame_construct = [
# #            [sg.T('URL:'), sg.In(sites[sitename]['site_url'], disabled=True), sg.Button(_('Open'), key='-visit_url-')],
            # [sg.T(f"URL: {sites[sitename]['site_url']}"), sg.Button(_('Open'), image_data=ease['icon_globe'], key='-visit_url-'), sg.Button('Send', image_data=ease['icon_trans'], disabled=xfer_disabled)],
            # [sg.T(site_sentence)]
            # # [
            # # sg.T(f"{_('Max file size')}:"),
            # # sg.T(f"{sites[sitename]['max_size_gb']} GB"),
            # # sg.T(f"{_('Expires (days)')}:"),
            # # sg.T(sites[sitename]['days_expire']),
            # # sg.T(f"{_('Require log-in')}:"),
            # # sg.T(require_login)]
        # ]
        
        # # append frame structure feat. table
        # SendfileLayout.append(
            # [sg.Frame(
                # layout=frame_construct,
                # title=f"{sitename} ({ease['str']['updated']}:{sites[sitename]['changed']})"
                # )
            # ],
            
        # )
        # SendfileLayout.append([sg.T(' ')],)
    
    # # Add Close/OK button at the bottom
    # SendfileLayout.append([sg.Button('Close', key='-send_cancel-')])
# #        [
# #        sg.OK 
# #        sg.Button(f"{_('Send')}", key='-send_send-'),
# #        sg.Cancel(ease['str']['cancel'], key='-send_cancel-')
# #        ]
# #    ]
    
    SendFile = sg.Window(
                         ease['title'],
                         layout=SendfileLayout,
                         resizable=True,
                         return_keyboard_events=False,
                         finalize=True
                         )
    
    return SendFile
    

def create_about_window() -> Type[sg.Window]:
    """
    Helper function to create (and re-create) an about window.
    Returns a window object to allow assignment to var in global scope.
    """
    # Window layout
    AboutLayout = [
        [sg.Text(f"{ease['title']}", font=('Sans serif', 16))],
        [sg.Text(' ')],
        [sg.Text("EASE is written by Sigbjørn Smelror (c) 2020, GNU GPL v.3+, to provide")],
        [sg.Text("a hopefully user-friendly graphical interface to the pyAesCrypt module.")],
        [sg.Text("It is distributed in the hope that it will be useful, but without any warranty.")],
        [sg.Text("See the GNU General Public License for more details.")],
        [sg.Text(f"{_('Submit issues and new translations at')}: {ease['git']}")],
        [sg.Text(' ')],
        [sg.Text("Usage should be fairly straight-forward: Encrypt -> Send -> Decrypt")],
        [sg.Text(' ')],
        [sg.Text(_('Encrypting'), font=('Sans serif', 12))],
        [sg.Text("The sender clicks the Encrypt button, selects the file(s) to encrypt,")],
        [sg.Text("and encrypts them using a passphrase (password) of his or her choosing.")],
        [sg.Text("It is recommended to use a full sentence as the passphrase.")],
        [sg.Text("This produces an encrypted AES Crypt v.2 file that has an .aes suffix.")],
        [sg.Text(' ')],
        [sg.Text(_('Sending'), font=('Sans serif', 12))],
        [sg.Text("The encrypted .aes file can be distributed over untrusted services like")],
        [sg.Text("e-mail or any of the file transfer services available when clicking Send.")],
        [sg.Text("Some services will provide a download link (URL) the recipient can use.")],
        [sg.Text("Remember: never send an encrypted file and its passphrase together!")],
        [sg.Text(' ')],
        [sg.Text(_('Decrypting'), font=('Sans serif', 12))],
        [sg.Text("Having received the encrypted .aes file through e-mail or a service (above),")],
        [sg.Text("the recipient simply clicks the Decrypt button, selects the (.aes) file and")],
        [sg.Text("enters the passphrase (password) provided separately by the sender.")],
        [sg.Text("And that's it!")],
        [sg.Text(' ')],
        [sg.Text("EASE Crypto relies on pyAesCrypt, password_strength and zxcvbn-python")],
        [sg.Text("Graphical interface is provided by PySimpleGUIQt, translations use gettext.")],
        [sg.Text("EASE is not affiliated with any of the file transfer services mentioned, and")],
        [sg.Text("please submit an issue if any of the services are terminated or changed.")],
        [sg.Text(' ')],
        [sg.Button(_('Homepage'), key='-github-'), sg.Button('OK', key='-about_ok-')]
    ]
    
    
    
    About = sg.Window(
                      ease['title'],
                      layout=AboutLayout,
                      resizable=False,
                      return_keyboard_events=False,
                      finalize=False
                      )
    
    return About


def get_infostring_from_key(key: str) -> Tuple[str, str, str, bool]:
    """
    Simple way to build string from sites[] dict in setup_transmitters()
    Returns a tuple: f-string of general site info, and a bool
    """
    
    sites = ease['sites']

    # automated "send" action button disabled/enabled status
    xfer_disabled = False if sites[key]['automated'] else True
    
    # build site info string
    site_sentence = _('Max file size')
    site_sentence += f": {sites[key]['max_size_gb']}, "
    site_sentence += _('Expires (days)')
    site_sentence += f": {sites[key]['days_expire']}, "
            
    # finish info string
    site_sentence += _('Require log-in')
    site_sentence += ': '
    if sites[key]['require_login']:
        site_sentence += _('Yes')
        xfer_disabled = True # override (avoids this whole bag of bugs)
    else:
        site_sentence += _('No')
    
    # get site cap (limitations) info
    limitations = _('Limitations')
    site_cap = sites[key]['limitations']
    if site_cap is None:
        site_cap = f"{limitations}: N/A"
    else:
        site_cap = f"{limitations}: {site_cap}"
    
    # get faq (URL)
    site_faq = _('FAQ')
    site_faq += ': '
    site_faq += sites[key]['faq']
     
    return site_sentence, site_cap, site_faq, xfer_disabled
    
    
    

def get_folder_from_infiles(input_files: str) -> str:
    """
    Return string of path object's parent if indeed the input is a valid path
    Else return safe default from settings.
    """
    try:
        if Path.is_file(Path(input_files)):
            return str(Path(input_files).parent) 
        elif Path.is_file(Path(input_files.split(sep=";")[0])):
            return str(Path(input_files.split(sep=";")[0]).parent) 
        else:
            return ease['output_dir']
    except:
        return ease['output_dir']


def get_unique_middlefix() -> int:
    """
    Returns a "unique" middle name for use in non-unique filenames
    usage: my_var = f"{my_file.stem}-{get_unique_suffix()}{my_file.suffix}"
    Requires that my_file is path object and, of course, datetime.
    """
    return int(datetime.datetime.timestamp(datetime.datetime.now()))


def get_password_strength(uinput_passphrase: str) -> str:
    """
    We are not evaluating password policies, just providing visual feedback
    Call using get_password_strength(Encrypt_value['uinput_passphrase'])
    """
    # string wrangling
    str_entr = _("Passphrase entropy bits")
    str_comp = _("complexity")
    
    if uinput_passphrase is None or uinput_passphrase == '':
        return f"{str_entr}: 0.0, {str_comp}: 0.00"

    stats = PasswordStats(uinput_passphrase)
    
    return f"{str_entr}: {stats.entropy_bits:0.1f}, {str_comp}: {stats.strength():0.2f}"


def archive(file_basename: str, use_tar: bool, use_compression: bool, input_files: list) -> Tuple[list, str]:
    """
    Write tar or zip file, depending on use_tar bool, containing items in
    input_files list with optional (medium) compression. This function handles
    filename too, given a basename. Returns tuple with a list of file(s)
    successfully archived and the final filename we wrote to.
    Requires tarfile, zipfile, zlib, Path (pathlib)
    """
    # Setup return vals
    return_list = []
    archive_filename = ''
    
    # configure parameters for archiving procedure
    if use_tar:
        archivist = tarfile.open
        if use_compression:
            ftype="tar.gz"
            compression = 'w:gz'
        else:
            ftype="tar"
            compression = 'w'
        use_mode = compression
        
    else:
        archivist = zipfile.ZipFile
        ftype="zip"
        if use_compression:
            try:
                import zlib
                compression = zipfile.ZIP_DEFLATED
            except (ImportError, AttributeError):
                compression = zipfile.ZIP_STORED
            except Exception as e:
                print(f"Unhandled exception in archive(): {e}") # debug
        use_mode = 'w'
    
    
    # Set output file (make unique if necessary)
    archive_filename = f"{file_basename}.{ftype}"
    if Path.is_file(Path(archive_filename)):
        archive_filename = f"{file_basename}-{get_unique_middlefix()}.{ftype}"
    
    # archive input files into archive_file using procedure set
    with archivist(archive_filename, mode=use_mode) as new_archive:
        for file_to_archive in input_files:
            try:
                if use_tar:
                    new_archive.add(file_to_archive, arcname=str(Path(file_to_archive).stem)) # using arcname=stem here did not work..
                else:
                    new_archive.write(file_to_archive, compress_type=compression)
                return_list.append(file_to_archive)
            except:
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
        use_mode = 'r:*'
    elif zipfile.is_zipfile(archive_filename):
        archivist = zipfile.ZipFile
        is_tar = False
        use_mode = 'r'
    else:
        raise TypeError(f"Input file {archive_filename} not recognized as tar or zip file.") # TODO
        return extracted, skipped
    
    with archivist(archive_filename, use_mode) as input_archive:
        # get content list
        archive_contents = input_archive.getnames() if is_tar else input_archive.namelist()

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
    Returns window object. Used once if user do not click X to close.
    """
    
    # Make strings available to gettext :P
    be_patient = _('This might take a while.')
    el_time = _('Elapsed time')
    secs = _('seconds')
    
    # create spinner
    spinner_layout = [[ sg.T(f"{show_text}.. {be_patient}.\n{el_time}: {show_time} {secs}", key='-spinner_text-') ]]
    return sg.Window(f"{show_text} ..", layout=spinner_layout, grab_anywhere=True, keep_on_top=True, finalize=True)


def unarchive_worker(archive_filename: str, output_dir: str, out_dict: dict, out_index: str):
    """
    Helper function to run unarchive() in a separate thread using Thread.
    Will save return values from archive into out_dict <dict> index <index>
    """
    
    try:
        extracted_files, skipped_files = unarchive(archive_filename, output_dir)
    except TypeError:
        # not an error, we will not unarchive it
        number_of_extracted_items, number_of_archived_items = [], []
    except Exception as e:
        number_of_extracted_items = 'error'
        number_of_archived_items = e
    
    out_dict[out_index] = extracted_files, skipped_files    
    
    


def archive_worker(file_basename: str, use_tar: bool, use_compression: bool, input_files: list, out_dict: dict, out_index: str):
    """
    Helper function to run archive() in a separate thread using Thread.
    Will save return values from archive into out_dict <dict> index <index>
    """
    out_dict[out_index] = archive(file_basename, use_tar, use_compression, input_files)


def aescrypt_worker(encrypt: bool, input_f: str, output_f: str, user_passphrase: str, out_dict: dict, out_index: str):
    """
    Helper function to execute encryp/decryption (depending on encrypt bool)
    in a separate thread. Returns status message to out_dict['out_index']
    """
    
    buffer_size = ease['buffer']
    
    
    if encrypt:
        string_action= _('Encryption')
        aes_exec = pyAesCrypt.encryptFile
        
    else:
        string_action= _('Decryption') # not sure this is in use .. ? TODO
        aes_exec = pyAesCrypt.decryptFile
    
    try:
        aes_exec(input_f, output_f, user_passphrase, buffer_size)
        out_dict[out_index] = (0, None)
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
    
    N return value because the thread saves to global ease['thread'].
    """
    
    output_dict = ease
    output_index = 'thread'
    daemonize = True
    number_of_args = 4 # + output_dict, output_index     
    
    if worker_to_run == 'archive':
        worker_func = archive_worker
        show_text = _('Archiving')        
    elif worker_to_run == 'unarchive':
        worker_func = unarchive_worker
        show_text = _('Extracting')
        number_of_args = 2 # only has 2 args + output_dict and output_index
    else:
        worker_func = aescrypt_worker
        show_text = _('Encrypting') if worker_to_run == 'encrypt' else _('Decrypting')
    
    
    # (re)set ease dict index 'thread' to store output values from separate thread
    ease['thread'] = None
    
    # Create helper thread for executing archiving (might be big file)
    if number_of_args == 4:
        input_arguments = (worker_args[0], worker_args[1], worker_args[2], worker_args[3], output_dict, output_index)
       #  worker = Thread(target=archive_worker, args=(uinput_basename, use_tar, use_compression, uinput_files, ease, 'thread'), daemon=True)
    elif number_of_args == 2:
        input_arguments = (worker_args[0], worker_args[1], output_dict, output_index)
#        worker = Thread(target=worker_func, args=(worker_args[0], worker_args[1], output_dict, output_index), daemon=daemonize)
    
    # Debugging info
    #print(f"Executing thread target={worker_func}") # with args={input_arguments}")
    
    # Create threading.Thread object
    worker = Thread(target=worker_func, args=input_arguments, daemon=daemonize)
    
    # Create popup_window working dot dot dot...
    spinner = create_spinner(show_text, 0.2) # 0.2 headstart
    
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
            spinner_e = ''
            spinner_v = ''
            spinner.close()
            time.sleep(0.1)
            elapsed_time = f"{time.time() - start_time:0.1f}"
            spinner = create_spinner(show_text, elapsed_time)
        
        if spinner_e == '__TIMEOUT__':
            # Make strings available to gettext :P
            be_patient = _('This might take a while.')
            el_time = _('Elapsed time')
            secs = _('seconds')
            elapsed_time = f"{time.time() - start_time:0.1f}"
            
            spinner['-spinner_text-'].update(f"{show_text}.. {be_patient}.\n{el_time}: {elapsed_time} {secs}")
    
    
    # join threads
    # (not sure if this is required? TO CHECK) TODO
    worker.join()
    
    # close GUI window
    spinner.close()




# Runtime
if __name__ == '__main__':
    # initiate ease settings dict with sane defaults
    ease = {}
    ease['name'] = 'EASE' # The name of the game
    ease['title'] = f"{ease['name']}: Encrypt And Send with {ease['name']}"
    ease['git'] = "https://github.com/sigg3/ease"
    ease['buffer'] = 64 * 1024
    ease['password'] = None # Not in use
    ease['input'] = None    # Not in use
    ease['output'] = None   # Not in use
    ease['language'] = 'English' # Not in use
    ease['archive'] = False
    ease['use_tar'] = True
    ease['compression'] = False # use store
    
    # Set "home" dir (our default)
    if Path.home().is_dir():
        ease['home_dir'] = Path.home()
    else:
        ease['home_dir'] = Path.cwd()
    
    # Set current output dir to default
    ease['output_dir'] = ease['home_dir']
    
    # PySimpleGUIQt color theme
    sg.ChangeLookAndFeel('SystemDefaultForReal')
    
    # Icons8 icon file (MIT) Copyright (C) The author(s) 
    ease['icon_decrypt'] = b'iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAB\
                             HNCSVQICAgIfAhkiAAAAAlwSFlzAAAOxAAADsQBlSsOGwAAAB\
                             l0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAJ\
                             zSURBVGiB7ZjPahNRFIe/M23FIqigIFSrG0EjutCd6E43voAL\
                             wWTQPIC7FHURV40IXQpW2yRSH8AX6Er6Aq3WCi4sVlyIGEQQb\
                             ea4aNQoycy5M7dJF/Ntsri/8+eXm3tmbiAnJxOSJVifcIxRTq\
                             OcAU4iTACHgYPAGLCvI20BP4FPwAawgbKGsMwmK1Lm3cAMaJP\
                             LKLeAi10NZqUFvCBiRm6w6BLoZECbTKNUXONcSgA1CbltDTA3\
                             onVChHqqtlwRQinRtEgDi0gVQbiTrSsHlLuqti/XJNKnFIh4F\
                             SN5hrKIsAZ8ZIzPtPkhRb514vcwwi4iDtDmEMoJAi6hXOubMe\
                             CUFFn1Y6BJGeVx3yRhujOhDTRmuSwhc0k5TD8h4LxR5xNTTZs\
                             BpRC7vMARU57umHkmYwUSX/M31h04Gru6yWxiQ13oPJMEzMaL\
                             Emp2GDXW3J+wfoWAdW0Ys/mpCdh3YHeGRtIybhFZDXzP0EhaT\
                             DWtBr5kaCQtXy0iq4H1DI2kQ21vqDYDkvxE9E7AG5vMgrKUqZ\
                             k0RLaaNgPBEAwYa9oMXOc18DZLP468Z5yXFqHJgAgKTGdqyY2\
                             aXKVtEVqnEBIyh/AAYt8gfTBLiYdWsfuduMEF4CZbd+LjaXL0\
                             oAUsITySEs9dArP9K7HAXiLOEnEOmHEKFqaIWGaEFSmmf854u\
                             5z3upysftj6LEz0KJzyEvQ/5jOwU8kNpEKo+ko1eANCVUrc85\
                             Vu8AYi20XFyjB2oKJ1ar7SDesMVHylyqdQKvIp9Jd8CjmTT6\
                             F/yafQH4QpB23VV1lvBqTEfZOJnTyFEk14bh624Qz0NbENzef\
                             keOAXZUqTVtznmewAAAAASUVORK5CYII='
    
    # Icons8 icon file (MIT) Copyright (C) The author(s) 
    ease['icon_encrypt'] = b'iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAB\
                             HNCSVQICAgIfAhkiAAAAAlwSFlzAAAOxAAADsQBlSsOGwAAAB\
                             l0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAK\
                             NSURBVGiB7Zi/a1NRFMc/9/ZVA43kkW62LoVOgiJPUQeHB4EO\
                             ounm2P+horZbp4IIOthFXHURBwtujX35B6IU1MEKhWLApSWpd\
                             qg19zg0wTSEvJf3I7H4PlPu5Zx7vt+8c96FBykp/zcqzsMcxx\
                             m1bbtojJlVSjnAOUCAbyJS0Vq/qdVqq5VK5TCumrEZcF23qJR\
                             6BEz7hG6KyD3P81bjqDsS9YClpSWttV5WSq0A4wFSxpVSd6am\
                             pk7Pzc155XJZotSPbEBrvQws9JmmgBvb29untra23kWqHyXZd\
                             d0i8KBj+wB4KiLXLMvKWpaVNcZcB1aAX+2BIrLguu7tKBpCz4\
                             DjOKO5XO4Tx3u+KiI3Pc/b6JZTKBQuGWPeAmfbtjfr9fr5sIM\
                             d+gnYtl3kuPiDXuIBSqXSB+AWx5/EdPOsUIQ2YIyZbV8rpZ71\
                             Et9ifX39vYg8b98TkcEbUEpd7hDxMmiuiLzo2LoSVkeUIZ5oX\
                             xhjPveR+7HXWf0QxUC2fVEul38GTewSm+0aGIBIr9F/gdTAsA\
                             l0kclDJn+P8ASYAc4kK4kfwFrDsJC5z6ZfsK+BpvgNIB+Huj7\
                             YtTQX1DzVXkG+LdT85wctHiB/aHjsFxRkBmZiEBMKFaB2EANJ\
                             93wvcn4BJ/4tlBoYNqmBYWMlcagA1Rrs7B/dlPkxmLBj/gjVJ\
                             BED1Rp83/u7bv2etOOvlUgL7ewH24uDRAx0a5Uk2gcSMpAfC7\
                             YXB4nMwESz13ebbdMa4iRIxIDiaGCTGNpOTvw9kBoYNqmBYRP\
                             EwJ5/SGLU/QKCGCjFICQsa34BvgYaikVgJxY5/bHb0Cz6Bfka\
                             yNzli6W5KPCKwbTTHvC6obmamefrAOqlpJxo/gB9k7aRwlhAg\
                             wAAAABJRU5ErkJggg=='

    # Icons8 icon file (MIT) Copyright (C) The author(s) 
    ease['icon_sendenc'] = b'iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAB\
                           HNCSVQICAgIfAhkiAAAAAlwSFlzAAAOxAAADsQBlSsOGwAAABl0\
                           RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAPCSUR\
                           BVGiB7ZhtaFtlFMd/z81LbaYZ7CUz6QzVabtZZju6UVb30oo6lI\
                           E6kIEw6AcHm3WgHwTnh4E4QSx0qAzpt8HQwVDRL1q26Wjt3Fbas\
                           jKtbeek617SJa3SG5YtL72PH9LEJrkzyU1sU7i/T/ee57n/c849\
                           51y4D5iYmJiYmCxixNF3+uU8+QoiOW0Ryrv72jZcKZaoUiyhHHg\
                           Iwa4Y8sLnb1+qKJaoSDcc2t1dUEVWeZfk4vVk68f1uwvxk2A+K/\
                           Avkh3FkrKmG3J6g4WztFhC1nkc4hRkV9mLQAewOsvWMTT2i+Zwp\
                           97iwrRQnFyCB6hE4Wv5s61Wb7HgITbacm/sbExeH/jmBUYCKzL2\
                           2CwzvLXtAs9V/QkwRtS+UTwbnJq7ZyErkEQveIDojIUjXZsZvLU\
                           KoBJr5JiUqTEv1BDnTExT+OBUE5/u+h6PM7iTbvt7EDmcWF+wIc\
                           4HNWznUGczn7zcyRJ75H15tqwvMdQl0UK5MP73Uj48sxVNCgVFf\
                           CG7HngUDAxxsVps7hA/37En5+derfuNvQ0DAJewhRsXTQUSfHt5\
                           beKyjmjZRyUxxNWuSUb8+l+idKIzlrm3r5fEEH/2yg8p9zOawvH\
                           +9Xw58FS2Rx0l2UIWRaNl0yAtmwaxKFrK2jrXZMp91iH+v1pq7h\
                           AXQklWIB9KYogLYdFXYNEnkNFCuXBdHWYocJGpuz4Alpe7qVm5m\
                           dXOqoID6h51caK3kmFf/KdtnXua1xrG2PKEX3e/XgIq4Lyfg4GJ\
                           H/nVfy7FdvvONW7fucZ61xY2PPyM4eCPnq3i+PnHUv2NL2NgfBk\
                           tjVfZ15RxGjOd2UKSM/dzcF0dTgZvs9nweL14vF6s1vh7uOzv4Y\
                           Zq7Mine9SVDF5P+9gva+i54kqP9XRGAlKzHASm0u0AQ4GLSQf1j\
                           duorqmluqaWjU9vTzoamjxvKIETvZVZtRN74oi/kBzMSODN9rpR\
                           JWapRXCSeDslmboX73mXu4JyhyNpL3c4cHk88T2hW4YSGJ5wZtX\
                           +3ecEUJF8hSYbRHP4D90h3n+k7iaQcfDUsOOlIPCgRMt4Rs6aol\
                           pEbW2rz3ps0tqWrm3Nqh2KWFWxPZyine9ntA8g4PNxNxRKGu+FQ\
                           gQmZt+8EH15ahaknddnVEjapaApGo3Sd64Llzt+xOn33SQWiwEg\
                           pdZuJHqj2pZ0w39x4+rI6COPr7UDWzVNI6hOE1Sn0bTZGktxuPf\
                           Udx1GEjCqnVcCs45+qljzZL8Q0g2sBCII0SORB4wGPx/aJiYmJi\
                           a6/AORnX+gBEwubAAAAABJRU5ErkJggg=='
    
    # Icons8 icon file (MIT) Copyright (C) The author(s) 
    ease['icon_easehlp'] = b'iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAB\
                           HNCSVQICAgIfAhkiAAAAAlwSFlzAAAOxAAADsQBlSsOGwAAABl0\
                           RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAGpSUR\
                           BVGiB7ZY9SwNBEIbfTS5GvLNQm4CiEFJpQLTTwo9eW5uonYYg/o\
                           FUscgfCEhAS7WxFfukSRcsJK34AcbCSi8haC5jJyh78YiZ3C3sU\
                           84sO+/DLncLaDQajZ+Ibs1EgaKOYe8DIgUgCZA5oFgNgG4hcDEy\
                           YZ3UtsSH60q3xlSxORkh5xrAPEtG79y0ndDG06H5LGuGZMVEgaI\
                           BCQ8ACxGjczV3SUOyplSgHbHTCEZ4AAARFpuv9p6sJxUQJFK8kX\
                           piW1aUCgA0y5mkR5KyoosALMYgvSLN5Cbwb9ZnDFR2TVR2TKxNh\
                           7nG8AnkV6KImQIxSyC/Osw1hk9gULAJZMstvNiEuk3IlltcY2Bw\
                           bVx6dLB81uDa/ht9hfyG7QrdZX5+tuNFm2WO8iegBfxGC/iNFvA\
                           bLeA3yguwPSW4ng6/Uf4EtMAAeZMV1REg1GRlZQQEcC6rqyJQHT\
                           OsU1lDBYFqJxzarKbFp6wZVAGbgIogHIyHraWHtFl3W+j5R0YCu\
                           fvM6FF/8vUPTycQ1PCAB4Eghwf+EAh6eKCLgArhXYkfv+f8zqBR\
                           hS9jd2TmUiJFJAAAAABJRU5ErkJggg=='
    
    # Smaller button (also Icons8, MIT). Currently not in use
    ease['icon_globe'] = b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHN\
                         CSVQICAgIfAhkiAAAAAlwSFlzAAAHYgAAB2IBOHqZ2wAAABl0RVh0\
                         U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAQ+SURBVEiJt\
                         ZVbbFRFGMd/M+fsObttactC3S0WBGyRO0EMhAQDlYsoEdRUI0Z80G\
                         h86YNcTNCXvhgDJkQl8UEe8EGjiVwUAgiUKqCEIHIpl2JLsY1N24W\
                         ml6XbPXv2nDM+tD3udkvSmPB/mvlm5v+b831zZuAhS4xp1tba+Zpk\
                         nhJEAIQi5gpVz47V1/4/oOZwnm6ZW3ThVtueUQJgSluZAYuEXYCrp\
                         DD09F3H0XY7IWsXNS8MjB2wrW65EUgfcFw9nBleW36MJ6OX8JQklo\
                         hwoKGKvlQhuuZ0267+EjtWnhlpJUcGAttPbdI0t055MhzNjxHJj4F\
                         QANTeWT24SHgUmnEG0nkAOK4e1lF1ge2nNo3000fu3FPu1wsjV+SK\
                         qb8S1JMA3O4u54eGVzE1GwDbM/jprxdJezq6TPPyzIPcGyjRTres2\
                         Mu22hY+XXU29wtqDucZgfSBinCTXPv4zwT1JPWxBey59A6diShBPU\
                         VIH6A3Vcw3V9+kpXcqAM9MraM83MTSsnNMG39bM3TnIO+fC+UAdMv\
                         cIvCK11UcAaFIpPM43rwWxzPouB/FSgfpsibw1Z/v0pmI+Pvy0Pz2\
                         hicOY2h2sWEmNucChFv9VOlFGRpKi1IaC6KXeWvhHl6ZvY+lk38HJ\
                         XC8gG+YHxhgSlGL3w/qSRZP+kOT0q3OBmytnW97RklFuMmfXGDcZ8\
                         30E37eh8GZem3Od0TzY1mx2SXXsd1AhA9/mQtDRdY0OVcKV5UWdGQ\
                         dW8/TaOyu4EbXHBq7ZmYZLZv8G5GCzhxocbCPoGa5KS84z4XrOoAS\
                         XmlxsEdp0s0C/Ni4gVtds3JMEIp5j9TnxoeUbySEZZmTIKMGvVax7\
                         LWKSLkGhxrX09r3GHd6po9qMCPcyPhQzwMBUnigUD5AINpdpbH/Vh\
                         U9ycGf90TzGmzXHNVg2ZSzo8aHlXRCnoB2H+AKdRUg1h/l+xsbCQW\
                         SlBZ0MnNiAzMmNGLqqSwDx9NzTIfVZxXRb+frrqR+cPNDCn10rD3l\
                         GKXD/VXTTrL40QsAtMXL+Pb6G7ie5qegKNhH2bh/WFd+FCldH3C6d\
                         TkXOxZ3JD9+LrsGaU/7LHMn9+1Cv11W2MZ7i77k6SmDd5mnJD3J8V\
                         y7O5+/e/+rUywR4UL7Ei/Tywc4ZuALQ7PvDfebe8oHqzSkIjPOgui\
                         VnJQ0dZcDYDkh9t+sQii6nH7n8xwANZWW5QTXS+E5AF0DE2jtnZZl\
                         dvPunBzA7e4KUq7BvoYq4nahY7nmBnY/7xct+7reWXleIl8fhrTFy\
                         /yhM63LqWtZmQOI2+PYe/lt2uJljhT6RnZWns8cH/3B2V63JIh9SA\
                         k1cVHpJVlk9nG8+dlRpwIYmhOzHH09O1deGDn24Cez+qipFwSqA9L\
                         ZnHm6MmXqdkfa03c5/endmWkZGyBTH5ycpQltof/oozpdIS/zSeWt\
                         Ma1/mPoXMhSlLR8VmrIAAAAASUVORK5CYII='

    # Smaller button (also Icons8, MIT). Currently not in use
    ease['icon_trans'] = b'iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAABHN\
                         CSVQICAgIfAhkiAAAAAlwSFlzAAAHYgAAB2IBOHqZ2wAAABl0RVh0\
                         U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAJrSURBVEiJ7\
                         ZPfS1NhGMc/75mejVJXdBFGWWkGmkY0ZbD8gTDKyAu7MPsHXKDhRV\
                         DdhRddmBYoIhFFRXijXgQhdKEUiporFkFqgknG0row2nTkznTn7WJ\
                         uOnUb7qYbv3A4D8/zfb/f5znPeWEX/xui85arCUBIcW49y0C8Q1Jn\
                         IaildzV25GqJDFLCwZJXs2/I2zcT08zqhrbAYPRWAjWJDEQ4uOd4J\
                         +MRowwACYHrrRZjIoOUzpuuuMJxOlPloDoCwhZdkU70gF1U4FvjhX\
                         Cndmhbo4NZe2Oa1FfZePk5j4ejRQAYFJ3GEicX82a6Rbn/amiCtSW\
                         T1Bzg01IjcVBX6Bi2kpnhq5VDv8ZEmdamRIjeQNSTLFZ1hbv95cx7\
                         0u/LQVOZ0tBiaWposTQlK5hu2trMoqby5utxA8hnSS85jOqCKaoLp\
                         pBS0OUqpOvjaaQUpBkDANlblhxvqZtRX2VLyIlctJ0I7wQpsQqBoJ\
                         9ZzyQAx/adQjXEv1Of3Pv5Mm8m75CXM0f+bGcgf4A4HBbvm37MqsE\
                         PwMTCMJdOXItp0v3hKG0D+aRlmPEterlhn6Sm+DuAO/KbCl1xAG6A\
                         b55xVg1+rKUVWEsrWBEas56JmN2/GM3hZH4hRbZScvMLeD6aA+BGx\
                         xGZoP7B2ddAFoD1fLXDtMf0KOQcqjvn+uran9Y92Sjc0Bp6Wy+o8w\
                         eQmeH8b586J8q1rE2faB1agB6Uv7edQ2+zAZb9yzPBoNobawIhaJ6\
                         eHG//6XbjW/JKKWRzpBbrkMVeY041aFcAVoLGHtdArzcWF8BaeblE\
                         6nqxIuX7sf5XI/G4u4jCP1lX4BBIAojvAAAAAElFTkSuQmCC'
    
    
    
    # GUI toggles
    show_encrypt = False
    show_decrypt = False
    show_send = False
    show_about = False
    
    # Listed files will be removed (unlinked) in event loop
    # These are typically temporary files: e.g. when sending >1 file we
    # create an archive and encrypt that. The unencrypted archive is garbage.
    files_to_remove = []
    
    # Create main window
    Main = create_main_window()
    
    
    # Master loop
    while True:
        
        # Clean up temporary/hanging files
        if files_to_remove:
            for xfile in files_to_remove:
                try:
                    # use unlink since we already use Path
                    Path(xfile).unlink(missing_ok=True)
                    print(f"removed {xfile}") # debug
                except Exception as e:
                    err_str = _('Error removing file')
                    sg.popup_error(
                                   f"{err_str} {xfile}.\n{e}",
                                   title=_('Error')
                                   )
            files_to_remove.clear()
        
        
        # Read events and values from Main
        Main_event, Main_value = Main.read()
        
        print(f"Main_event  = {Main_event}\nMain_value  = {Main_value}")  # debug
        
        # This must be separate from arg parsing below (bugfix)
        if Main_event == sg.WIN_CLOSED: break
        
        # Deal with options separately (weird bug with pysimplegui)
        if Main_event == '-button_encrypt-' and show_encrypt is False:
            show_encrypt = True
            Main.Hide() # "closes" main window
            Encrypt = create_enc_window()
            while show_encrypt:
                Encrypt_event, Encrypt_value = Encrypt.read()
                print(f"Encrypt_event  = {Encrypt_event}\nEncrypt_value  = {Encrypt_value}")  # debug
                
                if Encrypt_event == sg.WIN_CLOSED:
                    show_encrypt = False
                
                if Encrypt_event == '-enc_cancel-':
                    show_encrypt = False
                elif Encrypt_event == 'enc_uinput_files':
                    # Update output folder to match parent dir of files selectes as input (quality of life + 1)
                    Encrypt['output_preview_str'].update(get_folder_from_infiles(Encrypt_value['enc_uinput_files']))                    
                elif Encrypt_event == '-enc_encrypt-':
                    
                    # Read input
                    uinput_file = Encrypt_value['enc_uinput_files'] # was Encrypt_value[0], but should use unique keys
                    uinput_folder = Encrypt_value['output_preview_str']
                    uinput_passphrase = Encrypt_value['uinput_passphrase']
                    
                    # Read archiving options
                    # Note: will always force archiving for groups of files
                    use_tar = ease['use_tar']         # default (True)
                    archive_files = ease['archive']   # default (False)
                    use_compression = ease['compression'] # default (False)
                    if Encrypt_value['tar']:
                        use_tar = True
                        archive_files = True
                    elif Encrypt_value['zip']:
                        use_tar = False
                        archive_files = True
                    
                    if Encrypt_value['compression']:
                        use_compression = True
                    
                    
                    if Path.is_dir(Path(uinput_folder)):
                        proceed_with_encryption = False # fallback: expect failure
                        
                        if Path.is_file(Path(uinput_file)):
                            # create output name from input file
                            uinput_basename = f"{uinput_file.replace(' ', '_')}" # extension determined by archive() and pyAesCrypt
                            uinput_files = [ uinput_file ] # list of 1
                            # value = {0: '/home/sigg3/python/encyrpt_and_send/Icons8_flat_key.png', 'Browse': None, 'output_preview_str': '/home/sigg3/python/snek', 'Browse0': None, 'compression': True, 'tar': True, 'zip': False, 'uinput_passphrase': 'l'}
                        elif ";" in uinput_file:
                            # create output name from ISO 8601 date
                            uinput_basename = f"ease_{datetime.datetime.now().isoformat().split(sep='T')[0]}"
                            
                            # populate input_files list for archiving
                            uinput_files = uinput_file.split(sep=";") # list of files that we need to tarball/zip
                            
                            # turn on tarballing/archiving
                            archive_files = True
                           
                        else:
                            err_str = _('Selected input is not recognized as file(s)')
                            sg.popup_error(f"{err_str}:\n'{uinput_file}'", title=_('Error'))
                            show_encrypt = False
                        
                        
                        # Check password length within third-party libs parameters
                        # Note: EASE is not designed to enforce password policies.
                        if len(uinput_passphrase) < 6:
                            err_str = _('Error: password too short')
                            sg.popup_error(err_str, title=_('Error'))
                            show_encrypt = False
                        elif len(uinput_passphrase) > 1024:
                            err_str = _('Error: password too long')
                            sg.popup_error(err_str, title=_('Error'))
                            show_encrypt = False
                        
                        
                        # Archive files (if desired or > 1)
                        if archive_files:
                            number_of_inputs = len(uinput_files)
                            
                            # Run archiving in the background (threading)
                            # while showing a "Working ..." pop-up
                            # Output saved in ease['thread']
                            
                            target_location = Path(uinput_folder)
                            archive_target_location = Path(uinput_folder) / Path(uinput_basename).stem
                            run_in_the_background('archive', [str(archive_target_location), use_tar, use_compression, uinput_files])
                            
                            #print(f"got actual_output candidate as {ease['thread'][1]}")
                            
                            # save outputs here (ease['thread'] is re-usable)
                            archive_outputs = ease['thread'] # Note: tuple type
                            number_of_archived_items = len(archive_outputs[0])
                            if number_of_archived_items != number_of_inputs:
                                err_str = _('Could not archive any files')
                                err_tit = _('Archiving error')
                                sg.popup_error(f"{err_str}: {number_of_archived_items} / {number_of_inputs}. {_('Aborting')}!", title=err_tit)
                            elif number_of_archived_items == 0:
                                err_str = _('Could not archive all selected files')
                                err_tit = _('Archiving error')
                                sg.popup_error(err_str, title=err_tit)
                            else:
                                actual_input = archive_outputs[1]
                                proceed_with_encryption = True
                        else:
                            actual_input = uinput_file
                            proceed_with_encryption = True
                        
                        # Encrypt file
                        if proceed_with_encryption:
                            actual_output = f"{actual_input}.aes" # standard extension
                            
                            # Check that we're not overwriting
                            if Path.is_file(Path(actual_output)):
                                # Create a unique output name
                                if Path(actual_input).suffix in ('.zip', '.tar', '.gz'):
                                    actual_output = Path(actual_input).parent / Path(actual_input).stem
                                    actual_output = f"{actual_output}-{get_unique_middlefix()}{Path(actual_input).suffix}.aes"
                                else:
                                    actual_output = f"{actual_input}.{get_unique_middlefix()}.aes"
                            
                            # Run aescrypt_worker in a separate thread
                            # while displaying a "working..." animated pop-up
                            # and report back to ease['thread'] var.
                            run_in_the_background('encrypt', [ True, actual_input, actual_output, uinput_passphrase ])
                            
                            # parse return from separate thread
                            if ease['thread'][0] == 0: # success
                                # Visual feedback is good
                                # newline separated list of inputs' basenames
                                inputs_str = [ Path(x).name for x in uinput_files ]
                                inputs_str = '\n'.join(inputs_str)
                                
                                # success popup
                                err_str = _('Successfully encrypted the input file(s)')
                                sg.popup_ok(
                                    f"{err_str}:\n\n{inputs_str}\n\n({Path(actual_output).name})",
                                    title=_("Success!")
                                )
                                
                                # remove input file if tar or zip
                                if archive_files and actual_input.split('.')[-1] in ('zip', 'tar', 'gz'):
                                    files_to_remove.append(actual_input) # mark for deletion
                                
                            elif ease['thread'][0] == 1:
                                err_str = _('I/O error')
                                sg.popup_error(f"{err_str}: {ease['thread'][1]}", title=err_str)
                            elif ease['thread'][0] == 2:
                                err_str = _('Encryption error')
                                sg.popup_error(f"{err_str}: {ease['thread'][1]}", title=err_str)
                            else:
                                err_str = _('Unhandled exception')
                                sg.popup_error(f"{err_str}: ease['thread'] not in 0-2")
                        
                        
                        # Quit to main either way
                        show_encrypt = False
                        
                    else:
                        err_str = _('Selected folder is not a folder')
                        sg.popup_error(f"{_err_str}: '{uinput_folder}'.")
                        show_encrypt = False
                else:
                    # an "else" here is probably input into passphrase box
                    Encrypt['uinput_ppstrength'].update(get_password_strength(Encrypt_value['uinput_passphrase']))
            
            # End encryption window
            Encrypt.close()
            
            # Re-open main window
            Main.UnHide()
            
        elif Main_event == '-button_decrypt-' and show_decrypt is False:
            show_decrypt = True
            Main.Hide()
            Decrypt = create_dec_window()
            
            # Do decryption loop
            while show_decrypt:
                Decrypt_event, Decrypt_value = Decrypt.read()
                print(f"Decrypt_event  = {Decrypt_event}\nDecrypt_value  = {Decrypt_value}")  # debug
                if Decrypt_event == sg.WIN_CLOSED:
                    show_decrypt = False
                
                if Decrypt_event == '-dec_cancel-':
                    show_decrypt = False
                
                if Decrypt_event == 'dec_uinput_file':
                     # Update output folder to match parent dir of files selectes as input (quality of life + 1)
                    Decrypt['dec_output_preview_str'].update(get_folder_from_infiles(Decrypt_value['dec_uinput_file']))
                elif Decrypt_event == '-dec_decrypt-': # user clicked "Decrypt" to execut decryption on input
                    uinput_file = Decrypt_value['dec_uinput_file']
                    uinput_passphrase = Decrypt_value['uinput_passphrase']
                    uinput_unarchive = Decrypt_value['uncompress'] # uncompress if file is compressed (tar, gz or zip)
                    uinput_cleanup = Decrypt_value['removesrc']    # remove source .aes file after decryption
                    uinput_outdir = Decrypt_value['dec_output_preview_str']
                    
                    if Path.is_dir(Path(uinput_outdir)):
                        pass
                    else:
                        print(f"Weird: uinput_outdir = {uinput_outdir} not a dir..")
                    
                    if Path.is_file(Path(uinput_file)):
                        # read first bytes (AES header is a requirement)
                        # cf. https://github.com/marcobellaccini/pyAesCrypt/issues/11
                        with open(uinput_file, "rb") as rawfile: byte = str(rawfile.read(32))
                        
                        if 'AES' in byte or 'aescrypt' in byte.lower():

                            # We know it's an aes file, but it might have invalid extension
                            output_file = Path(uinput_outdir) / Path(uinput_file).stem
                            if Path(uinput_file).parent == Path(uinput_outdir):
                                if uinput_file.endswith('aes'):
                                    pass
                                else:
                                    output_file = Path(str(output_file + '.out'))
                            
                            # Create unique output name if out file exists
                            if output_file.is_file():
                                output_alt = output_file.parent / output_file.stem
                                output_alt = f"{output_alt}-{get_unique_middlefix()}"
                                output_file = f"{output_alt}{output_file.suffix}"
                                
                            
                            # Run aescrypt_worker in a separate thread
                            # while displaying a "working..." animated pop-up
                            # and report back to ease['thread'] var.
                            run_in_the_background('decrypt', [ False, uinput_file, str(output_file), uinput_passphrase ])
                            
                            # parse return from separate thread
                            if ease['thread'][0] == 0:
                                pass
                            elif ease['thread'][0] == 1:
                                err_str = _('I/O error')
                                sg.popup_error(f"{err_str}: {ease['thread'][1]}", title=err_str)
                                show_decrypt = False
                            elif ease['thread'][0] == 2:
                                err_str = _('Decryption error')
                                sg.popup_error(f"{err_str}: {ease['thread'][1]}", title=err_str)
                                show_decrypt = False
                            
                            
                            # check if it's an archive
                            # if so, we will extract the archive contents into out_directory
                            if output_file.is_file():
                                if uinput_unarchive:
                                    
                                    # Run extraction in the background (threading)
                                    # while showing a "Working ..." pop-up
                                    # Output saved in ease['thread']
                                    run_in_the_background('unarchive', [str(output_file), uinput_outdir])
                                    
                                    # There is a bug here, cf.
                                    # ~/Downloads/CentOS-8.1.1911-x86_64-dvd1/test/home/sigg3/Downloads/CentOS-8.1.1911-x86_64-dvd1$ 
                                    
                                    # it extracts to target/dir + full path to original, instead of just target dir..
                                    
                                    # parse returns from background thread
                                    if type(ease['thread'][0]) is list:
                                        pass
                                    elif ease['thread'][0] == 'error':
                                        err_str = _('Error')
                                        sg.popup_error(f"{err_str}: {ease['thread'][1]}.", title=err_str)
                                        show_decrypt = False # TODO is this correct state to break loop??
                                    else:
                                        sg.popup_error("Unhandled else in unarchiving shenanigans :( thread not in list or 'error'.")
                                    
                                    extracted_files = ease['thread'][0]
                                    skipped_files = ease['thread'][1]
                                    number_of_extracted_items = len(extracted_files)
                                    number_of_archived_items = number_of_extracted_items + len(skipped_files)
                                    
                                    
                                    # Determine deletion of temporary "leftover" archive file
                                    if number_of_archived_items == 0 and number_of_extracted_items == 0:
                                        # This file was not archived and we must skip deletion of temp archive file (will delete output)
                                        number_of_archived_items, number_of_extracted_items = 1, 1
                                    else:
                                        # delete temporary archive file "output_file" (end-user wants the extracted contents)
                                        files_to_remove.append(str(output_file))                                        
                                else:
                                    number_of_extracted_items, number_of_archived_items = 1, 1
                                
                                
                                # Give visual feedback
                                if number_of_extracted_items == number_of_archived_items:
                                    pop_msg = _('Successfully decrypted input file(s)')
                                    sg.popup_ok(
                                    f"{pop_msg}: {number_of_extracted_items} / {number_of_archived_items}",
                                    title=_("Success")
                                    )
                                    
                                else:
                                    pop_msg = _('Successfully decrypted input file(s)')
                                    pop_two = _('Skipped items')
                                    sg.popup_ok(
                                    f"{pop_msg}: {number_of_extracted_items} / {number_of_archived_items}\n\n{pop_two}:\n{skipped_files}",
                                    title='Info'
                                    )
                                
                            else:
                                err_str = _('Selected input is not recognized as file(s)')
                                sg.popup_error(
                                    f"{err_str}: {output_file}", title=_('Error')
                                    )
                                
                                show_decrypt = False
                            
                            # Remove .aes file if so configured
                            if uinput_cleanup:
                                files_to_remove.append(uinput_file) # mark for deletion
                            
                            # Quit to main after decryption
                            show_decrypt = False
                            
                        else:
                            sg.popup_error(
                                f"'{uinput_file}' != AES v2 (pyAesCrypt).",
                                title=_('Error')
                                )
                            show_decrypt = False
                    else:
                        err_str = _('Selected input is not recognized as file(s)')
                        sg.popup_error(
                            f"{err_str}: '{uinput_file}'.", title=_('Error')
                            )
                        show_decrypt = False
                    
                    # Rest of decrypt stuff goes here
            
            # End decryption window
            Decrypt.close()
            
            # Re-open main window
            Main.UnHide()
            
        elif Main_event == '-button_send-' and show_send is False:
            show_send = True
            Main.Hide()
            
            # Setup sites info if unset
            try:
                ease['sites']
            except:
                ease['sites'] = setup_transmitters()
            
            Send = create_send_window()
            
            # Do send file loop
            while show_send:
                Send_event, Send_value = Send.read()
                print(f"Send_event  = {Send_event}\nSend_value  = {Send_value}")  # debug
                if Send_event == sg.WIN_CLOSED:
                    show_send = False
                
                if Send_event == '-send_cancel-':
                    show_send = False
                
                if Send_event == '-send_combo-': # dropdown event
                    # get site selected
                    sitename = Send_value['-send_combo-']
                    
                    # fetch relevant info
                    site_sentence, site_cap, site_faq, xfer_disabled = get_infostring_from_key(sitename)
                                        
                    # update fields in-place
                    Send['-provider_url-'].update(f"URL: {ease['sites'][sitename]['site_url']}")
                    Send['-provider_info-'].update(site_sentence)
                    Send['-provider_capinfo-'].update(site_cap)
                    Send['-provider_faq-'].update(site_faq)
                elif Send_event == '-visit_url-':
                    target_key = Send_value['-send_combo-']
                    try:
                        target_url = ease['sites'][target_key]['site_url']
                    except Exception as e:
                        err_str = _('Error')
                        sg.popup_error(
                                       f"{err_str}: {e}",
                                       title=_('Error')
                                       )
                        show_send = False # quit to main
                    
                    try:
                        webbrowser.open(target_url)
                    except Exception as e:
                        err_str = _('Error')
                        sg.popup_error(
                                       f"{err_str}: {e}",
                                       title=_('Error')
                                       )
                        show_send = False # quit to main
                    
                elif Send_event == '-send_send-':
                    # TODO
                    pass
            
            # End Send window
            Send.close()
            
            # Re-open main window
            Main.UnHide()
            
        elif Main_event == '-button_about-' and show_about is False:    
            show_about = True
            About = create_about_window()

            while show_about:
                About_event, About_value = About.read()
                print(f"About_event  = {About_event}\nAbout_value  = {About_value}")  # debug
                
                if About_event == sg.WIN_CLOSED:
                    show_about = False
                
                if About_event == '-about_ok-':
                    show_about = False
                
                if About_event == '-github-':
                    try:
                        webbrowser.open(ease['git'])
                    except Exception as e:
                        err_str = _('Error')
                        sg.popup_error(
                                       f"{err_str}: {e}",
                                       title=_('Error')
                                       )
                        show_about = False # quit to main
            
            About.close()
            
    
    # Remember to close window
    Main.close()
