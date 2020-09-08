#!/usr/bin/env python3
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
# EaSE is distributed in the hope that it will be useful, but
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
#import PySimpleGUI as sg

# List of issues, todos and bugs (by priority)
# TODO sending
# Priority: sendgb.com, fromsmash.com and fallback to surgesend.com

# In [12]: import webbrowser                                 
# In [13]: webbrowser.open('https://sigg3.net')      

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
    This will return a dict of file transmission alternatives (over the web).
    Separated into its own function for maintenance reasons.
    """
    
    # setup return
    list_of_sites = {}
    
    # sendgb.com (added 2020-09-07)
    sitename = 'sendgb.com'
    list_of_sites[sitename] = {}
    list_of_sites[sitename]['changed'] = '2020-09-07'
    list_of_sites[sitename]['site_url'] = f'https://www.{sitename}'
    list_of_sites[sitename]['days_expire'] = 7
    list_of_sites[sitename]['maz_size_gb'] = 5
    list_of_sites[sitename]['require_login'] = False
    
    # sendgb.com (added 2020-09-07)
    sitename = 'fromsmash.com'
    list_of_sites[sitename] = {}
    list_of_sites[sitename]['changed'] = '2020-09-07'
    list_of_sites[sitename]['site_url'] = f'https://{sitename}'
    list_of_sites[sitename]['days_expire'] = 14
    list_of_sites[sitename]['maz_size_gb'] = 2
    list_of_sites[sitename]['require_login'] = False
    
    # sendgb.com (added 2020-09-07)
    sitename = 'surgesend.com'
    list_of_sites[sitename] = {}
    list_of_sites[sitename]['changed'] = '2020-09-07'
    list_of_sites[sitename]['site_url'] = f'https://{sitename}'
    list_of_sites[sitename]['days_expire'] = 7
    list_of_sites[sitename]['maz_size_gb'] = 3
    list_of_sites[sitename]['require_login'] = False
    
    
    # return any hits
    return list_of_sites


# language dict
def set_gui_strings(language):
    """
    This function sets the visible strings for the GUI according to language
    preference. Translation can be done by appending this function with an
    elif clause appropriate for your language.
    
    Please copy as-is (with missing punctuation intact), in order to
    allow for use in f-strings.
    
    It is safer to ignore line length than to introduce unwanted tabs in text.
    
    NOTE: This will be re-done to use gettext() instead. I was unaware of it.
    Sorry for the inconvenience.
    
    """
    
    # Init GUI strings dictionary
    # Note: 'available languages' list can be used in a drop-down to select
    # language based on preference (currently not implemented).
    ease['available_languages'] = []
    ease['str'] = {} # strings
    ease['err'] = {} # errors
    ease['enc'] = {} # encryption window
    ease['dec'] = {} # decryption window
    # + moar
    
    # Strings for the graphical user interface. Please do not wrap lines.
    # Recurring/general strings
    ease['str']['eas_win_intro'] = "Encrypt a file or files securely so it's safe to distribute, or decrypt files you have received."
    
    ease['str']['select_outdir'] = "Specify where to save the output"
    ease['str']['select_infile'] = "Select input file(s)"
    ease['str']['passphrase'] = "Passphrase"
    ease['str']['phrase_help'] = "It is recommended to use a full sentence as the passphrase."
    ease['str']['cancel'] = "Cancel"
    ease['str']['success'] = "Success"
    ease['str']['error'] = "Error"
    ease['str']['aborting'] = "Aborting"
    ease['str']['encryption'] = "Encryption"
    ease['str']['decryption'] = "Decryption"
    ease['str']['archiving'] = "Archiving"
    ease['str']['extracting'] = "Exctracting" # e.g. unarchiving
    ease['str']['working'] = "Working"
    ease['str']['encrypting'] = 'Encrypting'
    ease['str']['decrypting'] = 'Decrypting'
    ease['str']['patience'] = "This might take a while"
    ease['str']['language'] = "Language"
    ease['str']['options'] = 'options'
    ease['str']['elapsed'] = 'Elapsed time'
    ease['str']['secs'] = 'seconds'
        
    # Errors
    ease['err']['arch_none'] = "Could not archive all selected files"
    ease['err']['arch_some'] = "Could not archive any files"
    ease['err']['notfolder'] = "Selected folder is not a folder"
    ease['err']['isnotfile'] = "Selected input is not recognized as file(s)"
    
    # Encryption window strings
    ease['enc']['win_0'] = "Securely encrypt file(s), so it is safe to distribute over untrusted service (like e-mail)."
    ease['enc']['win_1'] = "If you select more than one file, they will be gathered in an encrypted archive."
    ease['enc']['win_2'] = "If your recipient uses Windows, consider using zip instead of tar."
    ease['enc']['options'] = "Archiving options (for groups of files)"
    ease['enc']['compress'] = "Enable compression (smaller file size)"
    ease['enc']['rypt'] = "Encrypt"
    ease['enc']['success'] = "Successfully encrypted input file(s)"
    
    
    # Decrypt window strings
    ease['dec']['win_0'] = "Decrypt any encrypted .aes file you have received."
    ease['dec']['win_1'] = "If the decrypted file is a tarball or zip archive, it will be extracted."
    ease['dec']['uncompress'] = "Automatically decompress decrypted archives"
    ease['dec']['rem_src'] = "Remove source .aes file after decryption"
    ease['dec']['rypt'] = "Decrypt"
    ease['dec']['success'] = "Successfully decrypted input file(s)"
    ease['dec']['skipped'] = 'Skipped items'
    
    # Send window strings
    # TODO
    
    # Welcome and About strings
    ease['str']['eas_win_wel_1'] = "This utility uses AES256-CBC (pyAesCrypt) to encrypt/decrypt files in the AES Crypt file format v.2."
    
    
    if language == 'English':
        pass # English is the default
    elif language == 'Norwegian':
        # Full set of the above English strings in Norwegian
        pass
        # TODO
    
    # Create a list of available languages in case
    # we want to be able to change language on-the-fly
    # Incomplete languages will contain English (safe fallback).
    ease['available_languages'].append('English')
    ease['available_languages'].append('Norwegian')


def create_main_window() -> Type[sg.Window]:
    """
    Create (and re-create) main (or initial) window
    Return window object to allow for assignment to variable in main.
    """
    
    # Set layout
    WelcomeLayout = [
                [sg.Text(f"{ease['title']}", font=('Sans serif', 16))],
                [sg.Text(' ')],
                [sg.Text(f"{ease['str']['eas_win_intro']}")],
                [sg.Text(f"{ease['str']['eas_win_wel_1']}")],
                [sg.Text(' ')],
                [sg.Button(
                    f"{ease['enc']['rypt']}",
                    image_data=ease['icon_encrypt'],
                    key='-button_encrypt-',
                    font=("Helvetica", 16)
                    ),
                 sg.Button(
                    f"{ease['dec']['rypt']}",
                    image_data=ease['icon_decrypt'],
                    key='-button_decrypt-',
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
        sg.CBox(ease['enc']['compress'], default=False, key='compression')
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
        [sg.Text(f"{ease['enc']['win_0']}")],
        [sg.Text(f"{ease['enc']['win_1']}")],
        [sg.Text(f"{ease['enc']['win_2']}")],
        [sg.T(' ')],
        [sg.Frame(layout=enc_in, title=f"{ease['str']['select_infile']}:")],
        [sg.Frame(layout=enc_out, title=ease['str']['select_outdir'])],
        [sg.Frame(layout=enc_opts, title=ease['enc']['options'])],
        [sg.Frame(layout=[
            [sg.T(f"{ease['str']['phrase_help']}")],
            [sg.In('', key='uinput_passphrase')],
            [sg.T(get_password_strength(''), key='uinput_ppstrength')]
            ],
            title=ease['str']['passphrase']
            )
        ],
        [
        sg.Button(f"{ease['enc']['rypt']}", key='-enc_encrypt-'),
        sg.Cancel(ease['str']['cancel'], key='-enc_cancel-')
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
        [sg.CBox(ease['dec']['uncompress'], default=True, key='uncompress')],
        [sg.CBox(ease['dec']['rem_src'], default=False, key='removesrc')]
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
        [sg.Text(f"{ease['dec']['win_0']}")],
        [sg.Text(f"{ease['dec']['win_1']}")],
        [sg.T(' ')],
        [sg.Frame(layout=dec_in, title=ease['str']['select_infile'])],
        [sg.Frame(layout=dec_opts, title=f"{ease['str']['decryption']} {ease['str']['options']}")],
        [sg.Frame(layout=dec_out, title=ease['str']['select_outdir'])],
        [sg.Frame(layout=dec_pass, title=ease['str']['passphrase'])],
        [
        sg.Button(f"{ease['dec']['rypt']}", key='-dec_decrypt-'),
        sg.Cancel(ease['str']['cancel'], key='-dec_cancel-')
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
    if uinput_passphrase is None or uinput_passphrase == '':
        return f"{ease['str']['passphrase']} entropy bits: 0.0, complexity: 0.00"

    stats = PasswordStats(uinput_passphrase)
    
    return f"{ease['str']['passphrase']} entropy bits: {stats.entropy_bits:0.1f}, complexity: {stats.strength():0.2f}"


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
#    elapsed_time = '0.2' # because we have a hard-coded 0.2 sec head start ..
    spinner_layout = [[ sg.T(f"{show_text}.. {ease['str']['patience']}.\n{ease['str']['elapsed']}: {show_time} {ease['str']['secs']}", key='-spinner_text-') ]]
    # changed from no_titlebar=True, because it was weird without it
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
        string_action= ease['str']['encryption']
        aes_exec = pyAesCrypt.encryptFile
        
    else:
        string_action= ease['str']['decryption']
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
        show_text = ease['str']['archiving']        
    elif worker_to_run == 'unarchive':
        worker_func = unarchive_worker
        show_text = ease['str']['extracting']
        number_of_args = 2 # only has 2 args + output_dict and output_index
    else:
        worker_func = aescrypt_worker
        show_text = ease['str']['encrypting'] if worker_to_run == 'encrypt' else ease['str']['decrypting']
    
    
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
            spinner['-spinner_text-'].update(f"{show_text}.. {ease['str']['patience']}.\n{ease['str']['elapsed']}: {time.time() - start_time:0.1f} {ease['str']['secs']}")
    
    
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
    ease['buffer'] = 64 * 1024
    ease['password'] = None # Not in use
    ease['input'] = None    # Not in use
    ease['output'] = None   # Not in use
    ease['language'] = 'English'
    ease['archive'] = False
    ease['use_tar'] = True
    ease['compression'] = False # use store
    
    # Set "home" dir (our default)
    if Path.is_dir(Path.home()):
        ease['home_dir'] = Path.home()
    else:
        ease['home_dir'] = Path.cwd()
    
    # Set current output dir to default
    ease['output_dir'] = ease['home_dir']
    
    # color theme
    sg.ChangeLookAndFeel('SystemDefaultForReal')
    #sg.theme(set_theme)
    
    # Set GUI strings language
    set_gui_strings(ease['language']) # default
    #set_gui_strings('Norwegian') # test Norwegian
    
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
    
    ease['icon_sendenc'] = '' # TODO send icon
    ease['icon_easehlp'] = '' # TODO help/about icon
    
    
    # GUI toggles
    show_encrypt = False
    show_decrypt = False
    show_send = False
    
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
                    Path(xfile).unlink(missing_ok=True) # since we already have Path imported ..
                    print(f"removed {xfile}") # debug
                except Exception as e:
                    sg.popup_error(f"Error removing file {xfile}.\nException: {e}", title='Error')
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
                            sg.popup_error(f"{ease['err']['isnotfile']}:\n'{uinput_file}'", title=f"{ease['str']['error']}")
                            show_encrypt = False
                        
                        
                        # Check password length within third-party libs parameters
                        # Note: EASE is not designed to enforce password policies.
                        if len(uinput_passphrase) < 6:
                            sg.popup_error(f"{ease['str']['error']}: len(pass) < 6. {ease['str']['aborting']}!")
                            show_encrypt = False
                        elif len(uinput_passphrase) > 1024:
                            sg.popup_error(f"{ease['str']['error']}: len(pass) > 1024. {ease['str']['aborting']}!")
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
                            
                            print(f"got actual_output candidate as {ease['thread'][1]}")
                            
                            # save outputs here (ease['thread'] is re-usable)
                            archive_outputs = ease['thread'] # Note: tuple type
                            number_of_archived_items = len(archive_outputs[0])
                            if number_of_archived_items != number_of_inputs:
                                sg.popup_error(f"{ease['err']['arch_some']}: {number_of_archived_items} / {number_of_inputs}. {ease['str']['aborting']}!", title=f"{ease['str']['archiving']} {ease['str']['error'].lower()}")
                            elif number_of_archived_items == 0:
                                sg.popup_error(f"{ease['err']['arch_none']}. {ease['str']['aborting']}!", title=f"{ease['str']['archiving']} {ease['str']['error'].lower()}")
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
                                sg.popup_ok(
                                    f"{ease['enc']['success']}:\n\n{inputs_str}\n\n({Path(actual_output).name})",
                                    title=f"{ease['str']['success']}!"
                                )
                                
                                # remove input file if tar or zip
                                if archive_files and actual_input.split('.')[-1] in ('zip', 'tar', 'gz'):
                                    files_to_remove.append(actual_input) # mark for deletion
                                
                            elif ease['thread'][0] == 1:
                                sg.popup_error(f"I/O {ease['str']['error']}: {ease['thread'][1]}", title=f"I/O {ease['str']['error']}")
                            elif ease['thread'][0] == 2:
                                sg.popup_error(f"{ease['str']['encryption']} {ease['str']['error']}: {ease['thread'][1]}", title=f"{ease['str']['encryption']} {ease['str']['error']}")
                            else:
                                sg.popup_error("Unhandled: ease['thread'] not in 0-2") # debug
                        
                        
                        # Quit to main either way
                        show_encrypt = False
                        
                    else:
                        sg.popup_error(f"{ease['err']['notfolder']}: '{uinput_folder}'. {ease['str']['aborting']}!")
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
                            
                            output_was = output_file                                            #
                            avoid_dupes = 1                                             #
                            while output_file.is_file():
                                output_alt = str(output_was) + f'-out_{avoid_dupes}'
                                output_file = Path(output_alt) # loop will end here
                                avoid_dupes += 1
                            
                            # Run aescrypt_worker in a separate thread
                            # while displaying a "working..." animated pop-up
                            # and report back to ease['thread'] var.
                            run_in_the_background('decrypt', [ False, uinput_file, str(output_file), uinput_passphrase ])
                            
                            # parse return from separate thread
                            if ease['thread'][0] == 0:
                                pass
                            elif ease['thread'][0] == 1:
                                sg.popup_error(f"I/O {ease['str']['error']}: {ease['thread'][1]}", title=f"I/O ease['str']['error'])")
                                show_decrypt = False
                            elif ease['thread'][0] == 2:
                                sg.popup_error(f"{ease['str']['error']} {ease['str']['decryption']}: {ease['thread'][1]}", title=f"{ease['str']['decryption']} {ease['str']['error']}")
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
                                        sg.popup_error(f"{ease['str']['error']}: {ease['thread'][1]}. {ease['str']['aborting']}", title=ease['str']['error'])
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
                                    sg.popup_ok(f"{ease['dec']['success']}: {number_of_extracted_items} / {number_of_archived_items}", title=f"{ease['str']['success']}!")
                                else:
                                    sg.popup_ok(f"{ease['dec']['success']}: {number_of_extracted_items} / {number_of_archived_items}\n\n{ease['dec']['skipped']}:\n{skipped_files}", title='Info')
                                
                            else:
                                sg.popup_error(f"{ease['err']['isnotfile']}: {output_file}", title=ease['str']['error'])
                                show_decrypt = False
                            
                            # Remove .aes file if so configured
                            if uinput_cleanup:
                                files_to_remove.append(uinput_file) # mark for deletion
                            
                            # Quit to main after decryption
                            show_decrypt = False
                            
                        else:
                            sg.popup_error(f"'{uinput_file}' != AES v2 (pyAesCrypt). {ease['str']['aborting']}!", title=ease['str']['error'])
                            show_decrypt = False
                    else:
                        sg.popup_error(f"{ease['err']['isnotfile']}: '{uinput_file}'. {ease['str']['aborting']}!", title=ease['str']['error'])
                        show_decrypt = False
                    
                    # Rest of decrypt stuff goes here
            
            # End decryption window
            Decrypt.close()
            
            # Re-open main window
            Main.UnHide()
            
        elif Main_event == '-button_send-' and show_send is False:
            # debug
            print('SEND window')
            pass 
            # TODO
        elif Main_event == '-button_about-':
            # Note: this just opens a text box popup, no need to hide main window.

            # debug
            print('ABOUT popup')

            pass
            # TODO
        
    
    # Remember to close window
    Main.close()
