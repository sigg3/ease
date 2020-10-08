# EASE: <ins>E</ins>ncrypt <ins>A</ins>nd <ins>S</ins>end with <ins>E</ins>ASE

Simple utility for symmetric encryption of files or file archives prior to distribution over untrusted services (like e-mail).
AES256-CBC encryption provided by pyAesCrypt (cryptography), and passphrase evaluation by password_strength and zxcvbn-python.
Graphical user interface using PySimpleGUIQt (Qt), with translations provided by gettext.

EASE will let you:
* Encrypt files you want to send
* Send files you have encrypted
* Decrypt files you have received

See [roadmap](https://github.com/sigg3/ease/blob/master/README.md#roadmap) for project progress below.

EASE is specifically made for non-expert users, which means that all options have sane defaults. The user only needs to specify input file(s) and a passphrase, and EASE will handle the rest. Let's bring cryptography to the masses!

EASE currently runs on GNU/Linux and Microsoft Windows (Apple OS untested).

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

(Black style not yet implemented, but am working on those lengthy lines..)

## Installation

Microsoft Windows binaries for English and Norwegian are [available in the dist folder](https://github.com/sigg3/ease/tree/master/dist). The zip files contains ease.exe and a locales directory with the appropriate language file. (This is not ideal and will be fixed later.) Please note that Windows Defender and Windows SmartScreen will probably "recognize" ease.exe as a potential threat, since it has an unknown publisher (me). Instructing them to [ignore the directory or run anyway](https://raw.githubusercontent.com/sigg3/ease/master/screenshots/win_smartscreen.png) seems to do the trick.


Apple OS binaries and GNU/Linux packages are plannet but not yet available.

### Run test-version (linux)
```
$ # create a directory for ease
$ mkdir ease && cd ease
$
$ # EITHER just get necessary files
$ wget https://raw.githubusercontent.com/sigg3/ease/master/ease.py
$ wget https://raw.githubusercontent.com/sigg3/ease/master/requirements.txt
$
$ # OR just clone everything
$ git clone https://github.com/sigg3/ease .
$
$ # THEN install deps
$ pip3 install -r requirements.txt
$
$ # FINALLY, run it
$ python3 ease.py
```

## Roadmap
- [ ] implement pytest
- [ ] object oriented modelling
- [ ] package (.deb) for GNU/Linux
- [x] binaries for Microsoft Windows
- [ ] binaries for Apple OS
- [x] implement gettext translation
- [ ] automated send-file attempt over selected service
- [ ] send file directly (magic-wormhole)
- [x] webbrowser open an online file transport service
- [x] encrypt file or group of files
- [x] archiving files (with or without compression)
- [x] decrypt files (with automatic archive extraction)


## Translations

EASE is currently available in: English, Norwegian.

Find locale .pot files in the locales directory. EASE only uses one domain (base). Using a GUI application like Poedit (https://poedit.net/) it's simple to translate EASE to your language.

Please be warned: _String set is incomplete and subject to change._ I will remove this warning when the string set is stable. We're currently on version 0.75, and we need to get to 1.0 for stable strings, specifically _automated send-file_ in roadmap (above).


## Screenshots

Main window

![Main window](https://raw.githubusercontent.com/sigg3/ease/master/screenshots/ease_main_full.png)

This is the first, friendly window of EASE. If you want to encrypt a file, click Encrypt. If you want to send a file you have encrypted, click Send. If you want to decrypt a file you have received, click Decrypt.


Encrypt file(s)

![Encrypt](https://raw.githubusercontent.com/sigg3/ease/master/screenshots/ease_encrypt.png)

Only input file and passphrase fields require user interaction.


Decrypt file(s)

![Decrypt](https://raw.githubusercontent.com/sigg3/ease/master/screenshots/ease_decrypt.png)

Only input file and passphrase fields require user interaction.


Send file(s)

![Send](https://raw.githubusercontent.com/sigg3/ease/master/screenshots/ease_send.png)
