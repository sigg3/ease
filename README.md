# EASE: <ins>E</ins>ncrypt <ins>A</ins>nd <ins>S</ins>end with <ins>E</ins>ASE

Simple utility for symmetric encryption of files or file archives prior to distribution over untrusted services (like e-mail).
AES256-CBC encryption provided by pyAesCrypt (cryptography), and passphrase evaluation by password_strength and zxcvbn-python.
Graphical user interface using PySimpleGUIQt (Qt), with translations provided by gettext.

EASE is specifically made for non-expert users, which means that all options have sane defaults. The user only needs to specify input file(s) and a passphrase, and EASE will handle the rest. Let's bring cryptography to the masses!

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

(Black style not yet implemented, but am working on those lengthy lines..)

## Translations

EASE is currently available in: English, Norwegian.

Find locale .pot files in the locales directory. EASE only uses one domain (base). Using a GUI application like Poedit (https://poedit.net/) it's simple to translate EASE to your language.

Please be warned: _String set is incomplete and subject to change._ I will remove this warning when the string set is stable.


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


## Run test-version (linux)
```
$ git clone https://github.com/sigg3/ease
$ cd ease
$ pip3 install -r requirements.txt
$ python3 ease.py
```
