# -*- coding: utf-8 -*-
# CODING=UTF8
#
# Weechat Remote Control
# ======================================================================
# Author       : Radek Valasek
# Contact      : https://github.com/reddy75/wrecon/issues
# Licence      : GPL3
# Description  : Script for control remote server
# Requirements : weechat, python3, tmate, ircrypt (script for weechat)

# GIT ................... : https://github.com/reddy75/wrecon
# LATEST RELEASE ........ : https://github.com/reddy75/wrecon/releases/latest
# BUG REPORTS ........... : https://github.com/reddy75/wrecon/issues
# IMPROVEMENT SUGGESTIONS : https://github.com/reddy75/wrecon/issues
# WIKI / HELP ........... : https://github.com/reddy75/wrecon/wiki

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# Changelog:
# 1.xx.0 (unusable, full reworking in progress)
# - Full code rewriting (for better lucidity)
# -- function 'display_message' replaces 'f_message' and 'f_message_simple'
# -- function 'update' fully changed (splitted into functions)
# -- functions 'encrypt/decrypt' enhanced into levels (also backward compatibility ensure with older script communication)
# -- 
#
# 1.16 - Small fix of call ADVERTISE after RENAME
# 1.15 - Small fix in HELP - REGISTER
# 1.14 - Bug fix REMOTE RENAME
# 1.13 - Bug fixes
# 1.12 - Version fix
# 1.11 - Bug fix for HELP command
# 1.10 - Command UPDATE added - New feature (check and install new version from GIT repo)
#      - Added UNIQUE HASH to all called commands
#      - Command UNREGISTER changed to UN[REGISTER]
#      - Help for UNREGISTER updated
#      - Corrected LATEST RELEASE in header of script
# 1.05 - Bug fix issue #3
# 1.04 - Bug fix issue #2
#      - Removed never used variable(s)
#      - Added autoadvertise request from local PC for non-advertised remote BOT when calling SSH
#      - Small bug fixes
# 1.03 - Update Contact field
#      - Small fixes of parts of short help
#      - Small fixes of parts of comments of code
# 1.02 - Bug fix issue #1
#        added github links into header
# 1.01 - Bug fix
# 1.00 - First release
#
# Purpose:
# Start 'tmate' session on remote PC over Weechat.
# - tmate session is started only for granted server(s)
# - communication between servers is accomplished over a registered IRC #Channel
# - IRC #Channel is encrypted via ircrypt
# 
# 
# Dependencies:
# Weechat, Tmate, Python3
# Python3 modules:
# - ast, base64, contextlib, datetime, gnupg, hashlib, json, os, random,
# - shutil, string, sys, tarfile, time, urllib
# 
# 
# Limitations:
# - only one IRC #Channel with IRC Server is allowed to register
# - supported platform is only linux and android (9/10 - with termux installed)
# 
# 
# Tested on platform:
# - Fedora 30/31
# - Xubuntu 18.04
# - Android 9/10 (in termux)

#####
#
# BASIC INITIALIZATION
# try import modules for python and check version of python

global SCRIPT_NAME, SCRIPT_VERSION, SCRIPT_AUTHOR, SCRIPT_LICENSE, SCRIPT_DESC, SCRIPT_UNLOAD, SCRIPT_CONTINUE, SCRIPT_TIMESTAMP, SCRIPT_FILE, SCRIPT_FILE_SIG, SCRIPT_BASE_NAME
SCRIPT_NAME      = 'wrecon'
SCRIPT_VERSION   = '1.17.0 devel'
SCRIPT_TIMESTAMP = ''

SCRIPT_FILE      = 'wrecon-devel.py'
SCRIPT_FILE_SIG  = 'wrecon-devel.py.sig'
SCRIPT_BASE_NAME = 'reddy75/wrecon-devel'

SCRIPT_AUTHOR    = 'Radek Valasek'
SCRIPT_LICENSE   = 'GPL3'
SCRIPT_DESC      = 'Weechat Remote control (WRECON)'
SCRIPT_UNLOAD    = 'wrecon_unload'

SCRIPT_CONTINUE  = True
import importlib
for IMPORT_MOD in ['ast', 'base64', 'contextlib', 'datetime', 'gnupg', 'hashlib', 'json', 'os', 'random', 'shutil', 'string', 'sys', 'tarfile', 'time', 'urllib', 'weechat']:
  try:
    IMPORT_OBJECT = importlib.import_module(IMPORT_MOD, package=None)
    globals()[IMPORT_MOD] = IMPORT_OBJECT
    # ~ print('[%s v%s] > module %s imported' % (SCRIPT_NAME, SCRIPT_VERSION, IMPORT_MOD))
  except ImportError:
    SCRIPT_CONTINUE = False
    print('[%s v%s] > module >> %s << import error' % (SCRIPT_NAME, SCRIPT_VERSION, IMPORT_MOD))


if sys.version_info >= (3,):
  #print('[%s v%s] > python version 3' % (SCRIPT_NAME, SCRIPT_VERSION))
  pass
else:
  SCRIPT_CONTINUE = False
  print('[%s v%s] > python version %s is not supported' % (SCRIPT_NAME, SCRIPT_VERSION, sys.version_info))

if SCRIPT_CONTINUE == False:
  # I there was issue with initialization basic modules for importing or version of python is unsupported, then
  # we write error message
  print('[%s v%s] > script not started, resolve dependencies and requirements' % (SCRIPT_NAME, SCRIPT_VERSION))
else:
  #####
  #
  # INITIALIZE SCRIP FOR WEECHAT
  
  weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, SCRIPT_UNLOAD, 'UTF-8')

  ####
  #
  # PUBLIC KEY
  
  global PUBLIC_KEY
  PUBLIC_KEY ='''
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
KPX4rlTJFYD/K/Hb0OM4NwaXz5Q=
=FtIt
-----END PGP PUBLIC KEY BLOCK-----
  '''
  
  #
  ##### END OF PUBLIC KEY

  #####
  #
  # FUNCTION FOR GENERATING RANDOM CHARACTERS AND NUMBERS
  
  def get_random_string(STRING_LENGTH):
    STR_LETTERS_AND_DIGITS = string.ascii_letters + string.digits
    return ''.join(random.choice(STR_LETTERS_AND_DIGITS) for INDEX in range(STRING_LENGTH))
  
  #####
  #
  # FUNCTION GET HASH OF A STRING
  
  def get_hash(INPUT_STRING):
    RESULT = hashlib.md5(INPUT_STRING.encode())
    return str(RESULT.hexdigest())
  
  #####
  #
  # FUNCTION FOR COUNTING COMMANDS AND ADD UNIQ HASH
  
  def get_command_uniq_id():
    global WRECON_COMMAND_COUNTER
    WRECON_COMMAND_COUNTER = WRECON_COMMAND_COUNTER + 1
    if WRECON_COMMAND_COUNTER > 9999:
      WRECON_COMMAND_COUNTER = 0
    return '%04d-%s' % (WRECON_COMMAND_COUNTER, get_random_string(4))
  
  #####
  #
  # FUNCTION FOR VERIFY CHANNEL SETUP AND POSSIBILITY TO CHANGE MODE IF NECESSARY
  
  def setup_channel(DATA, BUFFER, SERVER_NAME, CHANNEL_NAME):
    global WRECON_CHANNEL_KEY
    RESULT      = 0
    RESULT_NICK  = 0
    RESULT_CHANNEL  = 0
    RESULT_MODE  = 0
    MY_NICK_NAME = weechat.info_get('irc_nick', SERVER_NAME)
    INFOLIST    = weechat.infolist_get('irc_nick', '', '%s,%s' % (SERVER_NAME, CHANNEL_NAME))
    while weechat.infolist_next(INFOLIST):
      FOUND_NICK_NAME = weechat.infolist_string(INFOLIST, 'name')
      if MY_NICK_NAME == FOUND_NICK_NAME:
        NICK_PREFIX   = weechat.infolist_string(INFOLIST, 'prefix')
        NICK_PREFIXES = weechat.infolist_string(INFOLIST, 'prefixes')
        if '@' in NICK_PREFIXES:
          RESULT_NICK = 1
    weechat.infolist_free(INFOLIST)

    INFOLIST   = weechat.infolist_get('irc_channel', '', '%s,%s' % (SERVER_NAME, CHANNEL_NAME))
    while weechat.infolist_next(INFOLIST):
      FOUND_CHANNEL_NAME = weechat.infolist_string(INFOLIST, 'name')
      FOUND_CHANNEL_KEY  = weechat.infolist_string(INFOLIST, 'key')
      FOUND_CHANNEL_MODE = weechat.infolist_string(INFOLIST, 'modes')
      if FOUND_CHANNEL_NAME == CHANNEL_NAME:
        if not WRECON_CHANNEL_KEY in FOUND_CHANNEL_MODE:
          RESULT_CHANNEL = 1
        if not 'k' in FOUND_CHANNEL_MODE:
          RESULT_MODE = 1
        
    weechat.infolist_free(INFOLIST)
    
    if RESULT_NICK == 1:
      if RESULT_MODE == 1 or RESULT_CHANNEL == 1:
        weechat.command(BUFFER, '/mode %s -n+sk %s' % (CHANNEL_NAME, WRECON_CHANNEL_KEY))
    return RESULT
    
  #####
  #
  # FUNCTION ENCRYPT AND DECTRYPT STRING
  #
  # CORRECT LENGTH OF ENCRYPT/DECRYPT KEY

  def correct_key_length(INPUT_STRING, INPUT_KEY):
    OUTPUT_KEY = INPUT_KEY
    while len(INPUT_STRING) > len(OUTPUT_KEY):
      OUTPUT_KEY += INPUT_KEY
    return OUTPUT_KEY
  
  #
  # ENCRYPT
  #
  
  def encrypt_string(LEVEL, INPUT_STRING, INPUT_KEY):
    global ENCRYPT_LEVEL
    return ENCRYPT_LEVEL[LEVEL]

  def encrypt_string_level_0(INPUT_STRING, INPUT_KEY):
    INPUT_KEY   = correct_key_length(INPUT_STRING, INPUT_KEY)
    OUTPUT_LIST = []
    for INDEX in range(len(INPUT_STRING)):
      KEY_CHAR    = INPUT_STRING[INDEX % len(INPUT_STRING)]
      OUTPUT_CHAR = chr((ord(INPUT_KEY[INDEX]) + ord(KEY_CHAR)) % 256)
      OUTPUT_LIST.append(OUTPUT_CHAR)
    return base64.urlsafe_b64encode(''.join(OUTPUT_LIST).encode()).decode()
  
  def encrypt_string_level_1(INPUT_STRING, INPUT_KEY):
    INPUT_KEY             = correct_key_length(INPUT_STRING, INPUT_KEY)
    NEW_INPUT_KEY         = get_hash(INPUT_KEY)
    SALT_STRING           = f_random_generator(8)
    OUTPUT_RESULT_LEVEL_1 = encrypt_string_level_0(INPUT_STRING, SALT_STRING + INPUT_KEY)
    OUTPUT_RESULT_LEVEL_2 = encrypt_string_level_0(SALT_STRING + OUTPUT_RESULT_LEVEL_1, NEW_INPUT_KEY)
    return base64.urlsafe_b64encode(OUTPUT_RESULT_LEVEL_2.encode()).decode()
  
  global ENCRYPT_LEVEL
  ENCRYPT_LEVEL[0] = encrypt_string_level_0
  ENCRYPT_LEVEL[1] = encrypt_string_level_1
  
  #
  # DECRYPT
  #
  
  def decrypt_string(LEVEL, INPUT_STRING, INPUT_KEY):
    global DECRYPT_LEVEL
    return DECRYPT_LEVEL[LEVEL] 
  
  def decrypt_string_level_0(INPUT_STRING, INPUT_KEY):
    INPUT_KEY     = correct_key_length(INPUT_STRING, INPUT_KEY)
    OUTPUT_LIST   = []
    DECODE_STRING = base64.urlsafe_b64decode(INPUT_STRING).decode()
    for INDEX in range(len(DECODE_STRING)):
      KEY_CHAR = INPUT_KEY[INDEX % len(INPUT_KEY)]
      OUTPUT_CHAR = chr((256 + ord(DECODE_STRING[INDEX]) - ord(KEY_CHAR)) % 256)
      OUTPUT_LIST.append(OUTPUT_CHAR)
    return ''.join(OUTPUT_LIST)
  
  def decrypt_string_level_1(INPUT_STRING, INPUT_KEY):
    INPUT_KEY             = correct_key_length(INPUT_STRING, INPUT_KEY)
    DECODE_STRING         = base64.urlsafe_b64decode(INPUT_STRING).decode()
    NEW_INPUT_KEY         = get_hash(INPUT_KEY)
    OUTPUT_RESULT_LEVEL_2 = decrypt_string_level_0(DECODE_STRING, NEW_INPUT_KEY)
    SALT_STRING           = OUTPUT_RESULT_LEVEL_2[:8]
    OUTPUT_RESULT_LEVEL_1 = decrypt_string_level_0(OUTPUT_RESULT_LEVEL_2[8:], SALT_STRING + INPUT_KEY)
    return OUTPUT_RESULT_LEVEL_1
  
  global DECRYPT_LEVEL
  DECRYPT_LEVEL[0] = decrypt_string_level_0
  DECRYPT_LEVEL[1] = decrypt_string_level_1
  
  #
  #### END FUNCTION ENCRYPT AND DECTRYPT STRING

  #####
  #
  # FUNCTION DISPLAY MESSAGE
  
  def display_message(BUFFER, INPUT_MESSAGE):
    global SCRIPT_NAME

    if isinstance(INPUT_MESSAGE, list):
      for OUTPUT_MESSAGE in INPUT_MESSAGE:
        weechat.prnt(BUFFER, '[%s]\t%s' % (SCRIPT_NAME, str(OUTPUT_MESSAGE)))
    else:
      weechat.prnt(BUFFER, '[%s]\t%s' % (SCRIPT_NAME, str(INPUT_MESSAGE)))

    return weechat.WEECHAT_RC_OK
  
  #
  ##### END FUNCTION DISPLAY MESSAGE
  
  #####
  #
  # FUNCTION CHECK AND UPDATE
  
  #
  # UPDATE
  #
  
  def update(DATA, BUFFER):
    OUTPUT_MESSAGE = ['--- WRECON UPDATE CHECK AND INSTALL ---']
    
    # CALL CHECK FOR NEW UPDATE
    UPDATE_CONTINUE, UPDATE_NEXT_FUNCTION, OUTPUT_MESSAGE, LATEST_RELEASE, ARCHIVE_FILE, DOWNLOAD_URL, EXTRACT_SUBDIRECTORY = update_1_check(OUTPUT_MESSAGE)
    
    # CALL PREPARE DIR
    if UPDATE_CONTINUE == True:
      UPDATE_CONTINUE, UPDATE_NEXT_FUNCTION, OUTPUT_MESSAGE, DOWNLOAD_DIRECTORY = UPDATE_NEXT_FUNCTION(OUTPUT_MESSAGE)
    
    # CALL DOWNLOAD FILE
    if UPDATE_CONTINUE == True:
      UPDATE_CONTINUE, UPDATE_NEXT_FUNCTION, OUTPUT_MESSAGE = UPDATE_NEXT_FUNCTION(OUTPUT_MESSAGE, DOWNLOAD_DIRECTORY, ARCHIVE_FILE, DOWNLOAD_URL)
    
    # CALL EXTRACT ARCHIVE
    if UPDATE_CONTINUE == True:
      UPDATE_CONTINUE, UPDATE_NEXT_FUNCTION, OUTPUT_MESSAGE = UPDATE_NEXT_FUNCTION(OUTPUT_MESSAGE, DOWNLOAD_DIRECTORY, ARCHIVE_FILE)
    
    # CALL VERIFY EXTRACTED FILE
    if UPDATE_CONTINUE == True:
      UPDATE_CONTINUE, UPDATE_NEXT_FUNCTION, OUTPUT_MESSAGE, INSTALL_FILE = UPDATE_NEXT_FUNCTION(OUTPUT_MESSAGE, EXTRACT_SUBDIRECTORY)
    
    # CALL INSTALL NEW FILE
    if UPDATE_CONTINUE == True:
      UPDATE_CONTINUE, UPDATE_NEXT_FUNCTION, OUTPUT_MESSAGE = UPDATE_NEXT_FUNCTION(OUTPUT_MESSAGE, INSTALL_FILE)
    
    display_message(DATA, BUFFER, OUTPUT_MESSAGE)
    
    # AFTER SUCCESSFUL INSTALLATION WE CAN RESTART
    if UPDATE_CONTINUE == True:
      global SCRIPT_FILE
      display_message(BUFFER, 'RESTARTING WRECON...')
      weechat.command(BUFFER, '/wait 3s /script reload %s' % SCRIPT_FILE)
    
    return weechat.WEECHAT_RC_OK
    
  #
  # UPDATE - CHECK (new version in URL)
  #
  
  def update_1_check(OUTPUT_MESSAGE):
    import urllib.request
    global SCRIPT_VERSION, SCRIPT_BASE_NAME
    
    UPDATE_EXIST   = False
    NEXT_FUNCTION  = pass
    
    LATEST_RELEASE, ARCHIVE_FILE, DOWNLOAD_URL, EXTRACT_SUBDIRECTORY  = ['', '', '', '']

    ACTUAL_VERSION = SCRIPT_VERSION.split(' ')[0]
    BASE_URL       = 'https://github.com/%s/archive' % SCRIPT_BASE_NAME
    BASE_API_URL   = 'https://api.github.com/repos/%s/releases/latest' % SCRIPT_BASE_NAME
    
    OUTPUT_MESSAGE.append('ACTUAL VERSION  : %s' % ACTUAL_VERSION)
    OUTPUT_MESSAGE.append('REQUESTING URL  : %s' % BASE_API_URL)
    
    ERROR_GET = False
    try:
      URL_DATA = urllib.request.urlopen(BASE_API_URL)
    except (urllib.error.HTTPError, urllib.error.URLerror, urllib.error.ContentTooShortError()) as ERROR:
      ERROR_GET  = True
      ERROR_DATA = ERROR.__dict__
    
    if ERROR_GET == True:
      OUTPUT_MESSAGE.append('AN ERROR OCCURED DURING CHECK OF LATEST VERSION FROM GITHUB')
      if 'code' in ERROR_DATA and 'msg' in ERROR_DATA:
        OUTPUT_MESSAGE.append('ERROR CODE    : %s' % ERROR_DATA['code'])
        OUTPUT_MESSAGE.append('ERROR MESSAGE : %s' % ERROR_DATA['msg'])
      OUTPUT_MESSAGE.append('ERROR DATA    : %s' % ERROR_DATA)
    else:
      GET_DATA       = json.loads(URL_DATA.read().decode('utf8'))
      LATEST_RELEASE = GET_DATA['tag_name'].split('v')[1]
      
      OUTPUT_MESSAGE.append('LATEST RELEASE  : %s' % LATEST_RELEASE)
      
      if ACTUAL_VERSION >= LATEST_RELEASE:
        OUTPUT_MESSAGE.append('WRECON IS UP TO DATE')
      else:
        global SCRIPT_FILE
        UPDATE_EXIST         = True
        NEXT_FUNCTION        = update_2_prepare_dir
        ARCHIVE_FILE         = '%s.tar.gz' % LATEST_RELEASE
        DOWNLOAD_URL         = '%s/%s' % (BASE_URL, ARCHIVE_FILE)
        EXTRACT_SUBDIRECTORY = '%s-%s' % (SCRIPT_FILE.split('.')[0], LATEST_RELEASE)
        
        OUTPUT_MESSAGE.append('FOUND NEW RELEASE')        
        OUTPUT_MESSAGE.append('DOWNLOAD URL    : %s' % DOWNLOAD_URL)

    return [UPDATE_EXIST, NEXT_FUNCTION, OUTPUT_MESSAGE, LATEST_RELEASE, ARCHIVE_FILE, DOWNLOAD_URL, EXTRACT_SUBDIRECTORY]
  
  #
  # UPDATE - PREPARE DOWNLOAD DIR
  #
  
  def update_2_prepare_dir(OUTPUT_MESSAGE):
    ENVIRONMENT_VARIABLES = os.environ
    DOWNLOAD_DIRECTORY    = '%s/%s' % (ENVIRONMENT_VARIABLES['HOME'], '.wrecon-update')
    
    DIRECTORY_PREPARED    = False
    NEXT_FUNCTION         = pass
    
    OUTPUT_MESSAGE.append('DOWNLOAD DIR    : %s' % DOWNLOAD_DIRECTORY)
    
    if not os.path.exists(os.path.join(DOWNLOAD_DIRECTORY)):
      try:
        os.mkdir(os.path.join(DOWNLOAD_DIRECTORY))
        DIRECTORY_PREPARED = True
      except OSError as ERROR:
        OUTPUT_MESSAGE.append('ERROR, DOWNLOAD DIRECTORY CAN NOT BE CREATED')
        OUTPUT_MESSAGE.append('ERROR : %s' % ERROR.__dict__)
    else:
      if not os.path_isdir(s.path.join(DOWNLOAD_DIRECTORY)):
        OUTPUT_MESSAGE.append('ERROR, OBJECT EXIST, BUT IS NOT DIRECTORY')
      else:
        DIRECTORY_PREPARED == True
    
    if DIRECTORY_PREPARED == True:
      NEXT_FUNCTION = update_3_download
    
    return [DIRECTORY_PREPARED, NEXT_FUNCTION, OUTPUT_MESSAGE, DOWNLOAD_DIRECTORY]
  
  #
  # UPDATE - DOWNLOAD (new file from URL)
  # 
  
  def update_3_download(OUTPUT_MESSAGE, DOWNLOAD_DIRECTORY, ARCHIVE_FILE, DOWNLOAD_URL):
    import urllib.request
    
    DOWNLOAD_PREPARED = False
    NEXT_FUNCTION     = pass
    
    DOWNLOAD_FILE     = os.path.join(DOWNLOAD_DIRECTORY, ARCHIVE_FILE)
    
    with urllib.request.urlopen(DOWNLOAD_URL) as response, open(DOWNLOAD_FILE, 'wb') as OUT_FILE:
        shutil.copyfileobj(response, OUT_FILE)
      OUT_FILE.close()
      DOWNLOAD_PREPARED = True
      DOWNLOAD_RESULT   = 'SUCCESSFUL'
    except (urllib.error.URLerror, urllib.error.ContentTooShortError()) as ERROR:
      DOWNLOAD_RESULT = 'FAILED'
    
    DOWNLOAD_RESULT = 'DOWNLOAD STATUS : %' % DOWNLOAD_RESULT
    OUTPUT_MESSAGE.append(DOWNLOAD_RESULT)
    
    if DOWNLOAD_PREPARED == False:
      OUTPUT_MESSAGE.append('ERROR : %s' % ERROR.__dict__)
    else:
      NEXT_FUNCTION = update_4_extract
    
    return [DOWNLOAD_PREPARED, NEXT_FUNCTION, OUTPUT_MESSAGE]
  
  #
  # UPDATE - EXTRACT ARCHIVE (from downloaded file)
  #
  
  def update_4_extract(OUTPUT_MESSAGE, DOWNLOAD_DIRECTORY, ARCHIVE_FILE):
    EXTRACT_PREPARED = False
    NEXT_FUNCTION    = pass
    
    os.chdir(DOWNLOAD_DIRECTORY)
    
    try:
      OUTPUT_MESSAGE.append('EXTRACT FILE    : %' % ARCHIVE_FILE)
      EXTRACT_FILE = tarfile.open(ARCHIVE_FILE)
      for EXTRACT_OUTPUT in extract_me.extractall():
        OUTPUT_MESSAGE.append('EXTRACTING .... : %s' % EXTRACT_OUTPUT)
      EXTRACT_PREPARED = True
      EXTRACT_RESULT   = 'SUCCESSFUL'
    except (TarError, ReadError, CompressionError, StreamError, ExtractError, HeaderError) as ERROR:
      EXTRACT_RESULT = 'FAILED'
    
    OUTPUT_MESSAGE.append('EXTRACT RESULT  : %' % EXTRACT_RESULT)
    
    if EXTRACT_PREPARED == False:
      OUTPUT_MESSAGE.append('ERROR : %s' % ERROR.__dict__)
    else:
      NEXT_FUNCTION = update_5_verify_signature
    
    return [EXTRACT_PREPARED, NEXT_FUNCTION, OUTPUT_MESSAGE]
  
  #
  # UPDATE - VERIFY FILE (SIGNATURE)
  #
  
  def update_5_verify_signature(OUTPUT_MESSAGE, DOWNLOAD_DIRECTORY, EXTRACT_SUBDIRECTORY):
    global SCRIPT_FILE, SCRIPT_FILE_SIG, PUBLIC_KEY
    
    VERIFY_SUCCESSFUL   = False
    NEXT_FUNCTION       = pass
    
    NEW_FILE            = os.path.join(DOWNLOAD_DIRECTORY, EXTRACT_SUBDIRECTORY, SCRIPT_FILE)
    NEW_FILE_SIGNATURE  = os.path.join(DOWNLOAD_DIRECTORY, EXTRACT_SUBDIRECTORY, SCRIPT_FILE_SIG)
    
    GPG                 = gnupg.GPG()
    PUBLIC_KEY_INTERNAL = GPG.import_keys(PUBLIC_KEY)
    
    VERIFICATION_RESULT = 'FAILED'
    
    try:
      with open(NEW_FILE_SIGNATURE, 'rb') as SIGNATURE_FILE:
        VERIFY_RESULT = GPG.verify_file(SIGNATURE_FILE, '%s' % NEW_FILE)
      SIGNATURE_FILE.close()
    finally:
      if VERIFY_RESULT:
        CONTENT_PUBLIC_KEY        = PUBLIC_KEY_INTERNAL.__dict__
        CONTENT_NEW_FILE          = VERIFY_RESULT.__dict__
        FINGERPRINT_PUBLIC_KEY    = str(CONTENT_PUBLIC_KEY['results'][0]['fingerprint'])
        FINGERPRINT_VERIFIED_FILE = str(CONTENT_NEW_FILE['fingerprint'])
        if FINGERPRINT_PUBLIC_KEY == FINGERPRINT_VERIFIED_FILE:
          VERIFICATION_RESULT  = 'SUCCESSFUL'
          VERIFY_SUCCESSFUL    = True
          NEXT_FUNCTION        = update_6_install
        else:
          OUTPUT_MESSAGE.append('VERIFICATION    : Signature does not match')
    
    OUTPUT_MESSAGE.append('VERIFICATION    : %s' % VERIFICATION_RESULT)
    
    del GPG
    del PUBLIC_KEY_INTERNAL
    del CONTENT_PUBLIC_KEY
    del CONTENT_NEW_FILE

    return [VERIFY_SUCCESSFUL, NEXT_FUNCTION, OUTPUT_MESSAGE, NEW_FILE]
  
  #
  # UPDATE - INSTALL NEW FILE
  #
  
  def update_6_install(OUTPUT_MESSAGE, INSTALL_FILE):
    global SCRIPT_FILE
    
    INSTALLATION_SUCCESSFUL = False
    INSTALLATION_RESULT     = 'FAILED'
    
    DESTINATION_DIRECTORY  = weechat.string_eval_path_home('%h', {}, {}, {})
    DESTINATION_DIRECTORY  = str(os.path.join(DESTINATION_DIRECTORY, 'python'))
    DESTINATION_FILE       = str(os.path.join(DESTINATION_DIRECTORY, SCRIPT_FILE))
    SOURCE_FILE            = str(os.path.join(INSTALL_FILE)
    
    try:
      COPY_RESULT = shutil.copyfile(SOURCE_FILE, DESTINATION_FILE, follow_symlinks=True)
      INSTALLATION_SUCCESSFUL = True
      INSTALLATION_RESULT     = 'SUCCESSFUL'
    except (OSError, shutil.SameFileError) as ERROR:
      pass
    
    OUTPUT_MESSAGE.append('INSTALLATION    : %s' % INSTALLATION_RESULT)
    
    if INSTALLATION_SUCCESSFUL == False:
      OUTPUT_MESSAGE.append('ERROR : %s' % ERROR.__dict__)
    
    return [INSTALLATION_SUCCESSFUL, NEXT_FUNCTION, OUTPUT_MESSAGE]
  
  #
  ##### END FUNCTION CHECK AND UPDATE