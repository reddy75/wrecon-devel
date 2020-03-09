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
# - shutil, string, sys, tarfile, time, urllib, uuid
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
for IMPORT_MOD in ['ast', 'base64', 'contextlib', 'datetime', 'gnupg', 'hashlib', 'json', 'os', 'random', 'shutil', 'string', 'sys', 'tarfile', 'time', 'urllib', 'uuid', 'weechat']:
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

  #####
  #
  # FUNCTION FOR GENERATING RANDOM CHARACTERS AND NUMBERS
  
  def get_random_string(STRING_LENGTH):
    STR_LETTERS_AND_DIGITS = string.ascii_letters + string.digits
    
    return ''.join(random.choice(STR_LETTERS_AND_DIGITS) for INDEX in range(STRING_LENGTH))
  
  #
  ##### END FUNCTION FOR GENERATING RANDOM CHARACTERS AND NUMBERS
  
  #####
  #
  # FUNCTION GET HASH OF A STRING
  
  def get_hash(INPUT_STRING):
    RESULT = hashlib.md5(INPUT_STRING.encode())
    
    return str(RESULT.hexdigest())
  
  #
  ##### END FUNCTION GET HASH OF A STRING
  
  #####
  #
  # FUNCTION FOR COUNTING COMMANDS AND ADD UNIQ HASH
  
  def get_command_uniq_id():
    global WRECON_COMMAND_COUNTER
    WRECON_COMMAND_COUNTER = WRECON_COMMAND_COUNTER + 1
    
    if WRECON_COMMAND_COUNTER > 9999:
      WRECON_COMMAND_COUNTER = 0
    
    return '%04d-%s' % (WRECON_COMMAND_COUNTER, get_random_string(4))
  
  #
  ##### END FUNCTION FOR COUNTING COMMANDS AND ADD UNIQ HASH
  
  #####
  #
  # FUNCTION GET STATUS NICK
  # Will check my nick is operator, if yes, it will return 1, else 0
  
  def get_status_nick(SERVER_NAME, CHANNEL_NAME):
  
    RESULT_NICK    = 0
    
    # Get name of our nick
    MY_NICK_NAME   = weechat.info_get('irc_nick', SERVER_NAME)
    INFOLIST       = weechat.infolist_get('irc_nick', '', '%s,%s' % (SERVER_NAME, CHANNEL_NAME))
    
    while weechat.infolist_next(INFOLIST):
      FOUND_NICK_NAME = weechat.infolist_string(INFOLIST, 'name')
      if MY_NICK_NAME == FOUND_NICK_NAME:
        NICK_PREFIX   = weechat.infolist_string(INFOLIST, 'prefix')
        NICK_PREFIXES = weechat.infolist_string(INFOLIST, 'prefixes')
        if '@' in NICK_PREFIXES:
          RESULT_NICK = 1
    weechat.infolist_free(INFOLIST)
    
    return RESULT_NICK
  
  #
  ##### END FUNCTION GET STATUS NICK
  
  #####
  #
  # FUNCTION FOR VERIFY CHANNEL SETUP AND POSSIBILITY TO CHANGE MODE IF NECESSARY
  
  def setup_channel_2_mode(DATA, BUFFER, SERVER_NAME, CHANNEL_NAME):
    global WRECON_CHANNEL_KEY

    RESULT         = 0
    RESULT_CHANNEL = 0
    RESULT_MODE    = 0
    
    RESULT_NICK    = get_status_nick(SERVER_NAME, CHANNEL_NAME)

    INFOLIST   = weechat.infolist_get('irc_channel', '', '%s,%s' % (SERVER_NAME, CHANNEL_NAME))
    while weechat.infolist_next(INFOLIST):
      FOUND_CHANNEL_NAME = weechat.infolist_string(INFOLIST, 'name')
      FOUND_CHANNEL_KEY  = weechat.infolist_string(INFOLIST, 'key')
      FOUND_CHANNEL_MODE = weechat.infolist_string(INFOLIST, 'modes')
      if FOUND_CHANNEL_NAME == CHANNEL_NAME:
        if not WRECON_CHANNEL_KEY in FOUND_CHANNEL_MODE:
          RESULT_CHANNEL = 1
        if not 'k' in FOUND_CHANNEL_MODE:
          RESULT_MODE    = 1
        
    weechat.infolist_free(INFOLIST)
    
    if RESULT_NICK == 1:
      if RESULT_MODE == 1 or RESULT_CHANNEL == 1:
        weechat.command(BUFFER, '/mode %s -n+sk %s' % (CHANNEL_NAME, WRECON_CHANNEL_KEY))
    
    return RESULT
  
  #
  ##### END FUNCTION FOR VERIFY CHANNEL SETUP AND POSSIBILITY TO CHANGE MODE IF NECESSARY
  
  #####
  #
  # FUNCTION ENCRYPT AND DECTRYPT STRING, CORRECT LENGTH OF KEY, REVERT STRING
  
  #
  # ENCRYPT
  #
  
  global ENCRYPT_LEVEL
  ENCRYPT_LEVEL = {}
  
  def string_encrypt(LEVEL, INPUT_STRING, INPUT_KEY, INPUT_KEY2):
    global ENCRYPT_LEVEL
    return ENCRYPT_LEVEL[LEVEL](INPUT_STRING, INPUT_KEY, INPUT_KEY2)

  def string_encrypt_function(INPUT_STRING, INPUT_KEY):
    INPUT_KEY   = string_correct_key_length(INPUT_STRING, INPUT_KEY)
    OUTPUT_LIST = []
    
    for INDEX in range(len(INPUT_STRING)):
      KEY_CHAR    = INPUT_STRING[INDEX % len(INPUT_STRING)]
      OUTPUT_CHAR = chr((ord(INPUT_KEY[INDEX]) + ord(KEY_CHAR)) % 256)
      OUTPUT_LIST.append(OUTPUT_CHAR)
    
    OUTPUT_LIST = ''.join(OUTPUT_LIST)
    
    return OUTPUT_LIST
    
  def string_encrypt_level_0(INPUT_STRING, INPUT_KEY, NULL):
    OUTPUT_LIST = string_encrypt_function(INPUT_STRING, INPUT_KEY)
    
    OUTPUT_RESULT = base64.b64encode(OUTPUT_LIST.encode()).decode()
    
    return OUTPUT_RESULT
  
  def string_encrypt_level_1(INPUT_STRING, INPUT_KEY, NULL):
    NEW_INPUT_KEY         = get_hash(INPUT_KEY)
    SALT_STRING           = get_random_string(8)
    OUTPUT_RESULT_LEVEL_1 = str(string_encrypt_function(INPUT_STRING, SALT_STRING + INPUT_KEY))
    OUTPUT_RESULT_LEVEL_2 = string_encrypt_function(SALT_STRING + OUTPUT_RESULT_LEVEL_1, NEW_INPUT_KEY)
    
    OUTPUT_RESULT         = base64.b64encode(OUTPUT_RESULT_LEVEL_2.encode()).decode()
    
    return OUTPUT_RESULT
  
  def string_encrypt_level_2(INPUT_STRING, INPUT_KEY, INPUT_KEY2):
    INPUT_STRING          = string_reverse(INPUT_STRING)
    INPUT_KEY             = string_join_keys(INPUT_KEY2, INPUT_KEY)
    NEW_INPUT_KEY         = get_hash(INPUT_KEY)
    SALT_STRING           = get_random_string(8)
    OUTPUT_RESULT_LEVEL_1 = str(string_encrypt_function(INPUT_STRING, SALT_STRING + INPUT_KEY))
    OUTPUT_RESULT_LEVEL_2 = string_encrypt_function(SALT_STRING + OUTPUT_RESULT_LEVEL_1, NEW_INPUT_KEY)
    
    OUTPUT_RESULT         = base64.b64encode(OUTPUT_RESULT_LEVEL_2.encode()).decode()
    
    return OUTPUT_RESULT
  
  ENCRYPT_LEVEL[0] = string_encrypt_level_0
  ENCRYPT_LEVEL[1] = string_encrypt_level_1
  ENCRYPT_LEVEL[2] = string_encrypt_level_2
  
  #
  # DECRYPT
  #
  
  global DECRYPT_LEVEL
  DECRYPT_LEVEL = {}
  
  def string_decrypt(LEVEL, INPUT_STRING, INPUT_KEY, INPUT_KEY2):
    global DECRYPT_LEVEL
    
    return DECRYPT_LEVEL[LEVEL](INPUT_STRING, INPUT_KEY, INPUT_KEY2)
  
  def string_decrypt_function(INPUT_STRING, INPUT_KEY):
    INPUT_KEY     = string_correct_key_length(INPUT_STRING, INPUT_KEY)
    OUTPUT_LIST   = []
    
    for INDEX in range(len(INPUT_STRING)):
      KEY_CHAR = INPUT_KEY[INDEX % len(INPUT_KEY)]
      OUTPUT_CHAR = chr((256 + ord(INPUT_STRING[INDEX]) - ord(KEY_CHAR)) % 256)
      OUTPUT_LIST.append(OUTPUT_CHAR)
    
    OUTPUT_LIST = ''.join(OUTPUT_LIST)
    
    return OUTPUT_LIST
  
  def string_decrypt_level_0(INPUT_STRING, INPUT_KEY, NULL):
    DECODE_STRING = base64.b64decode(INPUT_STRING).decode()
    
    OUTPUT_RESULT = string_decrypt_function(DECODE_STRING, INPUT_KEY)
    
    return OUTPUT_RESULT
  
  def string_decrypt_level_1(INPUT_STRING, INPUT_KEY, NULL):
    DECODE_STRING         = base64.b64decode(INPUT_STRING).decode()
    NEW_INPUT_KEY         = get_hash(INPUT_KEY)
    OUTPUT_RESULT_LEVEL_2 = string_decrypt_function(DECODE_STRING, NEW_INPUT_KEY)
    SALT_STRING           = OUTPUT_RESULT_LEVEL_2[:8]
    OUTPUT_RESULT_LEVEL_1 = string_decrypt_function(OUTPUT_RESULT_LEVEL_2[8:], SALT_STRING + INPUT_KEY)
    
    return OUTPUT_RESULT_LEVEL_1
  
  def string_decrypt_level_2(INPUT_STRING, INPUT_KEY, INPUT_KEY2):
    DECODE_STRING         = base64.b64decode(INPUT_STRING).decode()
    
    INPUT_KEY             = string_join_keys(INPUT_KEY2, INPUT_KEY)
    NEW_INPUT_KEY         = get_hash(INPUT_KEY)
    
    OUTPUT_RESULT_LEVEL_2 = string_decrypt_function(DECODE_STRING, NEW_INPUT_KEY)
    SALT_STRING           = OUTPUT_RESULT_LEVEL_2[:8]
    
    OUTPUT_RESULT_LEVEL_1 = string_decrypt_function(OUTPUT_RESULT_LEVEL_2[8:], SALT_STRING + INPUT_KEY)
    
    DECODE_STRING         = string_reverse(OUTPUT_RESULT_LEVEL_1)
    return DECODE_STRING
    
  DECRYPT_LEVEL[0] = string_decrypt_level_0
  DECRYPT_LEVEL[1] = string_decrypt_level_1
  DECRYPT_LEVEL[2] = string_decrypt_level_2
  
  #
  # CORRECT LENGTH OF KEY
  #

  def string_correct_key_length(INPUT_STRING, INPUT_KEY):
    OUTPUT_KEY = INPUT_KEY
    
    while len(INPUT_STRING) > len(OUTPUT_KEY):
      OUTPUT_KEY += INPUT_KEY
    
    return OUTPUT_KEY
  
  #
  # REVERSE STRING
  #
  
  def string_reverse(INPUT_STRING):
    OUTPUT_STRING = ''
    
    for INDEX in range(len(INPUT_STRING)):
      OUTPUT_STRING = INPUT_STRING[INDEX] + OUTPUT_STRING
    
    return OUTPUT_STRING
  
  #
  # JOIN KEYS
  #
  
  def string_join_keys(INPUT_KEY1, INPUT_KEY2):
    OUTPUT_KEY   = ''
    INDEX_KEY1   = 0
    INDEX_KEY2   = 0
    
    for INDEX in range(len(INPUT_KEY1 + INPUT_KEY2)):
      OUTPUT_KEY = OUTPUT_KEY + INPUT_KEY1[INDEX_KEY1] + INPUT_KEY2[INDEX_KEY2]
      INDEX_KEY1 += 1
      INDEX_KEY2 += 1
      
      if INDEX_KEY1 >= len(INPUT_KEY1):
        INDEX_KEY1 = 0
      
      if INDEX_KEY2 >= len(INPUT_KEY2):
        INDEX_KEY2 = 0
    
    return OUTPUT_KEY
  
  #
  #### END FUNCFUNCTION ENCRYPT AND DECTRYPT STRING, CORRECT LENGTH OF KEY, REVERT STRING

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
    
    display_message(BUFFER, OUTPUT_MESSAGE)
    
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
    NEXT_FUNCTION  = ''
    
    LATEST_RELEASE, ARCHIVE_FILE, DOWNLOAD_URL, EXTRACT_SUBDIRECTORY  = ['', '', '', '']

    ACTUAL_VERSION = SCRIPT_VERSION.split(' ')[0]
    BASE_URL       = 'https://github.com/%s/archive' % SCRIPT_BASE_NAME
    BASE_API_URL   = 'https://api.github.com/repos/%s/releases/latest' % SCRIPT_BASE_NAME
    
    OUTPUT_MESSAGE.append('ACTUAL VERSION  : %s' % ACTUAL_VERSION)
    OUTPUT_MESSAGE.append('REQUESTING URL  : %s' % BASE_API_URL)
    
    ERROR_GET = False
    try:
      URL_DATA = urllib.request.urlopen(BASE_API_URL)
    except (urllib.error.HTTPError, urllib.error.ContentTooShortError, OSError) as ERROR:
      ERROR_GET  = True
      ERROR_DATA = ERROR.__dict__
    
    if ERROR_GET == True:
      OUTPUT_MESSAGE.append('AN ERROR OCCURED DURING CHECK OF LATEST VERSION FROM GITHUB')
      if 'code' in ERROR_DATA and 'msg' in ERROR_DATA:
        OUTPUT_MESSAGE.append('ERROR CODE    : %s' % ERROR_DATA['code'])
        OUTPUT_MESSAGE.append('ERROR MESSAGE : %s' % ERROR_DATA['msg'])
      # ~ for KEY in ERROR_DATA:
        # ~ OUTPUT_MESSAGE.append('ERROR DATA    : %10s : %s' % (KEY, ERROR_DATA[KEY]))
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
    NEXT_FUNCTION         = ''
    
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
    NEXT_FUNCTION     = ''
    
    DOWNLOAD_FILE     = os.path.join(DOWNLOAD_DIRECTORY, ARCHIVE_FILE)
    
    try:
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
    NEXT_FUNCTION    = ''
    
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
    NEXT_FUNCTION       = ''
    
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
    SOURCE_FILE            = str(os.path.join(INSTALL_FILE))
    
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
  
  #####
  #
  # FUNCTION GET BUFFERS AND BUFFER OF REGISTERED CHANNEL
  
  def get_buffers():
    WRECON_BUFFERS  = {}
    INFOLIST_BUFFER = weechat.infolist_get('BUFFER', '', '')
    while weechat.infolist_next(INFOLIST_BUFFER):
      BUFFER_POINTER              = weechat.infolist_pointer(INFOLIST_BUFFER, 'pointer')
      BUFFER_NAME                 = weechat.buffer_get_string(BUFFER_POINTER, 'localvar_name')
      WRECON_BUFFERS[BUFFER_NAME] = BUFFER_POINTER
    weechat.infolist_free(INFOLIST_BUFFER)
    return WRECON_BUFFERS
  
  def get_buffer_channel():
    global WRECON_SERVER, WRECON_CHANNEL
    WRECON_BUFFER_NAME = '%s.%s' % (WRECON_SERVER, WRECON_CHANNEL)
    WRECON_BUFFERS     = get_buffers()
    if WRECON_BUFFER_NAME in WRECON_BUFFERS:
      return WRECON_BUFFERS[WRECON_BUFFER_NAME]
    else:
      return ''
  
  #
  ##### END FUNCTION GET BUFFERS AND BUFFER OF REGISTERED CHANNEL
  
  #####
  #
  # FUNCTION STATUS CHANNEL
  # We need to know how many users are joined
  
  def get_status_channel():
    global WRECON_SERVER, WRECON_CHANNEL
    INFOLIST_CHANNEL  = weechat.infolist_get('irc_channel', '', WRECON_SERVER)
    CHANNEL_STATUS    = {}
    DO_RECORD         = False
    while weechat.infolist_next(INFOLIST_CHANNEL):
      CHANNEL_FIELDS = weechat.infolist_fields(INFOLIST_CHANNEL).split(",")
      for CHANNEL_FIELD in CHANNEL_FIELDS:
        (CHANNEL_FIELD_TYPE, CHANNEL_FIELD_NAME) = CHANNEL_FIELD.split(':', 1)
        if CHANNEL_FIELD_TYPE == 'INDEX':
          CHANNEL_FIELD_VALUE = weechat.infolist_integer(INFOLIST_CHANNEL, CHANNEL_FIELD_NAME)
        elif CHANNEL_FIELD_TYPE == 'p':
          CHANNEL_FIELD_VALUE = weechat.infolist_pointer(INFOLIST_CHANNEL, CHANNEL_FIELD_NAME)
        elif CHANNEL_FIELD_TYPE == 's':
          CHANNEL_FIELD_VALUE = weechat.infolist_string(INFOLIST_CHANNEL, CHANNEL_FIELD_NAME)
        elif CHANNEL_FIELD_TYPE == 'b':
          CHANNEL_FIELD_VALUE = weechat.infolist_buffer(INFOLIST_CHANNEL, CHANNEL_FIELD_NAME)
        elif CHANNEL_FIELD_TYPE == 't':
          CHANNEL_FIELD_VALUE = weechat.infolist_time(INFOLIST_CHANNEL, CHANNEL_FIELD_NAME)
        else:
          CHANNEL_FIELD_VALUE = 'N/A'
        if CHANNEL_FIELD_NAME == 'buffer_short_name' and CHANNEL_FIELD_VALUE == WRECON_CHANNEL:
          DO_RECORD = True
        elif CHANNEL_FIELD_NAME == 'buffer_short_name' and CHANNEL_FIELD_VALUE != WRECON_CHANNEL:
          DO_RECORD = False
        if DO_RECORD == True:
          CHANNEL_STATUS[CHANNEL_FIELD_NAME] = CHANNEL_FIELD_VALUE
    weechat.infolist_free(INFOLIST_CHANNEL)

    if 'nicks_count' in CHANNEL_STATUS:
      return CHANNEL_STATUS['nicks_count']
    else:
      return 0
  #
  ##### END FUNCTION STATUS CHANNEL
  
  #####
  #
  # HOOK AND UNHOOK BUFFER
  
  def hook_buffer():
    global SCRIPT_CALLBACK_BUFFER, WRECON_BUFFER_HOOKED, WRECON_HOOK_BUFFER, WRECON_BUFFER_CHANNEL
    WRECON_BUFFER_CHANNEL = get_buffer_channel()
    
    if WRECON_BUFFER_HOOKED == False:
      if WRECON_BUFFER_CHANNEL:
        WRECON_BUFFER_HOOKED = True
        WRECON_HOOK_BUFFER   = weechat.hook_print(WRECON_BUFFER_CHANNEL, '', COMMAND_IN_BUFFER, 1, SCRIPT_CALLBACK_BUFFER, '')
    
    return weechat.WEECHAT_RC_OK
  
  def unhook_buffer():
    global WRECON_BUFFER_HOOKED, WRECON_HOOK_BUFFER
    
    if WRECON_BUFFER_HOOKED == True:
      WRECON_BUFFER_HOOKED = False
      weechat.unhook(WRECON_HOOK_BUFFER)
    
    return weechat.WEECHAT_RC_OK
  
  #
  ##### END HOOK AND UNHOOK BUFFER
  
  #####
  #
  # HOOK USER COMMAND
  
  def hook_command_from_user(WEECHAT_DATA, BUFFER, DATA):
    
    COMMAND_ID = get_command_uniq_id()
    
    if not DATA:
      display_message(BUFFER, '[%s] ERROR: MISSING COMMAND' % COMMAND_ID)
    else:
      global ID_CALL_LOCAL, WRECON_BOT_ID, DISPLAY_COMMAND
      
      UNIQ_COMMAND_ID                  = WRECON_BOT_ID + COMMAND_ID
      DISPLAY_COMMAND[UNIQ_COMMAND_ID] = ''
      
      ARGUMENTS = DATA.split(None, 1)
      COMMAND = ARGUMENTS[0].upper()
      ARGUMENTS.pop(0)
      
      if not ARGUMENTS:
        COMMAND_ARGUMENTS      = ''
        COMMAND_ARGUMENTS_LIST = []
      else:
        COMMAND_ARGUMENTS      = ARGUMENTS[0]
        COMMAND_ARGUMENTS_LIST = COMMAND_ARGUMENTS.split(' ')
        
      ID_CALL_LOCAL[COMMAND_ID] = [COMMAND, COMMAND_ARGUMENTS_LIST]
      
      EXECUTE_COMMAND = validate_command(WEECHAT_DATA, BUFFER, 'LOCAL', COMMAND, WRECON_BOT_ID, WRECON_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS)
    
    return weechat.WEECHAT_RC_OK
  
  SCRIPT_CALLBACK = 'hook_command_from_user'
  
  #
  ##### END HOOK USER COMMAND
  
  #####
  #
  # PARSING BUFFER REPLY (COMMAND)
  
  def hook_command_from_buffer(WEECHAT_DATA, BUFFER, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, DATA):
    global ID_CALL_REMOTE, SCRIPT_BUFFER_CALL
    ARGUMENTS   = DATA.split()
    COMMAND     = ARGUMENTS[0]
    
    ARGUMENTS.pop(0)
    TO_BOT     = ARGUMENTS[0]
    FROM_BOT   = ARGUMENTS[1]
    COMMAND_ID = ARGUMENTS[2]
    
    ARGUMENTS.pop(0)
    ARGUMENTS.pop(0)
    ARGUMENTS.pop(0)
    
    if not ARGUMENTS:
      COMMAND_ARGUMENTS      = ''
      COMMAND_ARGUMENTS_LIST = []
    else:
      COMMAND_ARGUMENTS      = ARGUMENTS[0]
      COMMAND_ARGUMENTS_LIST = COMMAND_ARGUMENTS.split(' ')
    
    UNIQ_COMMAND_ID                 = FROM_BOT + COMMAND_ID
    ID_CALL_REMOTE[UNIQ_COMMAND_ID] = [COMMAND, FROM_BOT, COMMAND_ID, COMMAND_ARGUMENTS_LIST]
    
    EXECUTE_ALLOWED, EXECUTE_FUNCTION = validate_command(WEECHAT_DATA, BUFFER, 'REMOTE', COMMAND, TO_BOT, FROM_BOT, COMMAND_ID, COMMAND_ARGUMENTS)
    
    if EXECUTE_ALLOWED == True:
      EXECUTE_FUNCTION(WEECHAT_DATA, BUFFER, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND_ARGUMENTS)
    
    return weechat.WEECHAT_RC_OK
  
  global SCRIPT_CALLBACK_BUFFER
  
  SCRIPT_CALLBACK_BUFFER = 'hook_command_from_buffer'
  
  #
  ##### END PARSING BUFFER REPLY
  
  #####
  #
  # UNHOOK WRECON
  
  def wrecon_unload():
    weechat.unhook_all()
    return weechat.WEECHAT_RC_OK
  
  #
  ##### END UNHOOK WRECON
  
  #####
  #
  # FUNCTION AUTOCONNECT SERVER / AUTOJOIN CHANNEL
  
  def autoconnect():
    global WRECON_SERVER, WRECON_CHANNEL
    if WRECON_SERVER and WRECON_CHANNEL:
      if get_status_server() == 0:
        autoconnect_1_server()
      else:
        BUFFER_SERVER = get_buffers()
        autojoin_1_channel(BUFFER_SERVER['server.%s' % (WRECON_SERVER)])
    return weechat.WEECHAT_RC_OK
  
  #
  # AUTOCONNECT - SERVER
  #
  
  def autoconnect_1_server():
    global WRECON_SERVER. TIMEOUT_CONNECT
    weechat.command('', '/connect %s' % (WRECON_SERVER))
    WRECON_HOOK_CONNECT_SERVER = weechat.hook_timer(1*1000, 0, TIMEOUT_CONNECT, 'autoconnect_2_server_status', '')
    return weechat.WEECHAT_RC_OK
  
  #
  # AUTOCONNECT - SERVER STATUS
  #
  
  def autoconnect_2_server_status(NULL, REMAINING_CALLS):
    global WRECON_SERVER
    if get_status_server() == 1:
      weechat.unhook(WRECON_HOOK_CONNECT_SERVER)
      WRECON_BUFFERS = get_buffers()
      autojoin_1_channel(WRECON_BUFFERS['server.%s' % (WRECON_SERVER)])
    else:
      if REMAINING_CALLS = 0:
        # THERE CAN BE NETWORK ISSUE, WE CAN TRY AGAIN AND AGAIN...
        weechat.unhook(WRECON_HOOK_CONNECT_SERVER)
        autoconnect_1_server():
    return weechat.WEECHAT_RC_OK
  
  #
  # AUTOJOIN - CHANNEL
  #
  
  def autojoin_1_channel(BUFFER):
    global WRECON_CHANNEL, WRECON_CHANNEL_KEY, WRECON_HOOK_JOIN, WRECON_SERVER, TIMEOUT_CONNECT
    weechat.command(BUFFER, '/join %s %s' % (WRECON_CHANNEL, WRECON_CHANNEL_KEY))
    WRECON_HOOK_JOIN = weechat.hook_timer(1*1000, 0, TIMEOUT_CONNECT, 'autojoin_2_channel_status', '')
    return weechat.WEECHAT_RC_OK
  
  #
  # AUTOJOIN - CHANNEL STATUS
  #
  
  def autojoin_2_channel_status(NULL, REMAINING_CALLS):
    global WRECON_HOOK_JOIN, WRECON_AUTO_ADVERTISED, WRECON_HOOK_BUFFER, WRECON_BUFFER_CHANNEL, SCRIPT_CALLBACK_BUFFER
    
    if REMAINING_CALLS == '0':
      global WRECON_CHANNEL
      weechat.unhook(WRECON_HOOK_JOIN)
      ERROR_MESSAGE     = ['ERROR DURING JOINING TO CHANNEL ' + WRECON_CHANNEL]
      ERROR_MESSAGE.append('CHANNEL IS INACCESSIBLE')
      ERROR_MESSAGE.append('')
      ERROR_MESSAGE.append('POSSIBLE REASONS:')
      ERROR_MESSAGE.append('- CHANNEL HAS BEEN RELEASED DUE TO ALL YOUR PARTICIPANTS LEFT CHANNEL, NOW OCCUPIED BY A FOREIGN')
      ERROR_MESSAGE.append('- YOUR CHANNEL KEY HAS BEEN CHANGED BY MISTAKE BY YOUR PARTICIPANT')
      ERROR_MESSAGE.append('- YOUR CHANNEL KEY HAS BEEN EXPOSED, OR STOLEN, THEN ABUSED TO EMBARRASS ACCESS')
      display_message('', ERROR_MESSAGE)
    
    if get_status_channel() > 0:
      weechat.unhook(WRECON_HOOK_JOIN)
      if WRECON_AUTO_ADVERTISED == False:
        hook_buffer()
        setup_channel(WRECON_BUFFER_CHANNEL)
        # ~ command_advertise('', WRECON_BUFFER_CHANNEL, '', '')
        # ~ WRECON_AUTO_ADVERTISED = True
    return weechat.WEECHAT_RC_OK

  #
  ##### END FUNCTION AUTOCONNECT SERVER / AUTOJOIN CHANNEL
  
  #####
  #
  # FUNCTION SETUP CHANNEL (title of BUFFER, and mode of channel)
  
  def setup_channel(BUFFER):
    global WRECON_CHANNEL, WRECON_CHANNEL_KEY, WRECON_SERVER
    setup_channel_1_title_of_buffer(BUFFER, WRECON_SERVER, WRECON_CHANNEL)
    setup_channel_2_mode('', BUFFER, WRECON_SERVER, WRECON_CHANNEL)
    return weechat.WEECHAT_RC_OK
  
  #
  ##### END FUNCTION SETUP CHANNEL  

  #####
  #
  # FUNCTION CHANGE BUFFER TITLE
  
  def setup_channel_1_title_of_buffer(BUFFER, WRECON_SERVER, WRECON_CHANNEL):
    global WRECON_BOT_NAME, WRECON_BOT_ID
    weechat.buffer_set(BUFFER, 'title', 'Weechat Remote control - %s - %s - %s [%s]' % (WRECON_SERVER, WRECON_CHANNEL, WRECON_BOT_NAME, WRECON_BOT_ID))
    return weechat.WEECHAT_RC_OK
  
  #
  ##### END FUNCTION CHANGE BUFFER TITLE
  
  #####
  #
  # FUNCTION GET DEVICE SECRETS
  
  def get_device_seecrets():
    SECRET1 = str(os.path.expanduser('~'))
    SECRET2 = str(SECRET1.split('/')[-1])
    SECRET3 = str(uuid.uuid1(uuid.getnode(),0)[24:])
    SECRETS = get_hash(SECRET2 + SECRET3 + SECRET1)
    del SECRET1
    del SECRET2
    del SECRET3
    return str(SECRETS)
  
  #
  ##### END FUNCTION GET DEVICE SECRETS
  
  #####
  #
  # FUNCTION SETUP AUTOJOIN ADD / DEL (/ SAVE)
  
  global CALLBACK_SETUP_AUTOJOIN
  CALLBACK_SETUP_AUTOJOIN = {}
  
  def setup_autojoin(BUFFER, FUNCTION, WRECON_SERVER, WRECON_CHANNEL):
    global CALLBACK_SETUP_AUTOJOIN
    SAVE_SETUP = False
    
    # Check FUNCTION contain 'add' or 'del'
    if FUNCTION in CALLBACK_SETUP_AUTOJOIN:
      WEECHAT_SERVER_AUTOJOIN   = weechat.string_eval_expression("${irc.server.%s.autojoin}" % (WRECON_SERVER), {}, {}, {})
      WEECHAT_CHANNELS_AUTOJOIN = WEECHAT_SERVER_AUTOJOIN.split(' ')[0].split(',')
      WEECHAT_CHANNELS_KEYS     = WEECHAT_SERVER_AUTOJOIN.split(' ')[1].split(',')
      
      SAVE_SETUP, WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS = CALLBACK_SETUP_AUTOJOIN[FUNCTION](BUFFER, WRECON_SERVER, WRECON_CHANNEL, WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS)
      
      # SAVE data in case changes were done
      if SAVE_SETUP == True:
        EXPORT_CHANNELS = ','.join(map(str, WEECHAT_CHANNELS_AUTOJOIN))
        EXPORT_KEYS     = ','.join(map(str, WEECHAT_CHANNELS_KEYS))
        EXPORT_DATA     = '%s %s' % (EXPORT_CHANNELS, EXPORT_KEYS)
        weechat.command(BUFFER, '/set irc.server.%s.autojoin %s' % (WRECON_SERVER, EXPORT_DATA))
        weechat.command(BUFFER, '/save')
    
    return SAVE_SETUP
  
  #
  # FUNCTION SETUP AUTOJOIN ADD
  #
  
  def setup_autojoin_add(BUFFER, WRECON_SERVER, WRECON_CHANNEL, WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS):
    SAVE_SETUP         = False
    WRECON_CHANNEL_KEY = '${sec.data.wrecon_channel_key}'
    
    WEECHAT_SERVER_AUTOCONNECT   = weechat.string_eval_expression("${irc.server.%s.autoconnect}" % (WRECON_SERVER), {}, {}, {})
    WEECHAT_SERVER_AUTORECONNECT = weechat.string_eval_expression("${irc.server.%s.autoreconnect}" % (WRECON_SERVER), {}, {}, {})
    WEECHAT_CHANNEL_AUTOREJOIN   = weechat.string_eval_expression("${irc.server.%s.autorejoin}" % (WRECON_SERVER), {}, {}, {})
    
    if WEECHAT_SERVER_AUTOCONNECT != 'on':
      weechat.command(BUFFER, '/set irc.server.%s.autoconnect on' % (WRECON_SERVER))
      SAVE_SETUP = True
    
    if WEECHAT_SERVER_AUTORECONNECT != 'on':
      weechat.command(BUFFER, '/set irc.server.%s.autoreconnect on' % (WRECON_SERVER))
      SAVE_SETUP = True
    
    if WEECHAT_CHANNEL_AUTOREJOIN != 'on':
      weechat.command(BUFFER, '/set irc.server.%s.autorejoin on' % (WRECON_SERVER))
      SAVE_SETUP = True
    
    if not WRECON_CHANNEL in WEECHAT_CHANNELS_AUTOJOIN:
      WEECHAT_CHANNELS_AUTOJOIN.append(WRECON_CHANNEL)
      WEECHAT_CHANNELS_KEYS.append(WRECON_CHANNEL_KEY)
      SAVE_SETUP = True
    else:
      # Find index of my registered channel and test it have same setup of secure key
      CHANNEL_INDEX = [INDEX for INDEX, ELEMENT in enumerate(WEECHAT_CHANNELS_AUTOJOIN) if WRECON_CHANNEL in ELEMENT]
      for INDEX in CHANNEL_INDEX:
        if not WRECON_CHANNEL_KEY in WEECHAT_CHANNELS_KEYS[INDEX]:
          WEECHAT_CHANNELS_KEYS[INDEX] = WRECON_CHANNEL_KEY
          SAVE_SETUP = True

      return [SAVE_SETUP, WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS]
  
  #
  # FUNCTION SETUP AUTOJOIN DEL
  #
  
  def setup_autojoin_del(NULL, NULL, WRECON_CHANNEL, WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS):
    SAVE_SETUP = False
    
    if WRECON_CHANNEL in WEECHAT_CHANNELS_AUTOJOIN:
      # Find index of my registered channel
      CHANNEL_INDEX = [INDEX for INDEX, ELEMENT in enumerate(WEECHAT_CHANNELS_AUTOJOIN) if WRECON_CHANNEL in ELEMENT]
      for INDEX in CHANNEL_INDEX:
        del WEECHAT_CHANNELS_AUTOJOIN[INDEX]
        del WEECHAT_CHANNELS_KEYS[INDEX]
      SAVE_SETUP = True
    
    return [SAVE_SETUP, WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS]
  
  CALLBACK_SETUP_AUTOJOIN['add'] = setup_autojoin_add
  CALLBACK_SETUP_AUTOJOIN['del'] = setup_autojoin_del
  
  #
  ###### END FUNCTION SETUP AUTOJOIN ADD / DEL (/ SAVE)
  
  ######
  #
  # SETUP BASIC GLOBAL VARIABLES FOR WRECON - BOT, SERVER, CHANNEL etc.
  #
  
  def setup_wrecon_variables(BUFFER):
  
  #
  # SETUP VARIABLES OF BOT
  #

    global WRECON_DEFAULT_BOTNAMES, WRECON_BOT_NAME, WRECON_BOT_ID, WRECON_BOT_KEY
    
    WRECON_DEFAULT_BOTNAMES = ['anee', 'anet', 'ann', 'annee', 'annet', 'bob', 'brad', 'don', 'fred', 'freddie', 'john', 'mia', 'moon', 'pooh', 'red', 'ron', 'ronnie', 'shark', 'ted', 'teddy', 'zed', 'zoe', 'zombie']
    WRECON_BOT_NAME         = weechat.string_eval_expression("${sec.data.wrecon_bot_name}",{},{},{})
    WRECON_BOT_ID           = weechat.string_eval_expression("${sec.data.wrecon_bot_id}",{},{},{})
    WRECON_BOT_KEY          = weechat.string_eval_expression("${sec.data.wrecon_bot_key}",{},{},{})
  
    # Choice default BOT NAME if not exist and save it
    
    if not WRECON_BOT_NAME:
      WRECON_BOT_NAME = random.choice(WRECON_DEFAULT_BOTNAMES)
      weechat.command(BUFFER, '/secure set wrecon_bot_name %s' % (WRECON_BOT_NAME))
    
    #  Generate BOT ID if not exit and save it
    
    if not WRECON_BOT_ID:
      WRECON_BOT_ID = f_random_generator(16)
      weechat.command(BUFFER, '/secure set wrecon_bot_id %s' % (WRECON_BOT_ID))
    
    # Generate BOT KEY if not exist and save it
    
    if not WRECON_BOT_KEY:
      WRECON_BOT_KEY = f_random_generator(64)
      weechat.command(BUFFER, '/secure set wrecon_bot_key %s' % (WRECON_BOT_KEY))
  
  #
  # SETUP VARIABLES OF SERVER
  #

    global WRECON_SERVER
    WRECON_SERVER = weechat.string_eval_expression("${sec.data.wrecon_server}",{},{},{})
    
  #
  # SETUP VARIABLES OF CHANNEL
  #

    global WRECON_CHANNEL, WRECON_CHANNEL_KEY, WRECON_CHANNEL_ENCRYPTION_KEY
    WRECON_CHANNEL                = weechat.string_eval_expression("${sec.data.wrecon_channel}",{},{},{})
    WRECON_CHANNEL_KEY            = weechat.string_eval_expression("${sec.data.wrecon_channel_key}",{},{},{})
    WRECON_CHANNEL_ENCRYPTION_KEY = weechat.string_eval_expression("${sec.data.wrecon_channel_encryption_key}",{},{},{})
  
  #
  # SETUP VARIABLES OF BUFFER
  #
  
    global WRECON_BUFFERS, WRECON_BUFFER_CHANNEL, WRECON_BUFFER_HOOKED
    WRECON_BUFFERS         = {}
    WRECON_BUFFER_CHANNEL  = ''
    WRECON_BUFFER_HOOKED   = False
  
  #
  # SETUP VARIABLES OF REMOTE BOTS
  #
  # CONTROL    - bots you can control remotely on remote system
  #              table contain BOT IDs and it's BOT KEYs
  #
  # GRANTED    - bots from remote system can control your system (you grant controol of your system)
  #              table contain only BOT IDs
  #
  # VERIFIED   - runtime variable of bots from remote system can control your system only after verification
  #              table contain BOT IDs and additional info from irc_channel of related NICK
  #              in case information of remote NICK will be changed, then new verification will be triggered
  #
  # ADVERTISED - runtime variable of bots which has been advertised in channel, it is only informational and for internal purpose to
  #              have actual state
  #              table contain BOT IDs and BOT NAMEs only

    global WRECON_REMOTE_BOTS_CONTROL, WRECON_REMOTE_BOTS_GRANTED, WRECON_REMOTE_BOTS_VERIFIED, WRECON_REMOTE_BOTS_ADVERTISED
    WRECON_REMOTE_BOTS_CONTROL    = weechat.string_eval_expression("${sec.data.wrecon_remote_bots_control}",{},{},{})
    WRECON_REMOTE_BOTS_GRANTED    = weechat.string_eval_expression("${sec.data.wrecon_remote_bots_granted}",{},{},{})
    WRECON_REMOTE_BOTS_VERIFIED   = {}
    WRECON_REMOTE_BOTS_ADVERTISED = {}
    
    if WRECON_REMOTE_BOTS_CONTROL:
      WRECON_REMOTE_BOTS_CONTROL = ast.literal_eval(WRECON_REMOTE_BOTS_CONTROL)
    else:
      WRECON_REMOTE_BOTS_CONTROL = {}
    
    if WRECON_REMOTE_BOTS_GRANTED:
      WRECON_REMOTE_BOTS_GRANTED = ast.literal_eval(WRECON_REMOTE_BOTS_GRANTED)
    else:
      WRECON_REMOTE_BOTS_GRANTED = {}

  #
  # SETUP VARIABLES OF COUNTER COMMAND AND AUTO ADVERTISE
  #
  
    global WRECON_COMMAND_COUNTER, WRECON_AUTO_ADVERTISED
    WRECON_COMMAND_COUNTER = 0
    WRECON_AUTO_ADVERTISED = False
  
  #
  # PUBLIC KEY
  #

    global PUBLIC_KEY
    PUBLIC_KEY  = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
KPX4rlTJFYD/K/Hb0OM4NwaXz5Q=
=FtIt
-----END PGP PUBLIC KEY BLOCK-----
    '''
  
  #
  # SETUP OF FUNCTIONAL VARIABLES
  #

    global SCRIPT_COMMAND_CALL, SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_CALLBACK, COLOR_TEXT, SCRIPT_ARGS_DESCRIPTION, COMMAND_IN_BUFFER, SCRIPT_BUFFER_CALL, TIMEOUT_COMMAND, COMMAND_VERSION
    SCRIPT_COMMAND_CALL     = {}
    SCRIPT_BUFFER_CALL      = {}
    SCRIPT_ARGS             = ''
    SCRIPT_ARGS_DESCRIPTION = ''
    SCRIPT_COMPLETION       = ''
    SCRIPT_CALLBACK         = ''
    COMMAND_IN_BUFFER       = 'WRECON-CMD>'
    COLOR_TEXT              = {
    'bold'       : weechat.color('bold'),
    'nbold'      : weechat.color('-bold'),
    'italic'     : weechat.color('italic'),
    'nitalic'    : weechat.color('-italic'),
    'underline'  : weechat.color('underline'),
    'nunderline' : weechat.color('-underline')}
    SCRIPT_ARGS_DESCRIPTION = '''
    %(bold)s%(underline)sWeechat Remote control (WRECON) commands and options:%(nunderline)s%(nbold)s
    ''' % COLOR_TEXT
    TIMEOUT_COMMAND         = 20
    TIMEOUT_CONNECT         = 30
    COMMAND_VERSION         = {}
  
  #
  # SETUP OF HOOK VARIABLES
  #

    global WRECON_HOOK_COMMAND, WRECON_HOOK_CONNECT, WRECON_HOOK_JOIN, WRECON_HOOK_BUFFER, WRECON_HOOK_LOCAL_COMMANDS
    WRECON_HOOK_COMMAND        = ''
    WRECON_HOOK_CONNECT        = ''
    WRECON_HOOK_JOIN           = ''
    WRECON_HOOK_BUFFER         = ''
    WRECON_HOOK_LOCAL_COMMANDS = ''
    
    return
  
  #
  ##### END SETUP BASIC GLOBAL VARIABLES FOR WRECON - BOT, SERVER, CHANNEL etc.

  #####
  #
  # VALIDATE COMMAND EXECUTION
  #
  # WEECHAT_DATA BUFFER LOCAL/REMOTE COMMAND TOBOTID FROMBOTID COMMANDID [DATA]
  
  global ID_CALL_LOCAL, ID_CALL_REMOTE, COMMAND_REQUIREMENTS, VERIFY_REQUIREMENTS, DISPLAY_COMMAND
  
  ID_CALL_LOCAL        = {}
  ID_CALL_REMOTE       = {}
  COMMAND_REQUIREMENTS = {}
  VERIFY_REQUIREMENTS  = {}
  DISPLAY_COMMAND      = {}
  
  def validate_command(WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TO_BOT, FROM_BOT, COMMAND_ID, COMMAND_ARGUMENTS):
    
    # FIRST WE CHECK COMMAND BELONG TO US OR ADVERTISEMENT WAS REQUESTED
    COMMAND_CAN_BE_EXECUTED = validate_command_1_check_bot(COMMAND, TO_BOT)
    
    # WE SIMPLY IGNORE COMMANDS NOT BELOG TO US
    # EXCEPTION REMOTE ADVERTISEMENT
    if COMMAND_CAN_BE_EXECUTED == False:
      FUNCTION = ''
    else:
    # HERE WE CONTINUE IF COMMAND BELONG TO US, OR ADVERTIESEMENT WAS REQUESTED
      global DISPLAY_COMMAND
      UNIQ_COMMAND_ID = FROM_BOT + COMMAND_ID
      
      # SOMETIME WE NEED DISPLAY WHAT IS CALLED (just only in first call)
      if UNIQ_COMMAND_ID in DISPLAY_COMMAND:
        display_message(BUFFER, '[%s] %s > %s %s' + (COMMAND_ID, FROM_BOT, COMMAND, COMMAND_ARGUMENTS))
        del DISPLAY_COMMAND[UNIQ_COMMAND_ID]
      
      # ASSIGN VARIABLES for LOCAL or REMOTE CALL
      ID_CALL, SCRIPT_CALL = validate_command_2_setup_variables(SOURCE)
          
      # CHECK WE HAVE ASSIGNED UNIQ_COMMAND_ID FROM CALL
      # This is security feature to block 'fake' execution
      if not UNIQ_COMMAND_ID in ID_CALL:
        COMMAND_CAN_BE_EXECUTED = False
        display_message(BUFFER, '[%s] ERROR: CALL ID NOT EXIST' % COMMAND_ID)

      # CHECK COMMAND EXIST
      if COMMAND_CAN_BE_EXECUTED == True and not COMMAND in SCRIPT_CALL:
        COMMAND_CAN_BE_EXECUTED = False
        display_message(BUFFER, '[%s] ERROR: UNKNOWN COMMAND -> %s' % (COMMAND_ID, COMMAND))
      
      # CHECK REQUIREMENTS FOR EXECUTION
      if COMMAND_CAN_BE_EXECUTED == True:
        global COMMAND_REQUIREMENTS
        if COMMAND in COMMAND_REQUIREMENTS:
          COMMAND_CAN_BE_EXECUTED = validate_command_3_check_requirements(BUFFER, COMMAND, FROM_BOT, COMMAND_ID)
      
      # CHECK VERSION FOR EXECUTION
      if COMMAND_CAN_BE_EXECUTED == True:
        COMMAND_CAN_BE_EXECUTED = validate_command_4_check_version(BUFFER, COMMAND, FROM_BOT, COMMAND_ID)
        
      if COMMAND_CAN_BE_EXECUTED == True:
        FUNCTION = SCRIPT_CALL[COMMAND]
      else:
        FUNCTION = ''
        display_message(BUFFER, '[%s] %s < EXECUTION DENIED' % (COMMAND_ID, FROM_BOT))
        cleanup_command_id_variables(SOURCE, UNIQ_COMMAND_ID)
    
    return [COMMAND_CAN_BE_EXECUTED, FUNCTION]
  
  #
  # VALIDATE - CHECK COMMAND BELOGN TO US OR ADVERTISEMENT WAS REQUESTED
  #
  
  def validate_command_1_check_bot(COMMAND, BOT_ID):
    global WRECON_BOT_ID, BUFFER_CMD_ADV_EXE
    
    RETURN_RESULT = False
    
    if BOT_ID == WRECON_BOT_ID or COMMAND == BUFFER_CMD_ADV_EXE:
      RETURN_RESULT = True
    
    return RETURN_RESULT
  
  #
  # VALIDATE - SETUP VARIABLES
  #
  
  def validate_command_2_setup_variables(SOURCE):
  # CALL FROM USER INPUT (OR INTERNALL CALL)
  # PREPARE VARIABLES FOR LOCAL CALL
    if SOURCE == 'LOCAL':
      global ID_CALL_LOCAL, SCRIPT_COMMAND_CALL
      ID_CALL     = ID_CALL_LOCAL
      SCRIPT_CALL = SCRIPT_COMMAND_CALL
  # CALL FROM REMOTE INUT (BUFFER)
  # PREPARE VARIABLES FOR REMOTE CALL
    else:
      global ID_CALL_REMOTE, SCRIPT_BUFFER_CALL
      ID_CALL     = ID_CALL_REMOTE
      SCRIPT_CALL = SCRIPT_BUFFER_CALL
    
    return [ID_CALL, SCRIPT_CALL]
  
  #
  # CHECK COMMAND REQUIREMENTS
  #
  
  def validate_command_3_check_requirements(BUFFER, COMMAND, FROM_BOT, COMMAND_ID):
    global COMMAND_REQUIREMENTS
    COMMAND_CAN_BE_EXECUTED = True
    
    if COMMAND in COMMAND_REQUIREMENTS:
      COMMAND_REQUIREMENT = COMMAND_REQUIREMENTS[COMMAND]
      if isinstance(COMMAND_REQUIREMENT, list):
        for CHECK_REQUIREMENT in COMMAND_REQUIREMENT:
          RESULT = CHECK_REQUIREMENT[COMMAND](BUFFER, COMMAND, FROM_BOT, COMMAND_ID) 
          if RESULT == False:
            COMMAND_CAN_BE_EXECUTED = False
            display_message(BUFFER, '[%s] %s < REQUIREMENT RESULT UNSUCCESSFUL' % (COMMAND_ID, CHECK_REQUIREMENT))
            
      else:
        COMMAND_CAN_BE_EXECUTED = COMMAND_REQUIREMENT[COMMAND](BUFFER, COMMAND, FROM_BOT, COMMAND_ID)
        if COMMAND_CAN_BE_EXECUTED == False:
          display_message(BUFFER, '[%s] %s < REQUIREMENT RESULT UNSUCCESSFUL' % (COMMAND_ID, COMMAND_REQUIREMENT))
    
    return COMMAND_CAN_BE_EXECUTED
  
  #
  # VALIDATE COMMAND VERSION (some commands are not in previous version)
  #
  
  def validate_command_4_check_version(BUFFER, COMMAND, FROM_BOT, COMMAND_ID):
    global WRECON_BOT_ID
    
    VERIFY_RESULT = True
    
    if WRECON_BOT_ID == FROM_BOT:
      return VERIFY_RESULT
    
    global COMMAND_VERSION
    
    VERSION_REMOTE  = WRECON_REMOTE_BOTS_ADVERTISED[VERIFY_BOT].split(' ')[0].split('v')[1]
    VERSION_COMMAND = COMMAND_VERSION[COMMAND]
    if VERSION_REMOTE < VERSION_COMMAND:
      VERIFY_RESULT = False
      display_message(BUFFER, '[%s] %s < VERSION %s IS REQUIRED' % (COMMAND_ID, COMMAND, VERSION_COMMAND))
    
    return VERIFY_RESULT
  
  #
  # CLEANUP ID VARIABLES (LOCAL or REMOTE) AFTER VALIDATION or EXECUTION
  #
  
  def cleanup_command_id_variables(SOURCE, COMMAND_ID, UNIQ_COMMAND_ID):
    if SOURCE == 'LOCAL':
      global ID_CALL_LOCAL
      if UNIQ_COMMAND_ID in ID_CALL_LOCAL:
        del ID_CALL_LOCAL[UNIQ_COMMAND_ID]
    else:
      global ID_CALL_REMOTE
      if UNIQ_COMMAND_ID in ID_CALL_REMOTE:
        del ID_CALL_REMOTE[UNIQ_COMMAND_ID]
    
    return
  
  #
  # VERIFY WE CAN CONTROL REMOTE BOT FOR REMOTE EXECUTION (added BOT)
  # (for call)
  
  def verify_remote_bot_control(BUFFER, REMOTE_BOT, COMMAND_ID):
    global WRECON_BOT_ID
    
    VERIFY_RESULT = True
    
    if REMOTE_BOT = WRECON_BOT_ID:
      return VERIFY_RESULT
    
    global WRECON_REMOTE_BOTS_CONTROL
    
    # CHECK WE HAVE ADDED BOT
    if not REMOTE_BOT in WRECON_REMOTE_BOTS_CONTROL:
      VERIFY_RESULT = False
      display_message(BUFFER, '[%s] %s < REMOTE BOT IS NOT ADDED/REGISTERED' % (COMMAND_ID, REMOTE_BOT))
    
    return VERIFY_RESULT
  
  #
  # VERIFY REMOTE BOT WAS ADVERTISED
  #
  
  def verify_remote_bot_advertised(BUFFER, VERIFY_BOT, COMMAND_ID):
    global WRECON_BOT_ID
    
    VERIFY_RESULT = True
    
    if VERIFY_BOT == WRECON_BOT_ID:
      return VERIFY_RESULT
    
    global WRECON_REMOTE_BOTS_ADVERTISED
    
    # IF WE HAVE DATA OF BOT, NO NEED ADDITIONAL ACTION
    if not VERIFY_BOT in WRECON_REMOTE_BOTS_ADVERTISED:
      # TODO
      VERIFY_RESULT = advertise_additional(BUFFER, VERIFY_BOT, COMMAND_ID)
    
    return VERIFY_RESULT
  
  #
  # VERIFY REMOTE BOT WAS VERIFIED
  # verification require remote BOT is advertised
  
  def verify_remote_bot_verified(BUFFER, VERIFY_BOT, COMMAND_ID):
    global WRECON_BOT_ID
    
    VERIFY_RESULT = True
    
    if VERIFY_BOT == WRECON_BOT_ID:
      return VERIFY_RESULT
    
    # VERIFY REQUIRE REMOTE BOT WAS ADVERTISED, WE CHECK IT NOW
    VERIFY_RESULT = verify_remote_bot_advertised(BUFFER, VERIFY_BOT, COMMAND_ID)
    
    # When remote BOT was advertised, we need trigger verification
    if VERIFY_RESULT == True:
      global WRECON_REMOTE_BOTS_VERIFIED, WRECON_REMOTE_BOTS_ADVERTISED
    # Then we need check data of advertised BOT are same as of validated
    # If not, trigger revalidation
      if not WRECON_REMOTE_BOTS_VERIFIED[VERIFY_BOT] == WRECON_REMOTE_BOTS_ADVERTISED[VERIFY_BOT]:
        # TODO
        VERIFY_RESULT = verify_remote_bot(BUFFER, VERIFY_BOT, COMMAND_ID)
    
    return VERIFY_RESULT

  #
  # VERIFY REMOTE BOT WAS GRANTED (granted BOT)
  # verification require remote BOT is verified
  
  def verify_remote_bot_granted(BUFFER, VERIFY_BOT, COMMAND_ID):
    global WRECON_BOT_ID
    
    VERIFY_RESULT = True
    
    if VERIFY_BOT == WRECON_BOT_ID:
      return VERIFY_RESULT
    
    global WRECON_REMOTE_BOTS_GRANTED
    
    # CHECK WE GRANTED REMOTE BOT
    if not VERIFY_BOT in WRECON_REMOTE_BOTS_GRANTED:
      VERIFY_RESULT = False
      display_message(BUFFER, '[%s] %s < REMOTE BOT IS NOT GRANTED' % (COMMAND_ID, REMOTE_BOT))
    else:
      # THEN CHECK GRANTED BOT WAS VERIFIED
      VERIFY_RESULT = verify_remote_bot_verified(BUFFER, VERIFY_BOT, COMMAND_ID)
    
    return VERIFY_RESULT
