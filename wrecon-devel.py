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
# 2.00.0 (unusable, full reworking in progress)
# - Full code rewriting (for better lucidity, and also for code enhancements)
# -- function 'display_message' replaces 'f_message' and 'f_message_simple'
# -- function 'user_command_update' fully changed (splitted into functions)
# -- functions 'encrypt/decrypt' enhanced into levels (also backward compatibility ensure with older script communication)
# -- added possibility choice BOT by INDEX number (for commands DEL/RENAME/REVOKE/SSH/UPDATE)
# -- 
#
# 1.18.13 - Bug fix UPDATE (arguments incorrectly checked after additional advertise)
# 1.18.12 - Bug fix REGISTER/UNREGISTER (add/del registered channels and keys)
# 1.18.11 - Bug fix UPDATE CHECK VERSION
# 1.18.10 - Bug fix SSH AUTOADVERTISE
# 1.18.9 - Bug fix SSH AUTOADVERTISE
# 1.18.8 - Version correction
# 1.18.7 - Fixed bug of variables (lower cases and UPPER CASEs)
#        - in commands REGISTER and UNREGISTER
# 1.18.6 - Fixed bug of variables (lower cases and UPPER CASEs)
# 1.18.5 - Fixed list command (correction of command arguments)
# 1.18.4 - Fix command ADVERTISE
# 1.18.3 - Small fix of call ADDITIONAL ADVERTISE
#        - assignment variables fix (another patch)
#        - Fix ssh call
# 1.18.2 - Small fix of call ADDITIONAL ADVERTISE
#        - assignment variables fix (another patch)
# 1.18.1 - Small fix of call ADDITIONAL ADVERTISE
#        - assignment variables fix (another patch)
# 1.18 - Small fix of call ADDITIONAL ADVERTISE
#      - assignment variables fixed
# 1.17 - Small fix of call ADDITIONAL ADVERTISE
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
SCRIPT_NAME      = 'wrecon-devel'
SCRIPT_VERSION   = '2.0.0 devel'
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
for IMPORT_MOD in ['ast', 'base64', 'contextlib', 'datetime', 'gnupg', 'hashlib', 'json', 'os', 'platform', 'random', 'shutil', 'string', 'sys', 'tarfile', 'time', 'urllib', 'uuid', 'weechat']:
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
  # FUNCTION DISPLAY MESSAGE
  
  def display_message(BUFFER, INPUT_MESSAGE):
    global SCRIPT_NAME

    if isinstance(INPUT_MESSAGE, list):
      # ~ weechat.prnt(BUFFER, '')
      # ~ INPUT_MESSAGE.append('[%s]\t%s' %(SCRIPT_NAME, ''))
      for OUTPUT_MESSAGE in INPUT_MESSAGE:
        weechat.prnt(BUFFER, '\t%s' % str(OUTPUT_MESSAGE))
    else:
      weechat.prnt(BUFFER, '[%s]\t%s' % (SCRIPT_NAME, str(INPUT_MESSAGE)))
    
    return weechat.WEECHAT_RC_OK
  
  def display_message_info(BUFFER, INPUT_TAG, INPUT_MESSAGE):
    global WRECON_BOT_NAME, WRECON_BOT_ID
    
    OUT_MESSAGE      =['']
    OUT_MESSAGE.append('--- %s (%s %s) ---' % (INPUT_TAG, WRECON_BOT_NAME, WRECON_BOT_ID))
    OUT_MESSAGE.append('')
    
    if isinstance(INPUT_MESSAGE, list):
      for OUT_MSG in INPUT_MESSAGE:
        OUT_MESSAGE.append(OUT_MSG)
    else:
      OUT_MESSAGE.append(INPUT_MESSAGE)
    
    display_message(BUFFER, OUT_MESSAGE)
    
    return weechat.WEECHAT_RC_OK
  
  
  # For debug purspose only
  def display_data(FUNCTION, WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global ID_CALL_LOCAL, ID_CALL_REMOTE, WAIT_FOR_VERIFICATION
    OUT_MESSAGE     = ['FUNCTION               : %s' % FUNCTION]
    OUT_MESSAGE.append('WEECAHT_DATA           : %s' % WEECHAT_DATA)
    OUT_MESSAGE.append('BUFFER                 : %s' % BUFFER)
    OUT_MESSAGE.append('SOURCE                 : %s' % SOURCE)
    OUT_MESSAGE.append('DATE                   : %s' % DATE)
    OUT_MESSAGE.append('TAGS                   : %s' % TAGS)
    OUT_MESSAGE.append('DISPLAYED              : %s' % DISPLAYED)
    OUT_MESSAGE.append('HIGHLIGHT              : %s' % HIGHLIGHT)
    OUT_MESSAGE.append('PREFIX                 : %s' % PREFIX)
    OUT_MESSAGE.append('COMMAND/DATA           : %s' % COMMAND)
    OUT_MESSAGE.append('TARGET_BOT_ID          : %s' % TARGET_BOT_ID)
    OUT_MESSAGE.append('SOURCE_BOT_ID          : %s' % SOURCE_BOT_ID)
    OUT_MESSAGE.append('COMMAND_ID             : %s' % COMMAND_ID)
    OUT_MESSAGE.append('COMMAND_ARGUMENTS_LIST : %s' % COMMAND_ARGUMENTS_LIST)
    OUT_MESSAGE.append('LOCAL ID CALL          : %s' % ID_CALL_LOCAL)
    OUT_MESSAGE.append('REMOTE ID CALL         : %s' % ID_CALL_REMOTE)
    OUT_MESSAGE.append('WAIT_FOR_VERIFICATION  : %s' % WAIT_FOR_VERIFICATION)
    display_message_info(BUFFER, 'INFO OF COMMAND > %s < VARIABLES' % COMMAND, OUT_MESSAGE)
    return weechat.WEECHAT_RC_OK
  
  #
  ##### END FUNCTION DISPLAY MESSAGE
  
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
  
  def get_status_my_nick_is_op(SERVER_NAME, CHANNEL_NAME):
  
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
    
    RESULT_NICK    = get_status_my_nick_is_op(SERVER_NAME, CHANNEL_NAME)

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
    
    OUTPUT_RESULT = base64.urlsafe_b64encode(OUTPUT_LIST.encode()).decode()
    
    return OUTPUT_RESULT
  
  def string_encrypt_level_1(INPUT_STRING, INPUT_KEY, NULL):
    NEW_INPUT_KEY         = get_hash(INPUT_KEY)
    SALT_STRING           = get_random_string(8)
    OUTPUT_RESULT_LEVEL_1 = str(string_encrypt_function(INPUT_STRING, SALT_STRING + INPUT_KEY))
    OUTPUT_RESULT_LEVEL_2 = string_encrypt_function(SALT_STRING + OUTPUT_RESULT_LEVEL_1, NEW_INPUT_KEY)
    
    OUTPUT_RESULT         = base64.urlsafe_b64encode(OUTPUT_RESULT_LEVEL_2.encode()).decode()
    
    return OUTPUT_RESULT
  
  def string_encrypt_level_2(INPUT_STRING, INPUT_KEY, INPUT_KEY2):
    INPUT_STRING          = string_reverse(INPUT_STRING)
    INPUT_KEY             = string_join_keys(INPUT_KEY2, INPUT_KEY)
    NEW_INPUT_KEY         = get_hash(INPUT_KEY)
    SALT_STRING           = get_random_string(8)
    OUTPUT_RESULT_LEVEL_1 = str(string_encrypt_function(INPUT_STRING, SALT_STRING + INPUT_KEY))
    OUTPUT_RESULT_LEVEL_2 = string_encrypt_function(SALT_STRING + OUTPUT_RESULT_LEVEL_1, NEW_INPUT_KEY)
    
    OUTPUT_RESULT         = base64.urlsafe_b64encode(OUTPUT_RESULT_LEVEL_2.encode()).decode()
    
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
      KEY_CHAR    = INPUT_KEY[INDEX % len(INPUT_KEY)]
      OUTPUT_CHAR = chr((256 + ord(INPUT_STRING[INDEX]) - ord(KEY_CHAR)) % 256)
      OUTPUT_LIST.append(OUTPUT_CHAR)
    
    OUTPUT_LIST = ''.join(OUTPUT_LIST)
    
    return OUTPUT_LIST
  
  def string_decrypt_level_0(INPUT_STRING, INPUT_KEY, NULL):
    try:
      DECODE_STRING = base64.urlsafe_b64decode(INPUT_STRING).decode()
      OUTPUT_RESULT = string_decrypt_function(DECODE_STRING, INPUT_KEY)
    except:
      OUTPUT_RESULT = 'ERROR'
    
    return OUTPUT_RESULT
  
  def string_decrypt_level_1(INPUT_STRING, INPUT_KEY, NULL):
    try:
      DECODE_STRING         = base64.urlsafe_b64decode(INPUT_STRING).decode()
      NEW_INPUT_KEY         = get_hash(INPUT_KEY)
      OUTPUT_RESULT_LEVEL_2 = string_decrypt_function(DECODE_STRING, NEW_INPUT_KEY)
      SALT_STRING           = OUTPUT_RESULT_LEVEL_2[:8]
      OUTPUT_RESULT_LEVEL_1 = string_decrypt_function(OUTPUT_RESULT_LEVEL_2[8:], SALT_STRING + INPUT_KEY)
    except:
      OUTPUT_RESULT_LEVEL_1 = 'ERROR'
    
    return OUTPUT_RESULT_LEVEL_1
  
  def string_decrypt_level_2(INPUT_STRING, INPUT_KEY, INPUT_KEY2):
    try:
      DECODE_STRING         = base64.urlsafe_b64decode(INPUT_STRING).decode()
      
      INPUT_KEY             = string_join_keys(INPUT_KEY2, INPUT_KEY)
      NEW_INPUT_KEY         = get_hash(INPUT_KEY)
      
      OUTPUT_RESULT_LEVEL_2 = string_decrypt_function(DECODE_STRING, NEW_INPUT_KEY)
      SALT_STRING           = OUTPUT_RESULT_LEVEL_2[:8]
      
      OUTPUT_RESULT_LEVEL_1 = string_decrypt_function(OUTPUT_RESULT_LEVEL_2[8:], SALT_STRING + INPUT_KEY)
      
      DECODE_STRING         = string_reverse(OUTPUT_RESULT_LEVEL_1)
    except:
      DECODE_STRING         = 'ERROR'
      
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

  ######
  #
  # SETUP BASIC GLOBAL VARIABLES FOR WRECON - BOT, SERVER, CHANNEL etc.
  #
  
  #
  # SETUP VARIABLES OF BOT
  #
  
  def setup_wrecon_variables_of_local_bot():
    global WRECON_DEFAULT_BOTNAMES, WRECON_BOT_NAME, WRECON_BOT_ID, WRECON_BOT_KEY
  
    WRECON_DEFAULT_BOTNAMES = ['anee', 'anet', 'ann', 'annee', 'annet', 'bob', 'brad', 'don', 'fred', 'freddie', 'john', 'mia', 'moon', 'pooh', 'red', 'ron', 'ronnie', 'shark', 'ted', 'teddy', 'zed', 'zoe', 'zombie']
    WRECON_BOT_NAME         = weechat.string_eval_expression("${sec.data.wrecon_bot_name}",{},{},{})
    WRECON_BOT_ID           = weechat.string_eval_expression("${sec.data.wrecon_bot_id}",{},{},{})
    WRECON_BOT_KEY          = weechat.string_eval_expression("${sec.data.wrecon_bot_key}",{},{},{})
    
    # Choice default BOT NAME if not exist and save it
    
    if not WRECON_BOT_NAME:
      WRECON_BOT_NAME = random.choice(WRECON_DEFAULT_BOTNAMES)
      weechat.command('', '/secure set wrecon_bot_name %s' % (WRECON_BOT_NAME))
    
    #  Generate BOT ID if not exit and save it
    
    if not WRECON_BOT_ID:
      WRECON_BOT_ID = get_random_string(16)
      weechat.command('', '/secure set wrecon_bot_id %s' % (WRECON_BOT_ID))
    
    # Generate BOT KEY if not exist and save it
    
    if not WRECON_BOT_KEY:
      WRECON_BOT_KEY = get_random_string(64)
      weechat.command('', '/secure set wrecon_bot_key %s' % (WRECON_BOT_KEY))
    
    return
  
  #
  # SETUP VARIABLES OF SERVER
  #
  
  def setup_wrecon_variables_of_server_and_channel():
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
    
    return
  
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
  
  def setup_wrecon_variables_of_remote_bots():
    global WRECON_REMOTE_BOTS_CONTROL, WRECON_REMOTE_BOTS_GRANTED, WRECON_REMOTE_BOTS_VERIFIED, WRECON_REMOTE_BOTS_ADVERTISED, WRECON_REMOTE_BOTS_GRANTED_SECRET, WRECON_REMOTE_BOTS_CONTROL_SECRET
    
    WRECON_REMOTE_BOTS_CONTROL    = weechat.string_eval_expression("${sec.data.wrecon_remote_bots_control}",{},{},{})
    WRECON_REMOTE_BOTS_GRANTED    = weechat.string_eval_expression("${sec.data.wrecon_remote_bots_granted}",{},{},{})
    WRECON_REMOTE_BOTS_VERIFIED   = {}
    WRECON_REMOTE_BOTS_ADVERTISED = {}
    
    WRECON_REMOTE_BOTS_CONTROL_SECRET = weechat.string_eval_expression("${sec.data.wrecon_remote_bots_control_secret}",{},{},{})
    WRECON_REMOTE_BOTS_GRANTED_SECRET = weechat.string_eval_expression("${sec.data.wrecon_remote_bots_granted_secret}",{},{},{})
    
    if WRECON_REMOTE_BOTS_CONTROL:
      WRECON_REMOTE_BOTS_CONTROL = ast.literal_eval(WRECON_REMOTE_BOTS_CONTROL)
    else:
      WRECON_REMOTE_BOTS_CONTROL = {}
    
    if WRECON_REMOTE_BOTS_GRANTED:
      WRECON_REMOTE_BOTS_GRANTED = ast.literal_eval(WRECON_REMOTE_BOTS_GRANTED)
    else:
      WRECON_REMOTE_BOTS_GRANTED = {}
    
    if WRECON_REMOTE_BOTS_CONTROL_SECRET:
      WRECON_REMOTE_BOTS_CONTROL_SECRET = ast.literal_eval(WRECON_REMOTE_BOTS_CONTROL_SECRET)
    else:
      WRECON_REMOTE_BOTS_CONTROL_SECRET = {}
    
    if WRECON_REMOTE_BOTS_GRANTED_SECRET:
      WRECON_REMOTE_BOTS_GRANTED_SECRET = ast.literal_eval(WRECON_REMOTE_BOTS_GRANTED_SECRET)
    else:
      WRECON_REMOTE_BOTS_GRANTED_SECRET = {}
  
    #
    # SETUP VARIABLES OF COUNTER COMMAND AND AUTO ADVERTISE
    #
    
    global WRECON_COMMAND_COUNTER, WRECON_AUTO_ADVERTISED
    WRECON_COMMAND_COUNTER = 0
    WRECON_AUTO_ADVERTISED = False
    
    return
  
  #
  # PUBLIC KEY
  #
  
  def setup_wrecon_variables_of_public_key():
    global PUBLIC_KEY
    PUBLIC_KEY  = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF15LsQBEADK9fJXtm6q15+InXemAPlJlUF6ZJVX1SiOsKIxSp025BfVkern
+j5uXJopOff5ctINQGFXV+ukHhBKWiSCfTb4RXegvVeQ37uzUWxyhku6WHxKuauO
KqYvS7Sco1n6uo5xeCDNVkioQo4I0OKWXpjVvw6+Ve4seeIbzQN3hSvtPLJJzbJp
r4BtHtD/YRIoiY+zJDYOn6S8agz8EXrnNk4/wmZgMp42oo1aOngq8Z06qJ8ietkQ
hccRJgEAfIt5tkvEzfeQy5J1JyD/XgA9pIZ/xSCMezgtzCv2zDoIAhxPpUq8InDy
jNjJxeNDLEFZs9BjVkc7YjaPvtrTTffutl76ivAYopiZVCYV92oWlKiwvlgxHZcA
8e5pDGFuiwZ2CccaqsOxmmmgTYkM4j3d9JWHDESz91igHhZGDZXDQpxwziJdtjxh
Imlo6sxSCkY6ao/yD+DQGeVHqGElEjW0zoXrRP8mODgTndw+q+GhgzAjkBKez4U2
c1FRvnPdO9W7Pja+VaqbVYjhEXQ69ieOZZnmYoGQNJMRV5N8bN+PiZPK+kUr3ZLj
QaM2lKD2S3XWBgy96OYslJbKIX3x1htyVXlZwrTkJsIaSvY/grbNkswoCJPzqTMo
UrPIpjuPdDN8A81q/A/cp6lT4fXN0N67DfvkkJz+A6wJC8wEPOzFS8jD8QARAQAB
tCxSYWRlayBWYWzDocWhZWsgPHJhZGVrLnZhbGFzZWsuNzVAZ21haWwuY29tPokC
YwQTAQoANhYhBEXtfg7TIRSWGjBQtGQuynjp8aa7BQJdeS7EAhsDBAsJCAcEFQoJ
CAUWAgMBAAIeAQIXgAAhCRBkLsp46fGmuxYhBEXtfg7TIRSWGjBQtGQuynjp8aa7
RLkP/0cQMbTYk/0eQQghyiyX/QVlvJ3xSbAo1BvSkpRgtt7fzERQKtxGsEtt8kaF
PQv4+qitbT+BGedXA9b738Mr/OBVuYP03cQNF+Pnk7n/sHdCRXCkM5TXN7OAmc7f
NRj8bcyIKRTjfR/v7X9hgztST54UwFgJv28zTNxehkNUdaqPtiCZSSkGwBHmr+Kf
nkKZKQzzUnJMzuuP6D240pKO4DQ4+tImbM0m2C3ofAxLeF12Rl1pygjEMSCgaRED
aBqNqDCN/QZFM7A20tbu1s7A2CxF+gsU9N45rQW6UfIQX/2KmM6QfvlTyjojWzU8
QFyNKhlhxpPL/hc2EKAg5dsgbhyHgqP1eNZnWNzjbBxgow1HvoEIl1J9ascAHMT/
vUrca8C+PJ99Qaw6XbyPN1ScR+k2O3uVS1t+4s8xzpZbL+dFfc8b+QPbJb9D91tO
zoC5oVcsE4QLMOi5DZ9ZlipQjw2qQmH0ocLITatNwpbsiRRmyj25AkBZppRCcAya
9Rsr2Sa2EuV50sLiC/hnEsV0z6opXz+NqvfCWIdXiZWfchNWmSM9QZfgerymrpEf
NUTZipu9ps+AlvixY2DOBPdpdiLeyiGaYW+lyBk+3Jn8pQlVQVCvbEFIU9Cpxk59
0JlWXMwbZeiver/ca+gXfj5bmSH7ik33L0EtpTq2Pa9EbVEOuQINBF15LvoBEADG
xaC51pbOElqLwOJsfHLZYjqB0alw5U1agygfVmJRaby5iHrBX64otGzszWE7u5Vl
G+cj3aXua/clj3vO1tIuBsOlFRimBfBxUMJ9n26rRvk9iMWhEcxfFo4VN6iBgheE
Mpix735g5WKAo9fg1o8PW7rvZBPZe7K7oEHly9MpHpTUalDEU4KHQA78S5i49Vwj
s6yxl0Bn+Pj4F1XLlJeC51udPKwt7tkhPj2j1lMQ7emuU5Sbn1rLWJWq7fNnU/e4
g5uCowzi6dLSWYl1jNRT9o545Gp7i9SPn+ur2zVgD3+ThOfOXuSYs5GWeu2bjs2I
nnXms2U8f4AJfkkwlJaM1Ma68ywoxngZw6WjQtKGLWNbkiA2L5YvMyxNy2RVOeo9
JtdfN4u93W58wr94glywxW8Mx+4VX/vKRnbwa6oApDHLHWJMfI0pFzoj6OfUGGPi
fl7kCjjUwa5FSYQcYhQCdXsWZApg25nzYFi+dKx20APvm7f4SYKd6zdS5S0YWjhC
WDBa7DKoO6rroOqi6fEletbLJ2yn+O6Q3oIG4aAkImRXEXI+gbHf4GvMzn5xtgEI
C8Epk5QTxF6TuBEaK/iQLbDWoWBUVBaVDEZkIjxmwB6CwoBzYkNEDVvvhdmyNgb+
jAao94o14tV3w2sdfB7bXTMu4gjLiTp5DmBgob4moQARAQABiQJNBBgBCgAgFiEE
Re1+DtMhFJYaMFC0ZC7KeOnxprsFAl15LvoCGwwAIQkQZC7KeOnxprsWIQRF7X4O
0yEUlhowULRkLsp46fGmu7j2D/99eWv90v5BzW1cgau8fQrZUgNpUZD8NhandtPc
bI31/fQp0uPGNG14qRYjOPxa268nmozxMT7N0p5dC9B3CM2v2ykiruz7wRuPvO9j
Py/FDotHI7JzWeFQGgsoR9+ZWtzUI+JJ/Uh4l94X6UgSR5dqJM1WokerjP6K/LGa
ird7gK+o+oy6GWgF7ANWw77sWcqUhPYM4wszQiw8tLe/RKADgZYE4ciXD5rHiImP
+tVf7bewpMYkbOgQFldEo3uzjwZlcjFbNnzPCwEIInDdeWI4Sojo2WKlFsE8Z8rV
UVv/kGAhbiZwJVnOsDkR/86fKwtDFdO1Ytga7JNgcKpLjDK+IbQdwLYuuAt/xsOw
eV2gKTK4h+xZ6RQO5xwn94JObdWAUD9ScGo9sH7oSs3d/YVAfvDKZehWRchov4Dr
5trEgTXPXUKo9m0kYop8t0GxxjfqJ2ne3xwngh90gl3E1REcz/BI7Ckm7TYmm44v
4nj7Dj4ugEbH6I49u+MIF3ra5j/fsv4EZlpvuPNJy5nvxty/NfHk2JhX+CdETBmQ
HZsQjwtkGlg74ahJtWELhJunMYJuhBJwMn1jHGtI2/AusJEtq9JOzX8rImUxoKt0
UAq1cXOx8cCFQLxap557cOszspm9RYhuo9ySvHh0Uon+bWrvrH/ksLc7YJwyZQ/c
vJ3oMrkCDQRdeS8SARAAtCC2iG+iCjZrR+45O3TPKP/HjLmrj+FZWiDEvVI7sxlF
0rEOH9lJIVFcspeyzE0LnxZHi1UvOeF/P07Lcrp+CZvkeVi6sOwDL1E5cdkoOoV+
TbVV6mm4gaIw3oAZ7PAe2fpLtu33aYtWa+SVONOp9rFnOnEJs1jB8/u806UAHmoB
HWi35OBHiYyDA5jx4HWccSxc828MqBnmbpOsniigFEyj4paW+q/7ug5I7p9aBYYs
4CqS708sodJG+MuFpOZ2+XKTYrMvdTFZLbKqD8bmSwrAaA0FIFmIw+msbhpQnsrG
/RHXyItuwZybsLcrwLfp+0WPHbr//C5d96F+a21+suajRRvqjsTBabAYGlMRw0Ly
aHxBz0lWL0UT9hjGmmgC9Fgv3UessCvNe39Smt8ZnSE+sbyRZEmnjSd2mrKAcQ8b
6iQqqO+y0YbipgIjqxBDAsjWcYbd1/MTDr4ZTev1AkJ3shxgDBPogqQXGgOOrRI0
agb5frHSIvjo7AoyTbYjnqURWG3puBxFTuuxBK33n8umMdqigJQnDUJ8gtjzXmn9
BdQ5Pejaf5zduxdiv25l0Dcq6qplryfvowtfuJeLpNQOJrWbPq4UHqjN2cUF+HwI
tjfVUiGCl441FhgkJKOAcyNUO9TqNXSL5tR08dGQ/BYqlYSCIg7dgW2XojMtvFMA
EQEAAYkCTQQYAQoAIBYhBEXtfg7TIRSWGjBQtGQuynjp8aa7BQJdeS8SAhsgACEJ
EGQuynjp8aa7FiEERe1+DtMhFJYaMFC0ZC7KeOnxpruftQ//fw9TB2D1LZ1X5e8O
Uak29qiKgzCLFL24Q4pYY9MWDlN92qWjZxxuhVGXDIsmZ6yVU25bG3D3DLxOaWEJ
GqlQaA7mMvojhABQhZWRNQO4YrLkywR6M+wW7ga5xpvvIDoy9dmo8kybptUXBjSy
C0Ad6CGE5BcmdhD5B2jwUdfDDyQx95vjw2Zn1P59SHr8klNJbZvSNwtbfbY7vMUJ
Bq1v8EoCKu7Cyc0V+GaO4N4yj+k+yCVvfBpuisyzaA8nuAErrpxCmAZISKmv4kGC
6g1RQYDHxYnbYz2/hKsMj1aLyxBrIweHWnQwA3DrL9g8EJLDDfrOVO+4Cczpoa23
GUakDBIVocEK2JCIrvfa+LYfV2FSpKsCMQhD01ZeGwRT/XqGF234Pvpg/b9/D/DH
w7WpOD31yKQdklxW9P40D4Bk76SE+Mdy0kpxynbZ7WYOvO5CBFZ4yoA1mBw7KL7m
UYanKeAcB+GFWUfm6gSarE9D5uK+7+VrQCoqQTShsRpSHCGIXXDF9tv/kz0xt3Kw
niUws8q80UVE4+LuwQqPjyxGrtMnOMKMpCjm3Nd5THtaIEFIyL098FnCt49Wn/ro
i68o63HicKAfnAqq7Chc2ruMxMY+0u3s0OS5o6aJkySzzMUgki5ipKUEGRJQFWSb
KPX4rlTJFYD/K/Hb0OM4NwaXz5Q=
=FtIt
-----END PGP PUBLIC KEY BLOCK-----
  '''
    return
  
  #
  # SETUP OF FUNCTIONAL VARIABLES
  #
  
  def setup_wrecon_variables_of_functions():
    global SCRIPT_COMMAND_CALL, PREPARE_USER_CALL, SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, COLOR_TEXT, SCRIPT_ARGS_DESCRIPTION, COMMAND_IN_BUFFER, SCRIPT_BUFFER_CALL, TIMEOUT_COMMAND, COMMAND_VERSION, SHORT_HELP, TIMEOUT_CONNECT, TIMEOUT_COMMAND_SHORT, SCRIPT_INTERNAL_CALL, TIMEOUT_COMMAND_L2
    SCRIPT_COMMAND_CALL     = {}
    SCRIPT_BUFFER_CALL      = {}
    SCRIPT_INTERNAL_CALL    = {}
    PREPARE_USER_CALL       = {}
    SCRIPT_ARGS             = ''
    SCRIPT_ARGS_DESCRIPTION = ''
    SCRIPT_COMPLETION       = ''
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
    TIMEOUT_COMMAND         = 15
    TIMEOUT_COMMAND_SHORT   = 5
    TIMEOUT_CONNECT         = 30
    TIMEOUT_COMMAND_L2      = 10
    COMMAND_VERSION         = {}
    
    global GLOBAL_VERSION_LIMIT
    GLOBAL_VERSION_LIMIT    = '2.0.0'
    
    global SCRIPT_NAME, HELP_COMMAND
    SHORT_HELP              = ''
    HELP_COMMAND            = {}
    
    # Number of required or optional arguments of user commands
    #
    # ARGUMENTS_REQUIRED         == ARGUMENTS - command requires strict number of arguments
    # ARGUMENTS_OPTIONAL (list)  >= ARGUMENTS - command requires optional number of arguments
    #                                         - there can be no argument, or number of arguments up to limit number
    # ARGUMENTS_REQUIRED_MINIMAL <= ARGUMENTS - command requires minimum number of arguments, more is allowed
    #                                         - there should be minimum number of arguments
    global ARGUMENTS_REQUIRED, ARGUMENTS_OPTIONAL, ARGUMENTS_REQUIRED_MINIMAL
    ARGUMENTS_REQUIRED         = {}
    ARGUMENTS_OPTIONAL         = {}
    ARGUMENTS_REQUIRED_MINIMAL = {}
    
    #
    # SETUP OF VARIABLES FOR LOCAL or REMOTE REQUIREMENTS
    #
    global COMMAND_REQUIREMENTS_LOCAL, COMMAND_REQUIREMENTS_REMOTE
    COMMAND_REQUIREMENTS_LOCAL  = {}
    COMMAND_REQUIREMENTS_REMOTE = {}
    
    #
    # SETUP OF HOOK VARIABLES
    #
  
    global WRECON_HOOK_COMMAND, WRECON_HOOK_CONNECT, WRECON_HOOK_JOIN, WRECON_HOOK_BUFFER, WRECON_HOOK_LOCAL_COMMANDS
    WRECON_HOOK_COMMAND        = ''
    WRECON_HOOK_CONNECT        = ''
    WRECON_HOOK_JOIN           = ''
    WRECON_HOOK_BUFFER         = ''
    WRECON_HOOK_LOCAL_COMMANDS = ''
    
    #
    # SETUP VERIFICATION VARIABLE (for waiting of remote bot verification)
    #
    
    global WAIT_FOR_VERIFICATION, WAIT_FOR_REMOTE_DATA, WAIT_FOR_ADVERTISE_ADA, WAIT_FOR_VALIDATION, WAIT_FOR_VERSION, WAIT_FOR_ADVERTISE, WAIT_FOR_RENAME
    WAIT_FOR_VERIFICATION  = {}
    WAIT_FOR_REMOTE_DATA   = {}
    WAIT_FOR_ADVERTISE     = {}
    WAIT_FOR_ADVERTISE_ADA = {}
    WAIT_FOR_VALIDATION    = {}
    WAIT_FOR_VERSION       = {}
    WAIT_FOR_RENAME        = {}
    
    # VARIABLES FOR ENHANCED ENCRYPTION VERIFICATION
    global VERIFICATION_PROTOCOL, VERIFICATION_REPLY_EXPECT
    VERIFICATION_PROTOCOL     = {}
    VERIFICATION_REPLY_EXPECT = {}
    
    return
  
  #
  ##### END SETUP BASIC GLOBAL VARIABLES FOR WRECON - BOT, SERVER, CHANNEL etc.
  
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
        if CHANNEL_FIELD_TYPE == 'i':
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
  # FUNCTION GET STATUS SERVER
  
  def get_status_server():
    global WRECON_SERVER
    INFOLIST_SERVER = weechat.infolist_get('irc_server', '', '')
    SERVER_STATUS   = {}
    while  weechat.infolist_next(INFOLIST_SERVER):
      SERVER_NAME                = weechat.infolist_string(INFOLIST_SERVER, 'name')
      SERVER_STAT                = weechat.infolist_integer(INFOLIST_SERVER, 'is_connected')
      SERVER_STATUS[SERVER_NAME] = SERVER_STAT
    weechat.infolist_free(INFOLIST_SERVER)
    
    if WRECON_SERVER in SERVER_STATUS:
      return SERVER_STATUS[WRECON_SERVER]
    else:
      return '0'
  #
  ##### END FUNCTION GET STATUS SERVER
  
  #####
  #
  # FUNCTION GET VERSION AND TIMESTAMP
  
  def get_version_and_timestamp(INPUT_VERSION, INPUT_TIMESTAMP):
    
    LIST_VERSION     = INPUT_VERSION.split(' ')
    OUTPUT_VERSION   = LIST_VERSION[0].split('v')[0]
    LIST_VERSION.pop(0)
    
    OUTPUT_TIMESTAMP = INPUT_TIMESTAMP
    
    if len(LIST_VERSION) > 0:
      OUT_STAMP = ' '.join(LIST_VERSION)
      OUTPUT_TIMESTAMP = '%s %s' % (OUT_STAMP, OUTPUT_TIMESTAMP)
    
    return [OUTPUT_VERSION, OUTPUT_TIMESTAMP]
  
  #
  ##### END FUNCTION GET VERSION AND TIMESTAMP
  
  #####
  #
  # GET NICK INFO
  
  def get_nick_info(TAGS, PREFIX):
    
    # Get actual TIMESTAP of time in UTC as INT format, we no need FLOAT
    ACTUAL_TIMESTAMP = int(datetime.datetime.utcnow().timestamp())
    
    # Convert TIMESTAMP to human readable form also
    # Both values will be in content of NICK info
    # TIMESTAMP is used for easy comparing of last advertisement of remote BOT
    YMD, HMS         = str(datetime.datetime.utcfromtimestamp(ACTUAL_TIMESTAMP)).split(' ')
    YR, MO, DY       = YMD.split('-')
    HR, MI, SC       = HMS.split(':')
    ACTUAL_DATE_TIME = YR + MO + DY + HR + MI + SC
    
    NICK_NAME        = TAGS.split(',')[3].split('_')[1]
    HOST_NAME        = TAGS.split(',')[4]
    HOST_NAME        = HOST_NAME.split('_')[1]
    
    NICK_INFO        = '%s|%s|%s|%s|%s' % (NICK_NAME, HOST_NAME, PREFIX, ACTUAL_DATE_TIME, ACTUAL_TIMESTAMP)
    
    return NICK_INFO
  #
  ##### END GET NICK INFO
  
  #####
  #
  # FUNCTION IGNORE BUFFER COMMAND (do nothing)
  
  def ignore_buffer_command(WEECHAT_DATA, BUFFER, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS):
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    cleanup_unique_command_id('REMOTE', UNIQ_COMMAND_ID)
    return weechat.WEECHAT_RC_OK
  #
  ##### END FUNCTION IGNORE BUFFER COMMAND
  
  #####
  #
  # GET BASIC DATA OF REMOTE BOT
  
  def get_basic_data_of_remote_bot(TAGS, PREFIX, COMMAND_ARGUMENTS):
    
    COMMAND_ARGS = ' '.join(COMMAND_ARGUMENTS)
    
    SOURCE_BOT_NAME         = COMMAND_ARGS.split('[')[0].rstrip()
    SOURCE_BOT_VERSION_DATA = COMMAND_ARGS.split('[')[1].split(']')[0]
    
    # Not all advertised data contain time of version, so following condition
    # will result proper data will be saved
    if ' ' in SOURCE_BOT_VERSION_DATA:
      SOURCE_BOT_VERSION      = SOURCE_BOT_VERSION_DATA.split(' ')[0].split('v')[1]
      SOURCE_BOT_VERSION_TIME = SOURCE_BOT_VERSION_DATA.split(' ')[1]
    else:
      SOURCE_BOT_VERSION      = SOURCE_BOT_VERSION_DATA.split('v')[1]
      SOURCE_BOT_VERSION_TIME = ''
  
    SOURCE_BOT_NICK_INFO    = get_nick_info(TAGS, PREFIX)
    
    SOURCE_BOT_BASIC_DATA = '%s|%s|%s|%s' % (SOURCE_BOT_NAME, SOURCE_BOT_VERSION, SOURCE_BOT_VERSION_TIME, SOURCE_BOT_NICK_INFO)
    
    return SOURCE_BOT_BASIC_DATA
  #
  ##### END GET BASIC DATA OF REMOTE BOT
  
  #####
  #
  # GET VERSION OF REMOTE BOT FROM ADVERTISED DATA
  
  def get_version_of_advertised_remote_bot(SOURCE_BOT):
    global WRECON_REMOTE_BOTS_ADVERTISED
    
    if SOURCE_BOT in WRECON_REMOTE_BOTS_ADVERTISED:
      OUTPUT_VERSION = WRECON_REMOTE_BOTS_ADVERTISED[SOURCE_BOT].split('|')[1]
    else:
      OUTPUT_VERSION = 0
    
    return OUTPUT_VERSION
  #
  ##### END GET VERSION OF REMOTE BOT FROM ADVERTISED DATA
  
  #####
  #
  # GET BASIC TARGET LEVEL OF ENCRYPTION
  
  def get_target_level_01_encryption(TARGET_BOT_ID):
    global GLOBAL_VERSION_LIMIT, WRECON_REMOTE_BOTS_CONTROL_SECRET, WRECON_REMOTE_BOTS_GRANTED_SECRET
    
    TARGET_VERSION        = get_version_of_advertised_remote_bot(TARGET_BOT_ID)
    HIGH_LEVEL_ENCRYPTION = compare_version_of_command(GLOBAL_VERSION_LIMIT, TARGET_VERSION)
    
    if HIGH_LEVEL_ENCRYPTION == True:
      OUTPUT_LEVEL = 1
    else:
      OUTPUT_LEVEL = 0
    
    return OUTPUT_LEVEL
  
  #
  ##### END GET BASIC TARGET LEVEL OF ENCRYPTION
  
  #####
  #
  # HOOK AND UNHOOK BUFFER
  
  def hook_buffer():
    global SCRIPT_CALLBACK_BUFFER, WRECON_BUFFER_HOOKED, WRECON_HOOK_BUFFER, WRECON_BUFFER_CHANNEL, COMMAND_IN_BUFFER
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
  
  #
  # FUNCTION COMMAND RECALL
  # is called after a verification was requested and we have result
  # then we call command_pre_validation again to finish execution
  
  def command_recall(WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID):
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - command_recall: %s' % [WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID])
    
    if SOURCE == 'LOCAL':
      SOURCE = 'PRE-LOCAL'
      
    DATA = '%s %s %s %s %s' % (COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS)
    
    command_pre_validation(WEECHAT_DATA, BUFFER, SOURCE, '', '', '', '', '', DATA)
    return weechat.WEECHAT_RC_OK
  
  #
  # FUNCTION COMMAND PRE-VALIDATION
  # is called from user input or call from buffer
  
  def command_pre_validation(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, DATA):
    # HERE WE PREPARE VARIABLES
    global ID_CALL_LOCAL, ID_CALL_REMOTE, WRECON_BOT_ID, DISPLAY_COMMAND
    
    if SOURCE == 'LOCAL':
      COMMAND_ID  = get_command_uniq_id()
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - (1) command_pre_validation: ID_CALL_LOCAL : %s' % ID_CALL_LOCAL)
    
    if not DATA:
      if not COMMAND_ID:
        COMMAND_ID = '????-????'
      display_message(BUFFER, '[%s] %s CALL ERROR: MISSING COMMAND' % (COMMAND_ID, SOURCE))
    else:
      ARGUMENTS = DATA.split(' ')
      COMMAND   = ARGUMENTS[0].upper()
      ARGUMENTS.pop(0)
      
      # DEBUG
      # ~ display_data('command_pre_validation', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, '', '', '', ARGUMENTS)
      
      if SOURCE == 'REMOTE':
        TARGET_BOT_ID = ARGUMENTS[0]
        SOURCE_BOT_ID = ARGUMENTS[1]
        COMMAND_ID    = ARGUMENTS[2]
        
        ARGUMENTS.pop(0)
        ARGUMENTS.pop(0)
        ARGUMENTS.pop(0)
      
      if not ARGUMENTS:
        COMMAND_ARGUMENTS      = ''
        COMMAND_ARGUMENTS_LIST = []
        
      else:
        COMMAND_ARGUMENTS      = ' '.join(ARGUMENTS)
        COMMAND_ARGUMENTS_LIST = COMMAND_ARGUMENTS.split(' ')
      
      EXECUTION_ALLOWED = False
      
      # HERE WE PREPARE LOCAL, PRE-LOCAL or INTERNAL COMMANDS
      if SOURCE in ['LOCAL', 'PRE-LOCAL', 'INTERNAL']:
        
        if SOURCE in ['INTERNAL', 'PRE-LOCAL']:
          # ~ display_message(BUFFER, 'PRE-LOCAL ARGS : %s' % COMMAND_ARGUMENTS_LIST)
          # DEBUG
          # ~ display_message(BUFFER, 'DEBUG - ARGS : %s' % COMMAND_ARGUMENTS_LIST)
          TARGET_BOT_ID     = COMMAND_ARGUMENTS_LIST[0]
          COMMAND_ID        = COMMAND_ARGUMENTS_LIST[1]
          UNIQ_COMMAND_ID   = COMMAND_ARGUMENTS_LIST[2]
          
          if SOURCE == 'PRE-LOCAL':
            COMMAND_ID      = UNIQ_COMMAND_ID
            UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
          
          # DEBUG
          # ~ display_message(BUFFER, 'DEBUG - ARGS : TARGET_BOT_ID   : %s' % TARGET_BOT_ID)
          # ~ display_message(BUFFER, 'DEBUG - ARGS : COMMAND_ID      : %s' % COMMAND_ID)
          # ~ display_message(BUFFER, 'DEBUG - ARGS : UNIQ_COMMAND_ID : %s' % UNIQ_COMMAND_ID)
          
          COMMAND_ARGUMENTS_LIST.pop(0)
          COMMAND_ARGUMENTS_LIST.pop(0)
          COMMAND_ARGUMENTS_LIST.pop(0)
          COMMAND_ARGUMENTS = ' '.join(COMMAND_ARGUMENTS_LIST)
          if UNIQ_COMMAND_ID in DISPLAY_COMMAND:
            del DISPLAY_COMMAND[UNIQ_COMMAND_ID]
        
        if SOURCE == 'INTERNAL':
          COMMAND_ARGUMENTS_LIST                     = [TARGET_BOT_ID]
          COMMAND_ARGUMENTS                          = TARGET_BOT_ID
          ID_CALL_LOCAL[UNIQ_COMMAND_ID]             = [COMMAND, COMMAND_ID, COMMAND_ARGUMENTS_LIST]
        
        if SOURCE == 'LOCAL':
          UNIQ_COMMAND_ID                  = WRECON_BOT_ID + COMMAND_ID
          ID_CALL_LOCAL[UNIQ_COMMAND_ID]   = [COMMAND, COMMAND_ID, COMMAND_ARGUMENTS_LIST]
          DISPLAY_COMMAND[UNIQ_COMMAND_ID] = True
        
        # DEBUG
        # ~ display_message(BUFFER, 'DEBUG - (2) command_pre_validation: ID_CALL_LOCAL : %s' % ID_CALL_LOCAL)
        
        DATE      = ''
        TAGS      = ''
        DISPLAYED = ''
        HIGHLIGHT = ''
        PREFIX    = ''
        
        # DEBUG ONLY
        # ~ if SOURCE == 'PRE-LOCAL':
          # ~ display_data('command_pre_validation', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, WRECON_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
        # ~ else:
          # ~ display_data('command_pre_validation', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, WRECON_BOT_ID, WRECON_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
        
        # First we check command exist
        
        if SOURCE in ['LOCAL', 'PRE-LOCAL']:
          PRE_SOURCE = 'PRE-LOCAL'
          # ~ SOURCE     = 'LOCAL'
        else:
          PRE_SOURCE = 'INTERNAL'
        
        COMMAND_EXIST, PREPARE_COMMAND = validate_command(WEECHAT_DATA, BUFFER, PRE_SOURCE, COMMAND, WRECON_BOT_ID, WRECON_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID)
        
        # Then we prepare final data before execution of local command
        if COMMAND_EXIST == True:
          
          SOURCE = 'LOCAL'
          
          # Prepare correct ARGUMENTS (list) for command
          COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID = PREPARE_COMMAND(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, WRECON_BOT_ID, WRECON_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
          # Then validate command for if we can execute
          
          EXECUTION_ALLOWED, EXECUTE_COMMAND = validate_command(WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID)
          
          # DEBUG
          # ~ display_message(BUFFER, 'COMMAND   : %s' % [WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID])
          # ~ display_message(BUFFER, 'LOCAL EXE : %s' % EXECUTION_ALLOWED)
          # ~ display_message(BUFFER, 'LOCAL FNC : %s' % EXECUTE_COMMAND)
          
      # HERE WE PREPARE REMOTE COMMAND
      else:
        
        UNIQ_COMMAND_ID                  = SOURCE_BOT_ID + COMMAND_ID
        ID_CALL_REMOTE[UNIQ_COMMAND_ID]  = [COMMAND, COMMAND_ID, COMMAND_ARGUMENTS_LIST]
        DISPLAY_COMMAND[UNIQ_COMMAND_ID] = True
        
        # ~ display_data('command_pre_validation', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, WRECON_BOT_ID, WRECON_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
        EXECUTION_ALLOWED, EXECUTE_COMMAND  = validate_command(WEECHAT_DATA, BUFFER, 'REMOTE', COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID)
        
        # ~ display_message(BUFFER, 'REMOTE EXE : %s' % EXECUTION_ALLOWED)
        # ~ display_message(BUFFER, 'REMOTE FNC : %s' % EXECUTE_COMMAND)
      
      # ~ display_message(BUFFER, 'FINAL EXE : %s' % EXECUTION_ALLOWED)
      # ~ display_message(BUFFER, 'FINAL FNC : %s' % EXECUTE_COMMAND)
      # Finally we have all prepared, and if we can execute, then we execute it
      
      if EXECUTION_ALLOWED == True:
        EXECUTE_COMMAND(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
        
    return weechat.WEECHAT_RC_OK
  
  #####
  #
  # HOOK USER COMMAND
  
  def hook_command_from_user(WEECHAT_DATA, BUFFER, DATA):
    
    command_pre_validation(WEECHAT_DATA, BUFFER, 'LOCAL', '', '', '', '', '', DATA)
    
    return weechat.WEECHAT_RC_OK
  
  global SCRIPT_CALLBACK
  SCRIPT_CALLBACK = 'hook_command_from_user'
  
  #
  ##### END HOOK USER COMMAND
  
  #####
  #
  # PARSING BUFFER COMMAND (RECEIVED A COMMAND FROM BUFFER)
  
  def hook_command_from_buffer(WEECHAT_DATA, BUFFER, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, DATA):
    
    command_pre_validation(WEECHAT_DATA, BUFFER, 'REMOTE', DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, DATA)
    
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
      display_message('', 'CONNECTING SERVER : %s' % WRECON_SERVER)
      if get_status_server() == 0:
        autoconnect_1_server()
      else:
        BUFFER_SERVER = get_buffers()
        autojoin_1_channel(BUFFER_SERVER['server.%s' % (WRECON_SERVER)])
    else:
      display_message('', 'NO CHANNEL SETUP FOUND')
    
    return weechat.WEECHAT_RC_OK
  
  #
  # AUTOCONNECT - SERVER
  #
  
  def autoconnect_1_server():
    global WRECON_SERVER, TIMEOUT_CONNECT
    
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
      if REMAINING_CALLS == 0:
        # THERE CAN BE NETWORK ISSUE, WE CAN TRY AGAIN AND AGAIN...
        weechat.unhook(WRECON_HOOK_CONNECT_SERVER)
        autoconnect_1_server()
    
    return weechat.WEECHAT_RC_OK
  
  #
  # AUTOJOIN - CHANNEL
  #
  
  def autojoin_1_channel(BUFFER):
    global WRECON_CHANNEL, WRECON_CHANNEL_KEY, WRECON_HOOK_JOIN, WRECON_SERVER, TIMEOUT_CONNECT, WRECON_BUFFER_CHANNEL
    
    display_message('', 'JOINING CHANNEL   : %s' % WRECON_CHANNEL)
    
    weechat.command(BUFFER, '/join %s %s' % (WRECON_CHANNEL, WRECON_CHANNEL_KEY))
    WRECON_HOOK_JOIN = weechat.hook_timer(1*1000, 0, TIMEOUT_CONNECT, 'autojoin_2_channel_status', '')
    
    WRECON_BUFFER_CHANNEL = get_buffer_channel()
    
    return weechat.WEECHAT_RC_OK
  
  #
  # AUTOJOIN - CHANNEL STATUS
  #
  
  def autojoin_2_channel_status(NULL, REMAINING_CALLS):
    global WRECON_HOOK_JOIN, WRECON_AUTO_ADVERTISED, WRECON_HOOK_BUFFER, WRECON_BUFFER_CHANNEL, SCRIPT_CALLBACK_BUFFER, WRECON_CHANNEL
    
    if REMAINING_CALLS == '0':
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
      WRECON_BUFFER_CHANNEL = get_buffer_channel()
      if WRECON_AUTO_ADVERTISED == False:
        hook_buffer()
        setup_channel(WRECON_BUFFER_CHANNEL)
        hook_command_from_user('', WRECON_BUFFER_CHANNEL, 'ADVERTISE')
        WRECON_AUTO_ADVERTISED = True
    
    return weechat.WEECHAT_RC_OK

  #
  ##### END FUNCTION AUTOCONNECT SERVER / AUTOJOIN CHANNEL
  
  #####
  #
  # FUNCTION SETUP CHANNEL (title of BUFFER, and mode of channel)
  
  def setup_channel(BUFFER):
    global WRECON_CHANNEL, WRECON_CHANNEL_KEY, WRECON_SERVER, WRECON_BUFFER_CHANNEL
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
  
  def get_device_secrets():
    SECRET1 = str(os.path.expanduser('~'))
    SECRET2 = str(SECRET1.split('/')[-1])
    SECRET3 = str(uuid.uuid1(uuid.getnode(),0))
    SECRET4 = str(platform.node())
    SECRETS = get_hash(SECRET2 + SECRET4 + SECRET3[24:] + SECRET1)
    del SECRET1
    del SECRET2
    del SECRET3
    del SECRET4
    return str(SECRETS)
  
  #
  ##### END FUNCTION GET DEVICE SECRETS
  
  #####
  #
  # FUNCTION SETUP AUTOJOIN ADD / DEL (/ SAVE)
  
  #
  # SETUP VARIABLES OF FUNCTION setup_autojoin
  #
  
  def setup_wrecon_variables_of_setup_autojoin():
    global CALLBACK_SETUP_AUTOJOIN
    CALLBACK_SETUP_AUTOJOIN = {}
    
    CALLBACK_SETUP_AUTOJOIN['ADD'] = setup_autojoin_add
    CALLBACK_SETUP_AUTOJOIN['DEL'] = setup_autojoin_del
    
    return
  
  #
  # SETUP AUTOJOIN
  #
  
  def setup_autojoin(BUFFER, FUNCTION, INPUT_WRECON_SERVER, INPUT_WRECON_CHANNEL):
    global CALLBACK_SETUP_AUTOJOIN
    SAVE_SETUP = False
    
    
    # Check FUNCTION contain 'add' or 'del'
    if FUNCTION in CALLBACK_SETUP_AUTOJOIN:
      
      if FUNCTION == 'DEL':
        global WRECON_SERVER, WRECON_CHANNEL
      else:
        WRECON_SERVER, WRECON_CHANNEL = [INPUT_WRECON_SERVER, INPUT_WRECON_CHANNEL]
      
      WEECHAT_SERVER_AUTOJOIN = weechat.string_eval_expression("${irc.server.%s.autojoin}" % (WRECON_SERVER), {}, {}, {})
      
      WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS = setup_autojoin_convert_string2list(WEECHAT_SERVER_AUTOJOIN)
      
      SAVE_SETUP, WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS = CALLBACK_SETUP_AUTOJOIN[FUNCTION](BUFFER, WRECON_SERVER, WRECON_CHANNEL, WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS)
      
      # SAVE data in case changes were done
      if SAVE_SETUP == True:
        
        WEECHAT_CHANNELS_KEYS = [WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS]
        EXPORT_DATA = setup_autojoin_convert_list2string(WEECHAT_CHANNELS_KEYS)
        
        weechat.command(BUFFER, '/set irc.server.%s.autojoin %s' % (WRECON_SERVER, EXPORT_DATA))
        weechat.command(BUFFER, '/save')
    
    return SAVE_SETUP
  
  #
  # FUNCTION SETUP AUTOJOIN CONVERT STRING TO LIST
  #
  
  def setup_autojoin_convert_string2list(INPUT_STRING):
    
    CHANNELS_AND_KEYS = INPUT_STRING.split(' ')
    CHANNELS_LIST     = CHANNELS_AND_KEYS[0].split(',')
    KEYS_LIST         = ['']
    
    if len(CHANNELS_AND_KEYS) == 2:
      KEYS_LIST       = CHANNELS_AND_KEYS[1].split(',')
      
    OUTPUT_LIST       = [CHANNELS_LIST, KEYS_LIST]
    
    return OUTPUT_LIST
  
  #
  # FUNCTION SETUP AUTOJOIN CONVERT LIST TO STRING
  #
  
  def setup_autojoin_convert_list2string(INPUT_LIST):
    global WRECON_BUFFER_CHANNEL
    
    display_message(WRECON_BUFFER_CHANNEL, 'LIST TO STRING : %s' % INPUT_LIST)
    
    CHANNELS = INPUT_LIST[0]
    KEYS     = INPUT_LIST[1]
    
    CHANNELS_STRING = ','.join(map(str, CHANNELS))
    KEYS_STRING     = ','.join(map(str, KEYS))
    
    CHANNELS_KEYS   = [CHANNELS_STRING, KEYS_STRING]
    
    OUTPUT_STRING   = ' '.join(map(str, CHANNELS_KEYS))
    
    return OUTPUT_STRING
  
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
  
  def setup_autojoin_del(BUFFER, WRECON_SERVER, WRECON_CHANNEL, WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS):
    SAVE_SETUP = False
    
    if WRECON_CHANNEL in WEECHAT_CHANNELS_AUTOJOIN:
      # Find index of my registered channel
      CHANNEL_INDEX = [INDEX for INDEX, ELEMENT in enumerate(WEECHAT_CHANNELS_AUTOJOIN) if WRECON_CHANNEL in ELEMENT]
      for INDEX in CHANNEL_INDEX:
        WEECHAT_CHANNELS_AUTOJOIN.pop(INDEX)
        WEECHAT_CHANNELS_KEYS.pop(INDEX)
      SAVE_SETUP = True
    
    return [SAVE_SETUP, WEECHAT_CHANNELS_AUTOJOIN, WEECHAT_CHANNELS_KEYS]
  
  #
  ###### END FUNCTION SETUP AUTOJOIN ADD / DEL (/ SAVE)

  #####
  #
  # FUNCTION GET BOT ID
  
  def get_bot_id(INPUT_NUMBER_OR_STRING, DATA_OF_BOTS):
    
    INPUT_IS_NUMBER = False
    
    try:
      BOT_ID          = int(INPUT_NUMBER_OR_STRING)
      INPUT_IS_NUMBER = True
    except ValueError:
      BOT_ID          = INPUT_NUMBER_OR_STRING
    
    if INPUT_IS_NUMBER == True:
      INDEX    = BOT_ID
      BOT_LIST = []
      
      if isinstance(DATA_OF_BOTS, dict):
        BOT_LIST = list(DATA_OF_BOTS.keys())
      
      if isinstance(DATA_OF_BOTS, list):
        BOT_LIST = DATA_OF_BOTS
      
      if INDEX == 0 or INDEX > len(BOT_LIST):
        BOT_ID = '%s' % INDEX
      else:
        INDEX  = BOT_ID - 1
        BOT_ID = BOT_LIST[INDEX]
    
    return BOT_ID
  
  #
  ##### END
  
  #####
  #
  # FUNCTION COMPARE VERSION OF COMMAND
  
  def compare_version_of_command(SOURCE_VERSION, TARGET_VERSION):
    # ~ global WRECON_BUFFER_CHANNEL
    VERSION_RESULT = False
    
    SOURCE_VERSION = SOURCE_VERSION.split('.')
    TARGET_VERSION = TARGET_VERSION.split('.')
    
    SOURCE_VERSION = list(map(int, SOURCE_VERSION))
    TARGET_VERSION = list(map(int, TARGET_VERSION ))
    
    
    if SOURCE_VERSION <= TARGET_VERSION:
      VERSION_RESULT = True
    
    # ~ display_message_info(WRECON_BUFFER_CHANNEL, 'compare_version_of_command', 'compare_version_of_command : RESULT : %s - REQUIRED: %s - ACTUAL: %s' % (VERSION_RESULT, SOURCE_VERSION, TARGET_VERSION))
    
    return VERSION_RESULT
  
  #
  ##### END FUNCTION COMPARE COMMAND VERSION
  
  #####
  #
  # VALIDATE COMMAND EXECUTION
  #
  # WEECHAT_DATA BUFFER LOCAL/REMOTE COMMAND TOBOTID FROMBOTID COMMANDID [DATA]
  
  #
  # SETUP VARIABLES OF FUNCTION command_validate
  #
  
  def setup_wrecon_variables_of_validate_command():
    global ID_CALL_LOCAL, ID_CALL_REMOTE, COMMAND_REQUIREMENTS, VERIFY_REQUIREMENTS, DISPLAY_COMMAND
  
    ID_CALL_LOCAL        = {}
    ID_CALL_REMOTE       = {}
    COMMAND_REQUIREMENTS = {}
    VERIFY_REQUIREMENTS  = {}
    DISPLAY_COMMAND      = {}
    
    return
  
  def validate_command(WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID):
    global DISPLAY_COMMAND
    
    FUNCTION = ''
    
    # FIRST WE CHECK COMMAND BELONG TO US OR ADVERTISEMENT HAS BEEN REQUESTED
    COMMAND_CAN_BE_EXECUTED = function_validate_1_check_target_bot(SOURCE, COMMAND, TARGET_BOT_ID)
    
    # DEBUG
    # ~ display_data('DEBUG - validate_command:', WEECHAT_DATA, BUFFER, SOURCE, '', '', '', '', '', COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS)
    # ~ display_message(BUFFER, 'DEBUG - validate_command: COMMAND CAN BE EXECUTED : %s' % COMMAND_CAN_BE_EXECUTED)
    # ~ display_message(BUFFER, 'DEBUG - validate_command: %s' % [WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID])
    
    # WE SIMPLY IGNORE COMMANDS NOT BELOG TO US
    # EXCEPTION REMOTE ADVERTISEMENT, WHICH WAS CHECKED ALSO
    if COMMAND_CAN_BE_EXECUTED == True:
    # HERE WE CONTINUE IF COMMAND BELONG TO US, OR ADVERTIESEMENT WAS REQUESTED
      
      # ASSIGN VARIABLES of LOCAL or REMOTE CALL
      ID_CALL, SCRIPT_CALL, VERIFY_BOT = function_validate_2_setup_variables(SOURCE, TARGET_BOT_ID, SOURCE_BOT_ID)
      
      TARGET_UNIQ_ID = VERIFY_BOT + COMMAND_ID
      
      # SOMETIME WE NEED DISPLAY WHAT IS CALLED (just only in first call)
      if UNIQ_COMMAND_ID in DISPLAY_COMMAND and SOURCE == 'PRE-LOCAL':
        display_message(BUFFER, '[%s] %s EXECUTE > %s %s' % (COMMAND_ID, VERIFY_BOT, COMMAND, COMMAND_ARGUMENTS))
      
      # REMOVE DISPAY ID
      if UNIQ_COMMAND_ID in DISPLAY_COMMAND:
        del DISPLAY_COMMAND[UNIQ_COMMAND_ID]
      
      # DEBUG
      # ~ display_message(BUFFER, 'DEBUG - validate_command: SOURCE : %s : ID_CALL : %s' % (SOURCE, ID_CALL))
      
      # CHECK WE HAVE ASSIGNED UNIQ_COMMAND_ID FROM CALL
      # This is security feature to block 'fake' execution
      if not UNIQ_COMMAND_ID in ID_CALL:
        COMMAND_CAN_BE_EXECUTED = False
        display_message(BUFFER, '[%s] ERROR: CALL ID DOES NOT EXIST' % COMMAND_ID)

      # CHECK COMMAND EXIST
      if COMMAND_CAN_BE_EXECUTED == True and not COMMAND in SCRIPT_CALL:
        COMMAND_CAN_BE_EXECUTED = False
        if SOURCE in ['LOCAL', 'PRE-LOCAL', 'INTERNAL']:
          display_message(BUFFER, '[%s] ERROR: UNKNOWN COMMAND -> %s' % (COMMAND_ID, COMMAND))
        else:
          display_message(BUFFER, '[%s] ERROR: UNKNOWN %s COMMAND -> %s' % (COMMAND_ID, SOURCE, COMMAND))
      
      # CHECK NUMBER OF COMMAND ARGUMENTS, only LOCAL command is checked
      if COMMAND_CAN_BE_EXECUTED == True and SOURCE == 'LOCAL':
        COMMAND_CAN_BE_EXECUTED, ERROR_MESSAGE = function_validate_3_number_of_arguments(COMMAND, COMMAND_ARGUMENTS)
        if COMMAND_CAN_BE_EXECUTED == False:
          display_message(BUFFER, '[%s] ERROR: %s' % (COMMAND_ID, ERROR_MESSAGE))
      
      # CHECK VERSION FOR EXECUTION, only for LOCAL command is checked
      # we need to be sure, that remote bot have required version for execution
      if COMMAND_CAN_BE_EXECUTED == True:
        COMMAND_CAN_BE_EXECUTED = verify_remote_bot_version(BUFFER, COMMAND, VERIFY_BOT, COMMAND_ID)
      
      # CHECK REQUIREMENTS FOR EXECUTION, LOCAL and REMOTE command are checked, and PRE-LOCAL SOURCE is excluded
      if COMMAND_CAN_BE_EXECUTED == True and SOURCE != 'PRE-LOCAL':
        # ~ display_message(BUFFER, 'DEBUG - validate_command: call function_validate_4_requirements(%s)' % [SOURCE, BUFFER, COMMAND, VERIFY_BOT, COMMAND_ID])
        COMMAND_CAN_BE_EXECUTED  = function_validate_4_requirements(SOURCE, BUFFER, COMMAND, VERIFY_BOT, COMMAND_ID)
        # ~ display_message(BUFFER, 'DEBUG - validate_command: COMMAND_CAN_BE_EXECUTED : %s' % COMMAND_CAN_BE_EXECUTED)
        
      if COMMAND_CAN_BE_EXECUTED == False:
        # DEBUG
        # ~ display_message(BUFFER, 'DEBUG - validate_command: call verify_wait4verify_1_prepare(%s)' % [WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID, TARGET_UNIQ_ID])
        verify_wait4verify_1_prepare(WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID, TARGET_UNIQ_ID)
      
        
      if COMMAND_CAN_BE_EXECUTED == True:
        FUNCTION = SCRIPT_CALL[COMMAND]
      else:
        verify_wait4verify_2_report(BUFFER, COMMAND, TARGET_UNIQ_ID, COMMAND_ID, VERIFY_BOT, SOURCE)
      
    if COMMAND_CAN_BE_EXECUTED == False:
      FUNCTION = ''
    
    return [COMMAND_CAN_BE_EXECUTED, FUNCTION]
  
  #
  # VALIDATE - WAIT FOR VERIFICATION AFTER CHECK OF REQUIREMENT
  # This is called when COMMAND_CAN_BE_EXECUTED is False
  
  def verify_wait4verify_1_prepare(WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID, TARGET_UNIQ_ID):
    global WAIT_FOR_VERIFICATION
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_wait4verify_1_prepare : %s' % [WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID, TARGET_UNIQ_ID])
    # ~ display_message(BUFFER, 'DEBUG - verify_wait4verify_1_prepare : WAIT_FOR_VERIFICATION : %s' % WAIT_FOR_VERIFICATION)
    
    # We now verify, if DATA of additional verification has been prepared
    if TARGET_UNIQ_ID in WAIT_FOR_VERIFICATION:
      CALL_DATA    = WAIT_FOR_VERIFICATION[TARGET_UNIQ_ID]
      CALL_COMMAND = CALL_DATA[0]
      CALL_DATA.pop(0)
      # DEBUG
      # ~ display_message(BUFFER, 'DEBUG - verify_wait4verify_1_prepare: CALL_DATA : %s' % CALL_DATA)
      WWEECHAT_DATA, WBUFFER, WSOURCE, WCOMMAND, WTARGET_BOT_ID, WSOURCE_BOT_ID, WCOMMAND_ID, WCOMMAND_ARGUMENTS, WUNIQ_COMMAND_ID = CALL_DATA
      
      # SAVE ACTUAL DATA INTO WAIT_FOR_VERIFICATION
      WAIT_FOR_VERIFICATION[TARGET_UNIQ_ID] = [command_recall, WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID]
      
      # THEN CALL ADDITIONAL VERIFICATION COMMAND
      CALL_COMMAND(WWEECHAT_DATA, WBUFFER, WSOURCE, WCOMMAND, WTARGET_BOT_ID, WSOURCE_BOT_ID, WCOMMAND_ID, WCOMMAND_ARGUMENTS, WUNIQ_COMMAND_ID)
    else:
      # Here we know that additional verification has been executed, but result failed
      display_message(BUFFER, '[%s] %s < REQUIREMENT RESULT UNSUCCESSFUL' % (COMMAND_ID, SOURCE_BOT_ID))
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_wait4verify_1_prepare : %s' % [WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID, TARGET_UNIQ_ID])
    # ~ display_message(BUFFER, 'DEBUG - verify_wait4verify_1_prepare : WAIT_FOR_VERIFICATION : %s' % WAIT_FOR_VERIFICATION)
    
    return
  #
  # VALIDATE - WAIT FOR VERIFICATION AFTER ALL CHECKS
  #
  
  def verify_wait4verify_2_report(BUFFER, COMMAND, TARGET_UNIQ_ID, COMMAND_ID, VERIFY_BOT, SOURCE):
    global WAIT_FOR_VERIFICATION
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_wait4verify_2_report: %s' % [BUFFER, COMMAND, TARGET_UNIQ_ID, COMMAND_ID, VERIFY_BOT, SOURCE])
    # ~ display_message(BUFFER, 'DEBUG - verify_wait4verify_2_report: WAIT_FOR_VERIFICATION : %s' % WAIT_FOR_VERIFICATION)
    
    # Check we are waiting for result of verification
    if not TARGET_UNIQ_ID in WAIT_FOR_VERIFICATION:
      display_message(BUFFER, '[%s] %s < EXECUTION DENIED' % (COMMAND_ID, VERIFY_BOT))
      cleanup_unique_command_id(SOURCE, TARGET_UNIQ_ID)
    else:
      display_message(BUFFER, '[%s] VERIFICATION OF REMOTE BOT > %s < IS IN PROGRESS' % (COMMAND_ID, VERIFY_BOT))
    
    return
  
  #
  # VALIDATE - CHECK COMMAND BELOGN TO US, or
  #          - CHECK COMMAND IS GLOBAL ADVERTISEMENT, or
  #          - CHECK COMMAND WAS CALLED BY US
  
  def function_validate_1_check_target_bot(SOURCE, COMMAND, TARGET_BOT_ID):
    global WRECON_BOT_ID, BUFFER_CMD_ADV_REQ
    
    RETURN_RESULT = False
    
    if TARGET_BOT_ID == WRECON_BOT_ID:
      RETURN_RESULT = True
    
    if COMMAND == BUFFER_CMD_ADV_REQ:
      RETURN_RESULT = True
    
    if SOURCE in ['LOCAL', 'PRE-LOCAL', 'INTERNAL']:
      RETURN_RESULT = True
    
    return RETURN_RESULT
  
  #
  # VALIDATE - SETUP VARIABLES
  #
  
  def function_validate_2_setup_variables(SOURCE, TARGET_BOT_ID, SOURCE_BOT_ID):
    global ID_CALL_LOCAL, ID_CALL_REMOTE, SCRIPT_COMMAND_CALL, PREPARE_USER_CALL, SCRIPT_INTERNAL_CALL, WRECON_BUFFER_CHANNEL
  
    # PREPARE VARIABLES OF LOCAL CALL
    # Command was called by USER
    if SOURCE == 'LOCAL':
      ID_CALL     = ID_CALL_LOCAL
      VERIFY_BOT  = TARGET_BOT_ID
      SCRIPT_CALL = SCRIPT_COMMAND_CALL
    
    # PREPARE VARIABLES OF PRE-LOCAL CALL
    # Command was called by command_pre_validation
    if SOURCE == 'PRE-LOCAL':
      ID_CALL     = ID_CALL_LOCAL
      VERIFY_BOT  = TARGET_BOT_ID
      SCRIPT_CALL = PREPARE_USER_CALL
    
    # PREPARE VARIABLES OF INTERNAL CALL
    # Command is usually called when additional advertisement or verification is needed
    if SOURCE == 'INTERNAL':
      ID_CALL     = ID_CALL_LOCAL
      VERIFY_BOT  = TARGET_BOT_ID
      SCRIPT_CALL = SCRIPT_INTERNAL_CALL
    
    # PREPARE VARIABLES OF REMOTE CALL
    # Command we received from REMOTE BOT
    if SOURCE == 'REMOTE':
      ID_CALL     = ID_CALL_REMOTE
      VERIFY_BOT  = SOURCE_BOT_ID
      SCRIPT_CALL = SCRIPT_BUFFER_CALL
    
    # DEBUG
    # ~ display_message(WRECON_BUFFER_CHANNEL, 'DEBUG - function_validate_2_setup_variables: %s' % ID_CALL)
    
    # We return variables of tables of current command
    return [ID_CALL, SCRIPT_CALL, VERIFY_BOT]
  
  #
  # VALIDATE COMMAND - CHECK NUMBER OF ARGUMENTS OF COMMAND
  #
  
  def function_validate_3_number_of_arguments(COMMAND, COMMAND_ARGUMENTS):
    global ARGUMENTS_REQUIRED, ARGUMENTS_OPTIONAL, ARGUMENTS_REQUIRED_MINIMAL
    
    VERIFY_RESULT       = True
    OUT_MESSAGE         = 'CORRECT NUMBER OF ARGUMENTS'
    
    if COMMAND_ARGUMENTS == '':
      NUMBER_OF_ARGUMENTS = 0
      ARGUMENTS_LIST = []
    else:
      ARGUMENTS_LIST = COMMAND_ARGUMENTS.split(' ')
      NUMBER_OF_ARGUMENTS = int(len(ARGUMENTS_LIST))
    
    # DEBUG
    # ~ global WRECON_BUFFER_CHANNEL
    # ~ display_message(WRECON_BUFFER_CHANNEL, 'DEBUG - function_validate_3_number_of_arguments: COMMAND : %s  : %s : ARGUMENTS : %s' % (COMMAND, NUMBER_OF_ARGUMENTS, ARGUMENTS_LIST))
    
    # CHECK NO ARGUMENTS
    NO_ARGUMENTS = True
    for CHECK_ARGUMENTS in [ARGUMENTS_REQUIRED, ARGUMENTS_OPTIONAL, ARGUMENTS_REQUIRED_MINIMAL]:
      if COMMAND in CHECK_ARGUMENTS:
        NO_ARGUMENTS = False
    
    if NO_ARGUMENTS == True and NUMBER_OF_ARGUMENTS > 0:
      VERIFY_RESULT = False
      OUT_MESSAGE = 'COMMAND  > %s < REQUIRE NO ARGUMENTS, BUT %s HAS BEEN PROVIDED' % (COMMAND, NUMBER_OF_ARGUMENTS)
    
    # CHECK ARGUMENTS REQUIRED
    if COMMAND in ARGUMENTS_REQUIRED:
      if NUMBER_OF_ARGUMENTS != ARGUMENTS_REQUIRED[COMMAND]:
        VERIFY_RESULT = False
        OUT_MESSAGE = 'COMMAND > %s < REQUIRE %s ARGUMENT(S), BUT %s HAS BEEN PROVIDED' % (COMMAND, ARGUMENTS_REQUIRED[COMMAND], NUMBER_OF_ARGUMENTS)
    
    # CHECK OPTIONAL ARGUMENTS
    if COMMAND in ARGUMENTS_OPTIONAL:
      if NUMBER_OF_ARGUMENTS > ARGUMENTS_OPTIONAL[COMMAND]:
        VERIFY_RESULT = False
        OUT_MESSAGE = 'COMMAND > %s < REQUIRE MAXIMUM %s AGRUMENT(S), BUT %s HAS BEEN PROVIDED' % (COMMAND, ARGUMENTS_OPTIONAL[COMMAND], NUMBER_OF_ARGUMENTS)
    
    # CHECK MINIMAL ARGUMENTS
    if COMMAND in ARGUMENTS_REQUIRED_MINIMAL:
      if NUMBER_OF_ARGUMENTS < ARGUMENTS_REQUIRED_MINIMAL[COMMAND]:
        VERIFY_RESULT = False
        OUT_MESSAGE = 'COMMAND > %s < REQUIRE MINIMUM %s ARGUMENT(S), BUT %s HAS BEEN PROVIDED' % (COMMAND, ARGUMENTS_REQUIRED_MINIMAL[COMMAND], NUMBER_OF_ARGUMENTS)
    
    # True  = return command contain correct number of argumens
    # False = return command contain incorrect number of arguments
    
    return [VERIFY_RESULT, OUT_MESSAGE]
  #
  # CHECK COMMAND REQUIREMENTS
  #
  
  def function_validate_4_requirements(SOURCE, BUFFER, COMMAND, VERIFY_BOT, COMMAND_ID):
    global WRECON_BOT_ID, COMMAND_REQUIREMENTS_LOCAL, COMMAND_REQUIREMENTS_REMOTE
    
    COMMAND_CAN_BE_EXECUTED = True
    
    if VERIFY_BOT == WRECON_BOT_ID or (VERIFY_BOT == COMMAND_ID and SOURCE == 'LOCAL'):
      return COMMAND_CAN_BE_EXECUTED
    
    if SOURCE in ['LOCAL', 'PRE-LOCAL', 'INTERNAL']:
      COMMAND_REQUIREMENTS = COMMAND_REQUIREMENTS_LOCAL
    else:
      COMMAND_REQUIREMENTS = COMMAND_REQUIREMENTS_REMOTE
    
    if COMMAND in COMMAND_REQUIREMENTS:
      COMMAND_CAN_BE_EXECUTED = COMMAND_REQUIREMENTS[COMMAND](BUFFER, VERIFY_BOT, COMMAND_ID)
      
    return COMMAND_CAN_BE_EXECUTED
  
  #
  # VALIDATE COMMAND VERSION (some commands are not in previous version)
  # this command require remote bot is advertised
  
  def verify_remote_bot_version(BUFFER, COMMAND, VERIFY_BOT, COMMAND_ID):
    global WRECON_BOT_ID, COMMAND_VERSION, WRECON_REMOTE_BOTS_ADVERTISED, WAIT_FOR_VERSION
    
    COMMAND_CAN_BE_EXECUTED = True
    
    if VERIFY_BOT == WRECON_BOT_ID:
      return COMMAND_CAN_BE_EXECUTED
    
    UNIQ_COMMAND_ID = VERIFY_BOT + COMMAND_ID
    
    if COMMAND in COMMAND_VERSION:
      # Automatically Check remote BOT has been advertised
      # This is necessary to know version of remote BOT
      COMMAND_CAN_BE_EXECUTED  = verify_remote_bot_advertised(BUFFER, VERIFY_BOT, COMMAND_ID)
      
      if COMMAND_CAN_BE_EXECUTED == True:
        REMOTE_BOT_NAME         = WRECON_REMOTE_BOTS_ADVERTISED[VERIFY_BOT].split('|')[0]
        TARGET_VERSION          = WRECON_REMOTE_BOTS_ADVERTISED[VERIFY_BOT].split('|')[1]
        SOURCE_VERSION          = COMMAND_VERSION[COMMAND]
        
        COMMAND_CAN_BE_EXECUTED = compare_version_of_command(SOURCE_VERSION, TARGET_VERSION)
        
        if COMMAND_CAN_BE_EXECUTED == False:
          display_message(BUFFER, '[%s] %s < MINIMAL VERSION %s IS REQUIRED ON %s (%s)' % (COMMAND_ID, COMMAND, SOURCE_VERSION, VERIFY_BOT, REMOTE_BOT_NAME))
        
      verify_remote_bot_version_after_advertise(BUFFER, VERIFY_BOT, COMMAND_ID)
    
    return COMMAND_CAN_BE_EXECUTED
  
  def verify_remote_bot_version_after_advertise(BUFFER, VERIFY_BOT, COMMAND_ID):
    global WAIT_FOR_VERIFICATION, WAIT_FOR_VERSION
    
    UNIQ_COMMAND_ID = VERIFY_BOT + COMMAND_ID
    
    if UNIQ_COMMAND_ID in WAIT_FOR_VERSION:
      del WAIT_FOR_VERSION[UNIQ_COMMAND_ID]
      if UNIQ_COMMAND_ID in WAIT_FOR_VERIFICATION:
        del WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID]
    else:
      WAIT_FOR_VERSION[UNIQ_COMMAND_ID] = 'VERSION WAITING FOR ADVERTISE'
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_remote_bot_version_after_advertise: WAIT_FOR_VERSION      : %s' % WAIT_FOR_VERSION)
    # ~ display_message(BUFFER, 'DEBUG - verify_remote_bot_version_after_advertise: WAIT_FOR_VERIFICATION : %s' % WAIT_FOR_VERIFICATION)
    
    return
  
  #
  # CLEANUP ID VARIABLES (LOCAL or REMOTE) AFTER EXECUTION
  #
  
  def cleanup_unique_command_id(SOURCE, UNIQ_COMMAND_ID):
    if SOURCE in ['LOCAL', 'PRE-LOCAL', 'INTERNAL']:
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
  
  def verify_remote_bot_control(BUFFER, VERIFY_BOT, COMMAND_ID):
    global WRECON_BOT_ID, WRECON_REMOTE_BOTS_CONTROL
    
    COMMAND_CAN_BE_EXECUTED = True
    
    if VERIFY_BOT == WRECON_BOT_ID:
      return COMMAND_CAN_BE_EXECUTED
    
    # CHECK WE HAVE ADDED BOT
    if not VERIFY_BOT in WRECON_REMOTE_BOTS_CONTROL:
      COMMAND_CAN_BE_EXECUTED = False
      display_message(BUFFER, '[%s] %s < REMOTE BOT IS NOT ADDED/REGISTERED' % (COMMAND_ID, VERIFY_BOT))
    
    return COMMAND_CAN_BE_EXECUTED
  
  #
  # VERIFY REMOTE BOT WAS ADVERTISED
  #
  
  def verify_remote_bot_advertised(BUFFER, VERIFY_BOT, COMMAND_ID):
    global WRECON_BOT_ID, WRECON_REMOTE_BOTS_ADVERTISED, ID_CALL_LOCAL, WAIT_FOR_VERIFICATION, WAIT_FOR_ADVERTISE_ADA
    
    COMMAND_CAN_BE_EXECUTED = True
    
    if VERIFY_BOT == WRECON_BOT_ID:
      return COMMAND_CAN_BE_EXECUTED
    
    # IF WE ARE MISSING DATA OF REMOTE BOT, THEN WE REQUEST IT
    UNIQ_COMMAND_ID = VERIFY_BOT + COMMAND_ID
    
    COMMAND_ADA = 'ADA %s %s %s' % (VERIFY_BOT, COMMAND_ID, UNIQ_COMMAND_ID)
    
    if not VERIFY_BOT in WRECON_REMOTE_BOTS_ADVERTISED:
      
      COMMAND_CAN_BE_EXECUTED        = False
      ID_CALL_LOCAL[UNIQ_COMMAND_ID] = 'ADDITIONAL ADVERTISE REQUEST'
      
      # WE NEED GET ADVERTISEMENET DATA OF REMOTE BOT ADDITIONALLY, IF IT WAS NOT REQUESTED
      if UNIQ_COMMAND_ID in WAIT_FOR_ADVERTISE_ADA:
        del WAIT_FOR_ADVERTISE_ADA[UNIQ_COMMAND_ID]
        del WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID]
      else:
        WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID] = [command_pre_validation, '', BUFFER, 'INTERNAL', '', '', '', '', '', COMMAND_ADA]
        WAIT_FOR_ADVERTISE_ADA[UNIQ_COMMAND_ID]      = COMMAND_ADA
    else:
      if UNIQ_COMMAND_ID in WAIT_FOR_ADVERTISE_ADA:
        if COMMAND_ADA == WAIT_FOR_ADVERTISE_ADA[UNIQ_COMMAND_ID][9]:
          del WAIT_FOR_ADVERTISE_ADA[UNIQ_COMMAND_ID]
          del WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID]
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_remote_bot_advertised: WAIT_FOR_VERIFICATION   : %s' % WAIT_FOR_VERIFICATION)
    # ~ display_message(BUFFER, 'DEBUG - verify_remote_bot_advertised: COMMAND_CAN_BE_EXECUTED : %s' % COMMAND_CAN_BE_EXECUTED)
    
    return COMMAND_CAN_BE_EXECUTED
  
  #
  # VERIFY REMOTE BOT WAS VERIFIED
  # This function ensure verification of remote bot
  # Verification require remote BOT is advertised
  # In case remote BOT was not advertised, current function is not called, and command will end up with error message
  
  def verify_remote_bot_verified(BUFFER, VERIFY_BOT, COMMAND_ID):
    global WRECON_BOT_ID, WRECON_REMOTE_BOTS_VERIFIED, WAIT_FOR_VERIFICATION
    
    COMMAND_CAN_BE_EXECUTED = True
    
    if VERIFY_BOT == WRECON_BOT_ID:
      return COMMAND_CAN_BE_EXECUTED
    
    # IF WE ARE MISSING DATA OF REMOTE BOT, THEN WE REQUEST IT
    UNIQ_COMMAND_ID = VERIFY_BOT + COMMAND_ID
    
    # TARGET BOT will be in saved table only in case verification was successful
    if not VERIFY_BOT in WRECON_REMOTE_BOTS_VERIFIED:
      
      # WE NEED BE SURE REMOTE BOT IS ADVERTISED
      COMMAND_CAN_BE_EXECUTED = verify_remote_bot_advertised(BUFFER, VERIFY_BOT, COMMAND_ID)
      
      if COMMAND_CAN_BE_EXECUTED == True:
        COMMAND_CAN_BE_EXECUTED = verify_remote_bot_verified_after_advertise(BUFFER, VERIFY_BOT, COMMAND_ID)
    else:
      verify_remote_bot_verified_after_verified(BUFFER, VERIFY_BOT, COMMAND_ID)
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_remote_bot_verified: WAIT_FOR_VERIFICATION   : %s' % WAIT_FOR_VERIFICATION)
    # ~ display_message(BUFFER, 'DEBUG - verify_remote_bot_verified: COMMAND_CAN_BE_EXECUTED : %s' % COMMAND_CAN_BE_EXECUTED)
    
    return COMMAND_CAN_BE_EXECUTED
  
  def verify_remote_bot_verified_after_advertise(BUFFER, VERIFY_BOT, COMMAND_ID):
    global WAIT_FOR_VERIFICATION, WAIT_FOR_VALIDATION
    
    COMMAND_CAN_BE_EXECUTED = False
    UNIQ_COMMAND_ID = VERIFY_BOT + COMMAND_ID
    ID_CALL_LOCAL[UNIQ_COMMAND_ID] = 'ADDITIONAL VERIFICATION REQUEST'
    
    COMMAND_VAL = 'VERIFY %s %s %s' % (VERIFY_BOT, COMMAND_ID, UNIQ_COMMAND_ID)
    
    # WE NEED GET VERIFIED DATA OF REMOTE BOT ADDITIONALLY, IF IT WAS NOT REQUESTED
    if UNIQ_COMMAND_ID in WAIT_FOR_VALIDATION:
      del WAIT_FOR_VALIDATION[UNIQ_COMMAND_ID]
      if UNIQ_COMMAND_ID in WAIT_FOR_VERIFICATION:
        del WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID]
    else:
    # Prepare data for additional verification
      WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID] = [command_pre_validation, '', BUFFER, 'INTERNAL', '', '', '', '', '', COMMAND_VAL]
      WAIT_FOR_VALIDATION[UNIQ_COMMAND_ID]      = COMMAND_VAL
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_remote_bot_verified_after_advertise: WAIT_FOR_VERIFICATION   : %s' % WAIT_FOR_VERIFICATION)
    # ~ display_message(BUFFER, 'DEBUG - verify_remote_bot_verified_after_advertise: COMMAND_CAN_BE_EXECUTED : %s' % COMMAND_CAN_BE_EXECUTED)
    
    return COMMAND_CAN_BE_EXECUTED
  
  def verify_remote_bot_verified_after_verified(BUFFER, VERIFY_BOT, COMMAND_ID):
    global WAIT_FOR_VERIFICATION, WAIT_FOR_VALIDATION
    
    UNIQ_COMMAND_ID = VERIFY_BOT + COMMAND_ID
    
    if UNIQ_COMMAND_ID in WAIT_FOR_VALIDATION:
      del WAIT_FOR_VALIDATION[UNIQ_COMMAND_ID]
      if UNIQ_COMMAND_ID in WAIT_FOR_VERIFICATION:
        del WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID]
    
    return
  
  #
  # VERIFY REMOTE BOT WAS GRANTED (granted BOT)
  # verification require remote BOT is verified
  
  def verify_remote_bot_granted(BUFFER, VERIFY_BOT, COMMAND_ID):
    global WRECON_BOT_ID
    
    COMMAND_CAN_BE_EXECUTED = True
    
    if VERIFY_BOT == WRECON_BOT_ID:
      return COMMAND_CAN_BE_EXECUTED
    
    global WRECON_REMOTE_BOTS_GRANTED
    
    # CHECK WE GRANTED REMOTE BOT
    if not VERIFY_BOT in WRECON_REMOTE_BOTS_GRANTED:
      COMMAND_CAN_BE_EXECUTED = False
      display_message(BUFFER, '[%s] %s < REMOTE BOT IS NOT GRANTED' % (COMMAND_ID, VERIFY_BOT))
    else:
      # THEN CHECK GRANTED BOT WAS VERIFIED
      COMMAND_CAN_BE_EXECUTED  = verify_remote_bot_verified(BUFFER, VERIFY_BOT, COMMAND_ID)
    
    return COMMAND_CAN_BE_EXECUTED
  
  ######
  #
  # ALL COMMANDS

  #####
  #
  # COMMAND AND FUNCTIONS CHECK AND UPDATE
  
  #
  # UPDATE - PREPARE COMMAND FOR VALIDATION AND EXECUTION
  #
  
  def prepare_command_update(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_BOT_ID, BUFFER_CMD_UPD_EXE, WRECON_REMOTE_BOTS_CONTROL, WAIT_FOR_VERIFICATION
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - prepare_command_update: %s' % [WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST])
    # ~ display_message(BUFFER, 'DEBUG - prepare_command_update: WAIT_FOR_VERIFICATION : %s' % WAIT_FOR_VERIFICATION)
    
    COMMAND = 'UPDATE'
    
    if not COMMAND_ARGUMENTS_LIST:
      TARGET_BOT_ID = WRECON_BOT_ID
    else:
      TARGET_BOT_ID          = get_bot_id(COMMAND_ARGUMENTS_LIST[0], WRECON_REMOTE_BOTS_CONTROL)
      COMMAND_ARGUMENTS_LIST = [TARGET_BOT_ID]
      
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    
    # ~ display_data('prepare_command_update', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # UPDATE
  #
  
  def user_command_update(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_BOT_ID, BUFFER_CMD_UPD_EXE, WRECON_REMOTE_BOTS_ADVERTISED
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    # DEBUG
    # ~ display_data('user_command_update', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    
    
    if not TARGET_BOT_ID == WRECON_BOT_ID:
      REMOTE_BOT_NAME    = WRECON_REMOTE_BOTS_ADVERTISED[TARGET_BOT_ID].split('|')[0]
      REMOTE_BOT_VERSION = WRECON_REMOTE_BOTS_ADVERTISED[TARGET_BOT_ID].split('|')[1]
      display_message(BUFFER, '[%s] %s < UPDATE REQUESTED (%s [v%s])' % (COMMAND_ID, TARGET_BOT_ID, REMOTE_BOT_NAME, REMOTE_BOT_VERSION))
      weechat.command(WRECON_BUFFER_CHANNEL, '%s %s %s %s' % (BUFFER_CMD_UPD_EXE, TARGET_BOT_ID, WRECON_BOT_ID, COMMAND_ID))
    else:
      OUTPUT_MESSAGE = ['']
      OUTPUT_MESSAGE.append('--- WRECON UPDATE CHECK AND INSTALL ---')
      
      # CALL CHECK FOR NEW UPDATE
      UPDATE_CONTINUE, UPDATE_NEXT_FUNCTION, OUTPUT_MESSAGE, LATEST_RELEASE, ARCHIVE_FILE, DOWNLOAD_URL, EXTRACT_SUBDIRECTORY = function_update_1_check(OUTPUT_MESSAGE)
      
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
      
      OUTPUT_MESSAGE.append('')
      display_message(BUFFER, OUTPUT_MESSAGE)
      
      # AFTER SUCCESSFUL INSTALLATION WE CAN RESTART
      if UPDATE_CONTINUE == True:
        global SCRIPT_FILE
        display_message(BUFFER, 'RESTARTING WRECON...')
        weechat.command(BUFFER, '/wait 3s /script reload %s' % SCRIPT_FILE)
    
    cleanup_unique_command_id(SOURCE, UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
    
  #
  # UPDATE - CHECK (new version in URL)
  #
  
  def function_update_1_check(OUTPUT_MESSAGE):
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
      
      ACTUAL_VER = SCRIPT_VERSION.split('.')
      LATEST_VER = LATEST_RELEASE.split('.')
      
      ACTUAL_VERSION = list(map(int, ACTUAL_VER))
      LATEST_RELEASE = list(map(int, LATEST_VER))
      
      if ACTUAL_VERSION >= LATEST_RELEASE:
        OUTPUT_MESSAGE.append('WRECON IS UP TO DATE')
      else:
        global SCRIPT_FILE
        UPDATE_EXIST         = True
        NEXT_FUNCTION        = function_update_2_prepare_dir
        ARCHIVE_FILE         = '%s.tar.gz' % LATEST_RELEASE
        DOWNLOAD_URL         = '%s/%s' % (BASE_URL, ARCHIVE_FILE)
        EXTRACT_SUBDIRECTORY = '%s-%s' % (SCRIPT_FILE.split('.')[0], LATEST_RELEASE)
        
        OUTPUT_MESSAGE.append('FOUND NEW RELEASE')        
        OUTPUT_MESSAGE.append('DOWNLOAD URL    : %s' % DOWNLOAD_URL)

    return [UPDATE_EXIST, NEXT_FUNCTION, OUTPUT_MESSAGE, LATEST_RELEASE, ARCHIVE_FILE, DOWNLOAD_URL, EXTRACT_SUBDIRECTORY]
  
  #
  # UPDATE - PREPARE DOWNLOAD DIR
  #
  
  def function_update_2_prepare_dir(OUTPUT_MESSAGE):
    ENVIRONMENT_VARIABLES = os.environ
    DOWNLOAD_DIRECTORY    = '%s/%s' % (ENVIRONMENT_VARIABLES['HOME'], '.wrecon-user_command_update')
    
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
      NEXT_FUNCTION = function_update_3_download
    
    return [DIRECTORY_PREPARED, NEXT_FUNCTION, OUTPUT_MESSAGE, DOWNLOAD_DIRECTORY]
  
  #
  # UPDATE - DOWNLOAD (new file from URL)
  # 
  
  def function_update_3_download(OUTPUT_MESSAGE, DOWNLOAD_DIRECTORY, ARCHIVE_FILE, DOWNLOAD_URL):
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
      NEXT_FUNCTION = function_update_4_extract_archive
    
    return [DOWNLOAD_PREPARED, NEXT_FUNCTION, OUTPUT_MESSAGE]
  
  #
  # UPDATE - EXTRACT ARCHIVE (from downloaded file)
  #
  
  def function_update_4_extract_archive(OUTPUT_MESSAGE, DOWNLOAD_DIRECTORY, ARCHIVE_FILE):
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
      NEXT_FUNCTION = function_update_5_verify_signature
    
    return [EXTRACT_PREPARED, NEXT_FUNCTION, OUTPUT_MESSAGE]
  
  #
  # UPDATE - VERIFY FILE (SIGNATURE)
  #
  
  def function_update_5_verify_signature(OUTPUT_MESSAGE, DOWNLOAD_DIRECTORY, EXTRACT_SUBDIRECTORY):
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
          NEXT_FUNCTION        = function_update_6_install
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
  
  def function_update_6_install(OUTPUT_MESSAGE, INSTALL_FILE):
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
  # UPDATE - REQUEST, here we decide to sent command to buffer for remote bot, or we will update itself
  #
  
  def buffer_command_update_1_requested(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    
    display_message(BUFFER, '[%s] %s < UPDATE RECEIVED' % (COMMAND_ID, SOURCE_BOT_ID))
    user_command_update(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # UPDATE - SETUP VARIABLES
  #
  
  def setup_command_variables_update():
    global BUFFER_CMD_UPD_EXE
    BUFFER_CMD_UPD_EXE = '%sE-UPD' % (COMMAND_IN_BUFFER)
    
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, COLOR_TEXT
    
    global HELP_COMMAND
    
    HELP_COMMAND['UP'] = '''
%(bold)s%(italic)s--- UP[DATE] [BotID]|[INDEX]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
 Update script from github. This will check new released version, and in case newest version is found, it will trigger update.
 You can also update remote BOT if you are GRANTED to do. With no argument it will trigger update of local BOT, else update for remote BOT will be called.
 Remote BOT can be chosen by BOT ID or INDEX number of list of ADDED.
   /wrecon UP
   /wrecon UPDATE %s
   /wrecon UP 4
''' % (get_random_string(16))
    
    HELP_COMMAND['UPDATE'] = HELP_COMMAND['UP']
    
    SCRIPT_ARGS                       = SCRIPT_ARGS + ' | [UP[DATE] [BotID]]|[INDEX]'
    SCRIPT_ARGS_DESCRIPTION           = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['UPDATE']
    
    global SHORT_HELP
    
    SHORT_HELP                       = SHORT_HELP + '''
UPDATE             UP[DATE] [BotID]|<INDEX>'''
    
    global ARGUMENTS_OPTIONAL
    ARGUMENTS_OPTIONAL['UPDATE'] = 1
    
    global SCRIPT_COMPLETION, SCRIPT_COMMAND_CALL, PREPARE_USER_CALL, SCRIPT_BUFFER_CALL, COMMAND_VERSION, GLOBAL_VERSION_LIMIT
    SCRIPT_COMPLETION              = SCRIPT_COMPLETION + ' || UP || UPDATE'
    SCRIPT_COMMAND_CALL['UPDATE']  = user_command_update
    
    PREPARE_USER_CALL['UP']               = prepare_command_update
    PREPARE_USER_CALL['UPDATE']           = PREPARE_USER_CALL['UP']
    PREPARE_USER_CALL[BUFFER_CMD_UPD_EXE] = PREPARE_USER_CALL['UP']
    
    SCRIPT_BUFFER_CALL[BUFFER_CMD_UPD_EXE] = buffer_command_update_1_requested
    
    COMMAND_VERSION['UP']               = '1.10'
    COMMAND_VERSION['UPDATE']           = COMMAND_VERSION['UP']
    COMMAND_VERSION[BUFFER_CMD_UPD_EXE] = GLOBAL_VERSION_LIMIT
    
    global COMMAND_REQUIREMENTS_LOCAL, COMMAND_REQUIREMENTS_REMOTE
    COMMAND_REQUIREMENTS_LOCAL['UPDATE']            = verify_remote_bot_control
    COMMAND_REQUIREMENTS_REMOTE[BUFFER_CMD_UPD_EXE] = verify_remote_bot_granted
    
    return
    
  #
  ##### END COMMAND AND FUNCTION CHECK AND UPDATE
  
  #####
  #
  # BUFFER COMMAND VERIFY REMOTE BOT
  # Current command is INTERNAL only and is called automatically when needed
  
  #
  # VERIFY - PREPARE INTERNAL COMMAND VARIABLES
  #
  
  def prepare_command_verify(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global BUFFER_CMD_VAL_EXE, BUFFER_CMD_VAL_EXE, WRECON_BOT_ID
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - prepare_command_verify: %s' % [WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST])
    
    SOURCE_BOT_ID = WRECON_BOT_ID
    
    COMMAND = 'VERIFY'
    
    if len(COMMAND_ARGUMENTS_LIST) == 0:
      TARGET_BOT_ID   = ''
      UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    else:
      TARGET_BOT_ID   = COMMAND_ARGUMENTS_LIST[0]
      UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # VERIFY - REQUEST
  # Called from validation, we are requesting information from remote BOT
  # Will not be called when we are missing ADVERTISE data of remote BOT
  
  def buffer_command_verify(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global BUFFER_CMD_VAL_EXE, BUFFER_CMD_VAL_ERR, WAIT_FOR_REMOTE_DATA, VERIFY_RESULT_VAL, TIMEOUT_COMMAND_L2
    global WRECON_BOT_KEY, VERIFICATION_PROTOCOL, WRECON_REMOTE_BOTS_GRANTED_SECRET
    
    # DEBUG
    # ~ display_data('DEBUG - buffer_command_verify:', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    
    UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    
    ENCRYPT_LEVEL  = get_target_level_01_encryption(TARGET_BOT_ID)
    
    ENCRYPT_KEY1   = WRECON_BOT_KEY
    ENCRYPT_KEY2   = ''
    SEND_DATA      = ''
    L2_PROTOCOL    = ''
    ERROR          = False
    
    VERIFY_COMMAND = BUFFER_CMD_VAL_EXE
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify: ENCRYPT_LEVEL : %s' % ENCRYPT_LEVEL)
    
    # We need determine which verification will be used
    if ENCRYPT_LEVEL > 0:
      ENCRYPT_LEVEL, REMOTE_SECRET_SYSINFO, REMOTE_SECRET_KEY = get_granted_secret(TARGET_BOT_ID)
      # If we have no DATA of REMOTE bot, then it is first initialisation
      if ENCRYPT_LEVEL == 1:
        INITIAL_FUNCTION  = list(VERIFICATION_PROTOCOL)[0]
        L2_PROTOCOL       = VERIFICATION_PROTOCOL[INITIAL_FUNCTION][0]
        protocol_function = VERIFICATION_PROTOCOL[INITIAL_FUNCTION][2]
        # Call the function for prepare all necessary variables
        ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA = protocol_function(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
        if ERROR == True:
          VERIFY_COMMAND = BUFFER_CMD_VAL_ERR
      # Here we have DATA of REMOTE bot, we try verify by usual way with enhanced encryption
      else:
        ENCRYPT_KEY2 = REMOTE_SECRET_SYSINFO
    
    if ERROR == False:
      RANDOM_NUMBER = random.randint(7,31)
      SECRET_DATA   = get_random_string(RANDOM_NUMBER)
      SECRET_HASH   = get_hash(SECRET_DATA)
      
      if L2_PROTOCOL and SEND_DATA:
        SECRET_DATA = '%s %s' % (SECRET_DATA, SEND_DATA)
      
      ENCRYPT_SEECRET_DATA                  = string_encrypt(ENCRYPT_LEVEL, SECRET_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
      WAIT_FOR_REMOTE_DATA[UNIQ_COMMAND_ID] = SECRET_HASH
      
      # SEND INITIAL REQUEST FOR VERIFICATION TO REMOTE BOT
      if L2_PROTOCOL and SEND_DATA:
        ENCRYPT_SEECRET_DATA = '%s %s' % (INITIAL_FUNCTION, ENCRYPT_SEECRET_DATA)
        
      weechat.command(BUFFER, '%s %s %s %s %s' % (VERIFY_COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, ENCRYPT_SEECRET_DATA))
      VERIFY_RESULT_VAL[UNIQ_COMMAND_ID] = weechat.hook_timer(TIMEOUT_COMMAND_L2*1000, 0, 1, 'function_verify_wait_result', UNIQ_COMMAND_ID)
    else:
      weechat.command(BUFFER, '%s %s %s %s ERROR IN INITIALIZATION VERIFICATION' % (VERIFY_COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID))
      if UNIQ_COMMAND_ID in VERIFICATION_REPLY_EXPECT:
        del VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID]
    
    return weechat.WEECHAT_RC_OK
  
  #
  # VERIFY - REQUESTED
  # Called from buffer, this is received from remote BOT as request
  
  def buffer_command_verify_1_requested(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global BUFFER_CMD_VAL_REP, WRECON_REMOTE_BOTS_CONTROL, VERIFICATION_PROTOCOL
    global VERIFICATION_REPLY_EXPECT, VERIFICATION_INITIAL, BUFFER_CMD_VAL_ERR, VERIFICATION_LAST_L2
    
    # ~ display_data('buffer_command_verify_1_requested', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    # ~ display_data('DEBUG - buffer_command_verify_1_  requested:', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_1_requested: BOT : %s' % WRECON_REMOTE_BOTS_CONTROL[SOURCE_BOT_ID])
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    ENCRYPT_KEY1   = WRECON_REMOTE_BOTS_CONTROL[SOURCE_BOT_ID][0]
    ENCRYPT_KEY2   = ''
    SEND_DATA      = ''
    L2_PROTOCOL    = ''
    ERROR          = False
    OUT_MESSAGE    = ''
    
    ENCRYPT_LEVEL  = get_target_level_01_encryption(SOURCE_BOT_ID)
    
    SECRET_DATA    = COMMAND_ARGUMENTS_LIST[0]
    VERIFY_COMMAND = BUFFER_CMD_VAL_REP
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_1_requested: ENCRYPT_LEVEL : %s' % ENCRYPT_LEVEL)
    
    if ENCRYPT_LEVEL > 0:
      
      # HERE WE NEED ENSURE, THAT WE WILL FOLLOWING L2 PROTOCOL FOR EXCHANGING SECRET INFORMATIONS
      if SECRET_DATA in VERIFICATION_INITIAL:
        VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID] = SECRET_DATA
      
      # DEBUG
      # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_1_requested VERIFICATION_REPLY_EXPECT: %s' % VERIFICATION_REPLY_EXPECT)
      
      if SECRET_DATA in VERIFICATION_PROTOCOL:
        if not SECRET_DATA in VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID]:
          ERROR          = True
          VERIFY_COMMAND = BUFFER_CMD_VAL_ERR
          display_message(BUFFER, '[%s] %s < PROTOCOL VIOLATION' % (COMMAND_ID, SOURCE_BOT_ID))
          OUT_MESSAGE    = 'PROTOCOL VIOLATION'
        
        else:
          L2_PROTOCOL   = VERIFICATION_PROTOCOL[SECRET_DATA][1]
          ENCRYPT_LEVEL = VERIFICATION_PROTOCOL[SECRET_DATA][0]
          SECRET_DATA   = COMMAND_ARGUMENTS_LIST[1]
          if L2_PROTOCOL:
            ENCRYPT_LEVEL = VERIFICATION_PROTOCOL[L2_PROTOCOL][0]
            initial_function = VERIFICATION_PROTOCOL[L2_PROTOCOL][2]
            # Call the function for prepare all necessary variables
            ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA = initial_function(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
            if ERROR == True:
              VERIFY_COMMAND = BUFFER_CMD_VAL_ERR
              display_message(BUFFER, '[%s] %s < %s' % (COMMAND_ID, SOURCE_BOT_ID, SEND_DATA))
              OUT_MESSAGE    = SEND_DATA
          else:
            # DEBUG
            ENCRYPT_LEVEL, ENCRYPT_KEY2, REMOTE_SECRET_KEY = get_control_secret(SOURCE_BOT_ID)
            # ~ ENCRYPT_KEY1  = WRECON_REMOTE_BOTS_CONTROL[SOURCE_BOT_ID][0]
            verify_remove_l2_temporary_data(UNIQ_COMMAND_ID)

      # Here we have DATA of REMOTE bot, we try verify by usual way with enhanced encryption
      else:
        ENCRYPT_LEVEL, ENCRYPT_KEY2, REMOTE_SECRET_KEY = get_control_secret(SOURCE_BOT_ID)
        # ~ SECRET_DATA  = COMMAND_ARGUMENTS_LIST[0]
    
    if ERROR == False:
      # WE RECEIVED ENCRYPTED DATA
      # DECRYPTED DATA WILL RETURN HASH BACK IN ENCRYPTED FORM
      # 1. DATA ARE DECRYPTED
      
      # DEUG
      # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_1_requested: SEECRET : %s' % (SECRET_DATA))
      
      DECRYPT_SEECRET_DATA = string_decrypt(ENCRYPT_LEVEL, SECRET_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
      
      # DEBUG
      # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_1_requested: SEECRET : %s' % (DECRYPT_SEECRET_DATA))
      
      # 2. GET HASH OF DECRYPTED DATA
      if L2_PROTOCOL:
        HASH_DATA          = get_hash(DECRYPT_SEECRET_DATA.split(' ')[0])
      else:
        HASH_DATA          = get_hash(DECRYPT_SEECRET_DATA)
      
      if L2_PROTOCOL and SEND_DATA:
        HASH_DATA = '%s %s' % (HASH_DATA, SEND_DATA)
      
      # 3. ENCRYPT HASH
      
      # DEBUG
      # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_1_requested: SEC  : %s' % get_device_secrets())
      # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_1_requested: KEY1 : %s' % ENCRYPT_KEY1)
      # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_1_requested: KEY2 : %s' % ENCRYPT_KEY2)
      display_message(BUFFER, 'DEBUG - buffer_command_verify_1_requested: DATA : %s' % DECRYPT_SEECRET_DATA)
      display_message(BUFFER, 'DEBUG - buffer_command_verify_1_requested: HASH : %s' % HASH_DATA)
      display_message(BUFFER, 'DEBUG - buffer_command_verify_1_requested: LVL  : %s' % ENCRYPT_LEVEL)
      
      ENCRYPT_SEECRET_DATA = string_encrypt(ENCRYPT_LEVEL, HASH_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
      # 4. SEND BACK ENCRYPTED HASH TO REQUESTOR
      
      if L2_PROTOCOL:
        ENCRYPT_SEECRET_DATA = '%s %s' % (L2_PROTOCOL, ENCRYPT_SEECRET_DATA)
      weechat.command(BUFFER, '%s %s %s %s %s' % (VERIFY_COMMAND, SOURCE_BOT_ID, TARGET_BOT_ID, COMMAND_ID, ENCRYPT_SEECRET_DATA))
    else:
      weechat.command(BUFFER, '%s %s %s %s %s' % (VERIFY_COMMAND, SOURCE_BOT_ID, TARGET_BOT_ID, COMMAND_ID, OUT_MESSAGE))
      if UNIQ_COMMAND_ID in VERIFICATION_REPLY_EXPECT:
        del VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID]
    
    cleanup_unique_command_id(SOURCE, UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # VERIFY - RESULT RECEIVED
  # Called from buffer, we are received data from remote BOT of our request
  
  def buffer_command_verify_2_result_received(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global BUFFER_CMD_VAL_ERR, BUFFER_CMD_VAL_REA, BUFFER_CMD_VAL_EXE, WRECON_REMOTE_BOTS_CONTROL, WAIT_FOR_REMOTE_DATA, VERIFY_RESULT_VAL, WRECON_REMOTE_BOTS_ADVERTISED
    global ID_CALL_LOCAL, ID_CALL_REMOTE, WRECON_BOT_KEY, WRECON_BOT_ID, VERIFICATION_PROTOCOL, VERIFICATION_REPLY_EXPECT, VERIFICATION_LAST_L2, TIMEOUT_COMMAND_L2
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    # Stop waiting for result, we received data
    # Condition is necessary against result received after time out, or against fake results
    if UNIQ_COMMAND_ID in VERIFY_RESULT_VAL:
      weechat.unhook(VERIFY_RESULT_VAL[UNIQ_COMMAND_ID])
      del VERIFY_RESULT_VAL[UNIQ_COMMAND_ID]
    
    # ~ display_data('buffer_command_verify_2_result_received', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received VERIFICATION_REPLY_EXPECT: %s' % VERIFICATION_REPLY_EXPECT)
    
    # CHECK WE REQUESTED VERIFICATION
    ENCRYPT_LEVEL      = get_target_level_01_encryption(SOURCE_BOT_ID)
    
    ENCRYPT_KEY1       = WRECON_BOT_KEY
    ENCRYPT_KEY2       = ''
    SEND_DATA          = ''
    L2_PROTOCOL        = ''
    ERROR              = False
    FINAL_VERIFICATION = True
    VERIFY_COMMAND     = BUFFER_CMD_VAL_REA
    OUT_MESSAGE        = ''
    
    if COMMAND == BUFFER_CMD_VAL_ERR:
      ERROR       = True
      OUT_MESSAGE = 'ERROR'
      VERIFY_COMMAND = BUFFER_CMD_VAL_ERR
    
    if ERROR == False:
      # Check the result we received
      
      SECRET_DATA   = COMMAND_ARGUMENTS_LIST[0]
      
      # Check verfication is new protocol with L2 verification
      if ENCRYPT_LEVEL > 0:
      # Check we expected L2 protocol
        if not SECRET_DATA in VERIFICATION_PROTOCOL:
          ENCRYPT_LEVEL, ENCRYPT_KEY2, REMOTE_SECRET_KEY = get_granted_secret(SOURCE_BOT_ID)
          if ENCRYPT_KEY2:
            ENCRYPT_LEVEL = 2
          # DEBUG
          display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received: ENCRYPT_KEY1 : %s' % ENCRYPT_KEY1)
          display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received: ENCRYPT_KEY2 : %s' % ENCRYPT_KEY2)
          display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received: LEVEL        : %s' % ENCRYPT_LEVEL)
          display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received: EDATA        : %s' % SECRET_DATA)
        else:
      # If yes, we check L2 protocol is strictly followed
          if SECRET_DATA in VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID]:
            FINAL_VERIFICATION = False
            VERIFY_COMMAND     = BUFFER_CMD_VAL_EXE
            
            # Pickup protocol function we need call for next request
            L2_PROTOCOL   = VERIFICATION_PROTOCOL[SECRET_DATA][1]
            
            # DEBUG
            # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received: INI FUNC : %s' % INITIAL_FUNCTION)
            
            SECRET_DATA        = COMMAND_ARGUMENTS_LIST[1]
            
            # DEBUG
            # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received: SECRET_DATA            : %s' % SECRET_DATA)
            # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received: COMMAND_ARGUMENTS_LIST : %s' % COMMAND_ARGUMENTS_LIST)
            
            L2_PROTOCOL_NEXT   = VERIFICATION_PROTOCOL[L2_PROTOCOL][1]
            protocol_function  = VERIFICATION_PROTOCOL[L2_PROTOCOL][2]
            ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA = protocol_function(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, SECRET_DATA)
            if ERROR == True:
              OUT_MESSAGE      = SEND_DATA
          else:
            ERROR              = True
            OUT_MESSAGE        = 'PROTOCOL VIOLATION'
      
      # Check if an ERROR occured
      if ERROR == True:
        VERIFY_COMMAND = BUFFER_CMD_VAL_ERR
      else:
      # If not ERROR occured, then decrypt data and check HASH
      
        # DEBUG
        # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received: L KEYS : %s %s %s' % (ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2))
        
        DECRYPT_DATA  = string_decrypt(ENCRYPT_LEVEL, SECRET_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
        
        # DEBUG
        # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received: DECRYPT_DATA         : %s' % DECRYPT_DATA)
        
      # Check HASH is correct of older version of remote client
        if ENCRYPT_LEVEL == 0:
          if WAIT_FOR_REMOTE_DATA[UNIQ_COMMAND_ID] == DECRYPT_DATA:
            OUT_MESSAGE        = 'VERIFICATION SUCCESSFUL'
          else:
            ERROR              = True
            OUT_MESSAGE        = 'VERIFICATION FAILED'
            FINAL_VERIFICATION = True
            VERIFY_COMMAND     = BUFFER_CMD_VAL_ERR
      # Check HASH is correct of new version of remote client
        else:
          DECRYPT_DATA = DECRYPT_DATA.split(' ')
          
          # DEBUG
          # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received: WAIT_FOR_REMOTE_DATA : %s' % WAIT_FOR_REMOTE_DATA)
          
          if WAIT_FOR_REMOTE_DATA[UNIQ_COMMAND_ID] == DECRYPT_DATA[0]:
            OUT_MESSAGE        = 'VERIFICATION SUCCESSFUL'
          else:
          # In case this was first request and device of remote client has been changed,
          # then it always result verification failed
          # So we need request verification by additional secret key
          # Here we start with L2 protocol by 6th of protocol function
            if not UNIQ_COMMAND_ID in VERIFICATION_REPLY_EXPECT:
              FINAL_VERIFICATION = False
              VERIFY_COMMAND     = BUFFER_CMD_VAL_EXE
              L2_PROTOCOL        = list(VERIFICATION_PROTOCOL)[4]
              L2_PROTOCOL_NEXT   = VERIFICATION_PROTOCOL[L2_PROTOCOL][1]
              protocol_function  = VERIFICATION_PROTOCOL[L2_PROTOCOL][2]
          # Here we know that additional verification has been triggered, but verification failed
            else:
              ERROR              = True
              OUT_MESSAGE        = 'VERIFICATION FAILED'
              FINAL_VERIFICATION = True
              VERIFY_COMMAND     = BUFFER_CMD_VAL_ERR
        
      # Here we continue in case we need follow L2 protocol for requesting next data
      if FINAL_VERIFICATION == False:
        # Here we will call again protocol function with DECRYPT_DATA
        ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA = protocol_function(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, DECRYPT_DATA)
        # In case an error, we stop verifications
        if ERROR == True:
          FINAL_VERIFICATION = True
          VERIFY_COMMAND     = BUFFER_CMD_VAL_ERR
          OUT_MESSAGE        = SEND_DATA
        # Request next verification
        else:
          RANDOM_NUMBER = random.randint(7,31)
          SECRET_DATA   = get_random_string(RANDOM_NUMBER)
          SECRET_HASH   = get_hash(SECRET_DATA)
          
          # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received : PROTOCOL : %s' % L2_PROTOCOL)
          
          # ~ if L2_PROTOCOL == VERIFICATION_LAST_L2:
            # ~ L2_PROTOCOL = ''
          
          if L2_PROTOCOL and SEND_DATA:
            SECRET_DATA = '%s %s' % (SECRET_DATA, SEND_DATA)
          
          # DEBUG
          # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received : SEC  : %s' % get_device_secrets())
          # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received : KEY1 : %s' % ENCRYPT_KEY1)
          # ~ display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received : KEY2 : %s' % ENCRYPT_KEY2)
          display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received : DATA : %s' % SECRET_DATA)
          display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received : HASH : %s' % SECRET_HASH)
          display_message(BUFFER, 'DEBUG - buffer_command_verify_2_result_received : LVL  : %s' % ENCRYPT_LEVEL)
          
          ENCRYPT_SEECRET_DATA                  = string_encrypt(ENCRYPT_LEVEL, SECRET_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
          WAIT_FOR_REMOTE_DATA[UNIQ_COMMAND_ID] = SECRET_HASH
          
          if L2_PROTOCOL:
            SEND_DATA = '%s %s' % (L2_PROTOCOL, ENCRYPT_SEECRET_DATA)
          else:
            SEND_DATA = ENCRYPT_SEECRET_DATA
          
          weechat.command(BUFFER, '%s %s %s %s %s' % (VERIFY_COMMAND, SOURCE_BOT_ID, TARGET_BOT_ID, COMMAND_ID, SEND_DATA))
          VERIFY_RESULT_VAL[UNIQ_COMMAND_ID] = weechat.hook_timer(TIMEOUT_COMMAND_L2*1000, 0, 1, 'function_verify_wait_result', UNIQ_COMMAND_ID)
          
          if not L2_PROTOCOL:
            verify_remove_l2_temporary_data(UNIQ_COMMAND_ID)
    
    # Here we have final verification, then we can stop all waiting tasks and requests
    if FINAL_VERIFICATION == True:
      display_message(BUFFER, '[%s] %s < %s' % (COMMAND_ID, SOURCE_BOT_ID, OUT_MESSAGE))
      if UNIQ_COMMAND_ID in ID_CALL_REMOTE and UNIQ_COMMAND_ID in WAIT_FOR_VERIFICATION:
        weechat.command(BUFFER, '%s %s %s %s %s' % (VERIFY_COMMAND, SOURCE_BOT_ID, TARGET_BOT_ID, COMMAND_ID, OUT_MESSAGE))
      
      # Cleanup all verification variables
      if UNIQ_COMMAND_ID in WAIT_FOR_REMOTE_DATA:
        del WAIT_FOR_REMOTE_DATA[UNIQ_COMMAND_ID]
      
      if UNIQ_COMMAND_ID in VERIFICATION_REPLY_EXPECT:
        del VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID]
      
      # Here we call back command
      if UNIQ_COMMAND_ID in WAIT_FOR_VERIFICATION:
        recall_function, WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID = WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID]
        recall_function(WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # VERIFY - WAIT FOR RESULT
  #
  
  def function_verify_wait_result(UNIQ_COMMAND_ID, REMAINING_CALLS):
    global WRECON_BUFFER_CHANNEL, VERIFY_RESULT_VAL, WRECON_BOT_ID, WAIT_FOR_VERIFICATION
    
    if int(REMAINING_CALLS) == 0:
      if len(UNIQ_COMMAND_ID) > 16:
        TARGET_BOT_ID = UNIQ_COMMAND_ID[0:15]
        COMMAND_ID    = UNIQ_COMMAND_ID[16:]
      else:
        TARGET_BOT_ID = WRECON_BOT_ID
        COMMAND_ID    = UNIQ_COMMAND_ID[0:8]
      
      # Command has been called locally, we also clean up LOCAL CALL ID
      cleanup_unique_command_id('LOCAL', UNIQ_COMMAND_ID)
    
      # We need unhook our timer
      weechat.unhook(VERIFY_RESULT_VAL[UNIQ_COMMAND_ID])
      
      # ~ display_message(WRECON_BUFFER_CHANNEL, 'ADV RESULT : %s' % WAIT_FOR_VERIFICATION)
      
      verify_remove_l2_temporary_data(UNIQ_COMMAND_ID)
      
      # And recall requested command, when was requested for additional verification (advertisement)
      if UNIQ_COMMAND_ID in WAIT_FOR_VERIFICATION:
        RECALL_FUNCTION, WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID = WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID]
        RECALL_FUNCTION(WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # VERIFY - remove L2 temporary data
  #
  
  def verify_remove_l2_temporary_data(UNIQ_COMMAND_ID):
    global VERIFICATION_REPLY_EXPECT, TEMPORARY_ENCRYPT_KEY1, TEMPORARY_ENCRYPT_KEY2
    
    if UNIQ_COMMAND_ID in VERIFICATION_REPLY_EXPECT:
      del VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID]
    
    if UNIQ_COMMAND_ID in TEMPORARY_ENCRYPT_KEY1:
      del TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]
    
    if UNIQ_COMMAND_ID in TEMPORARY_ENCRYPT_KEY2:
      del TEMPORARY_ENCRYPT_KEY2
    
    return weechat.WEECHAT_RC_OK
  
  #
  # VERIFY - SAVE DATA
  # 
  
  def function_verify_save_data(BUFFER, TAGS, PREFIX, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS):
    global WRECON_REMOTE_BOTS_VERIFIED, WRECON_REMOTE_BOTS_ADVERTISED
    
    # Save actual common data of ADVERTISED remote BOT and of VERIFIED remote BOT together
   
    WRECON_REMOTE_BOTS_ADVERTISED[SOURCE_BOT_ID] = get_basic_data_of_remote_bot(TAGS, PREFIX, COMMAND_ARGUMENTS)
    SOURCE_BOT_NAME                              = WRECON_REMOTE_BOTS_ADVERTISED[SOURCE_BOT_ID].split('|')[0]
    SOURCE_BOT_VERSION                           = WRECON_REMOTE_BOTS_ADVERTISED[SOURCE_BOT_ID].split('|')[1]
    WRECON_REMOTE_BOTS_VERIFIED[SOURCE_BOT_ID]   = WRECON_REMOTE_BOTS_ADVERTISED[SOURCE_BOT_ID]
    
    display_message(BUFFER, '[%s] REMOTE BOT VERIFIED -> %s (%s) [v%s]' % (COMMAND_ID, SOURCE_BOT_ID, SOURCE_BOT_NAME, SOURCE_BOT_VERSION))
    
    return weechat.WEECHAT_RC_OK
  
  #
  # VERIFY - ERROR
  # We remove VERFIED data if exists, and also ADVERTISE data
  
  def function_verify_refuse_data(BUFFER, COMMAND_ID, SOURCE_BOT_ID):
    global WRECON_REMOTE_BOTS_VERIFIED, WRECON_REMOTE_BOTS_ADVERTISED
    
    # We remove previous verification, if exist
    if SOURCE_BOT_ID in WRECON_REMOTE_BOTS_VERIFIED:
      del WRECON_REMOTE_BOTS_VERIFIED[SOURCE_BOT_ID]
    
    # We also remove advertised data of remote bot
    # and display error message (display global error message is there)
    function_advertise_refuse_data(BUFFER, COMMAND_ID, SOURCE_BOT_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # VERIFY - PROTOCOL
  #
  
  ### FIRST CONTACT WITH REMOTE BOT, WE DO NOT HAVE DATA OF REMOTE BOT
  
  # 0 - ree (eer) - LOCAL -> REMOTE - verify KEY1
  def verify_protocol_0_ree(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global VERIFICATION_PROTOCOL, VERIFICATION_REPLY_EXPECT, WRECON_BOT_KEY, WAIT_FOR_REMOTE_DATA, TEMPORARY_ENCRYPT_KEY1, TEMPORARY_ENCRYPT_KEY2
    
    UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    
    # DEBUG
    # ~ display_message(BUFFER, '[%s] %s < L2 PROTOCOL - 0 REE' % (COMMAND_ID, TARGET_BOT_ID))
    
    ERROR         = False
    
    L2_PROTOCOL   = list(VERIFICATION_PROTOCOL)[0]
    ENCRYPT_LEVEL = VERIFICATION_PROTOCOL[L2_PROTOCOL][0]
    ENCRYPT_KEY1  = WRECON_BOT_KEY
    ENCRYPT_KEY2  = ''
    SEND_DATA     = ''
    
    # Prepare temporary random keys
    RANDOM_NUMBER = random.randint(7,15)
    TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID] = get_random_string(RANDOM_NUMBER)
    RANDOM_NUMBER = random.randint(7,15)
    TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID] = get_random_string(RANDOM_NUMBER)
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_0_ree: TEMPORARY_ENCRYPT_KEY1 : %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]))
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_0_ree: TEMPORARY_ENCRYPT_KEY2 : %s' % (TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_0_ree: ENCRYPT_KEY1           : %s' % ENCRYPT_KEY1)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_0_ree: ENCRYPT_KEY2           : %s' % ENCRYPT_KEY2)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_0_ree: SYS_DATA               : %s' % SYS_DATA)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_0_ree: BKEY_DATA              : %s' % BKEY_DATA)
    
    
    # Prepare keys as data
    OUT_DATA = '%s %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID], TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID])
    # And encrypt it
    SEND_DATA = string_encrypt(ENCRYPT_LEVEL, OUT_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
    
    VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID] = VERIFICATION_PROTOCOL[L2_PROTOCOL][1]
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_0_ree: TKEYS  : %s %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID], TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_0_ree: DATA   : %s' % SEND_DATA)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_0_ree: ELEVEL : %s' % ENCRYPT_LEVEL)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_0_ree: EKEY 1 : %s' % ENCRYPT_KEY1)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_0_ree: EKEY 2 : %s' % ENCRYPT_KEY2)
    
    return [ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA]
  
  # 1 - eer (rre) - REMOTE -> LOCAL - verify KEY1
  def verify_protocol_1_eer(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global VERIFICATION_PROTOCOL, VERIFICATION_REPLY_EXPECT, WRECON_REMOTE_BOTS_CONTROL, TEMPORARY_ENCRYPT_KEY1, TEMPORARY_ENCRYPT_KEY2
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    # DEBUG
    # ~ display_message(BUFFER, '[%s] %s < L2 PROTOCOL - 1 EER' % (COMMAND_ID, SOURCE_BOT_ID))
    
    ERROR         = False
    
    L2_PROTOCOL   = list(VERIFICATION_PROTOCOL)[1]
    ENCRYPT_LEVEL = VERIFICATION_PROTOCOL[L2_PROTOCOL][0]
    ENCRYPT_KEY1  = WRECON_REMOTE_BOTS_CONTROL[SOURCE_BOT_ID][0]
    ENCRYPT_KEY2  = ''
    SEND_DATA     = ''
    
    
    # We received new temporary keys (in encrypted form), we need decrypt, and save them for later use
    SECRET_DATA = COMMAND_ARGUMENTS_LIST[1]
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: SECRET_DATA  : %s' % SECRET_DATA)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: ELEVEL       : %s' % ENCRYPT_LEVEL)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: EKEY 1       : %s' % ENCRYPT_KEY1)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: EKEY 2       : %s' % ENCRYPT_KEY2)
    
    DECRYPT_DATA = string_decrypt(ENCRYPT_LEVEL, SECRET_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: DECRYPT_DATA : %s' % DECRYPT_DATA)
    
    XKEY_DATA = DECRYPT_DATA.split(' ')
    
    if len(XKEY_DATA) == 2:
      XKEY_DATA = string_decrypt(ENCRYPT_LEVEL, XKEY_DATA[1], ENCRYPT_KEY1, ENCRYPT_KEY2)
      KEY_DATA  = XKEY_DATA.split(' ')
      
      # DEBUG
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: KEY_DATA     : %s' % KEY_DATA)
      
      if len(KEY_DATA) == 2:
        TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID] = KEY_DATA[0]
        TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID] = KEY_DATA[1]
        
        VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID] = VERIFICATION_PROTOCOL[L2_PROTOCOL][1]
        
        # DEBUG
        # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: TKEYS : %s %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID], TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
      else:
        ERROR = True
    
    else:
      ERROR = True
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: TEMPORARY_ENCRYPT_KEY1 : %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]))
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: TEMPORARY_ENCRYPT_KEY2 : %s' % (TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: ENCRYPT_KEY1           : %s' % ENCRYPT_KEY1)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: ENCRYPT_KEY2           : %s' % ENCRYPT_KEY2)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: SYS_DATA               : %s' % SYS_DATA)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_1_eer: BKEY_DATA              : %s' % BKEY_DATA)
    
    if ERROR == True:
      SEND_DATA = 'DECRYPTION ERROR (function EER)'
      verify_remove_l2_temporary_data(UNIQ_COMMAND_ID)
    
    return [ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA]
    
  # 2 - rre (ner) - LOCAL -> REMOTE - request for SYS
  def verify_protocol_2_rre(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global VERIFICATION_PROTOCOL, VERIFICATION_REPLY_EXPECT, WRECON_BOT_KEY, VERIFY_CALL_ORDER, TEMPORARY_ENCRYPT_KEY1, TEMPORARY_ENCRYPT_KEY2
    global WRECON_REMOTE_BOTS_GRANTED_SECRET
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    # DEBUG
    # ~ display_message(BUFFER, '[%s] %s < L2 PROTOCOL - 2 RRE' % (COMMAND_ID, SOURCE_BOT_ID))
    
    L2_PROTOCOL   = list(VERIFICATION_PROTOCOL)[2]
    ENCRYPT_LEVEL = 1
    ENCRYPT_KEY1  = WRECON_BOT_KEY
    ENCRYPT_KEY2  = ''
    SEND_DATA     = ''
    ERROR         = False
    
    # First call
    if not UNIQ_COMMAND_ID in VERIFY_CALL_ORDER:
      VERIFY_CALL_ORDER[UNIQ_COMMAND_ID] = ''
    # Second call
    else:
      # Now we use our temporary keys, we sent by first request to remote PC
      # Keys will be used for next requests now
      # Also this is the way how to ensure symetric encryption more secure
      ENCRYPT_LEVEL = VERIFICATION_PROTOCOL[L2_PROTOCOL][0]
      ENCRYPT_KEY1  = TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]
      ENCRYPT_KEY2  = TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]
      
      # Also prepare BKEY and send to remote PC      
      SYS_DATA, BKEY_DATA = get_granted_secret(SOURCE_BOT_ID)
      
      RANDOM_NUMBER = random.randint(15,31)
      BKEY_DATA     = get_random_string(RANDOM_NUMBER)
      WRECON_REMOTE_BOTS_GRANTED_SECRET[SOURCE_BOT_ID] = [SYS_DATA, BKEY_DATA]
      
      # DEBUG
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_2_rre: TEMPORARY_ENCRYPT_KEY1 : %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]))
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_2_rre: TEMPORARY_ENCRYPT_KEY2 : %s' % (TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_2_rre: ENCRYPT_KEY1           : %s' % ENCRYPT_KEY1)
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_2_rre: ENCRYPT_KEY2           : %s' % ENCRYPT_KEY2)
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_2_rre: SYS_DATA               : %s' % SYS_DATA)
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_2_rre: BKEY_DATA              : %s' % BKEY_DATA)
      
      SEND_DATA = string_encrypt(ENCRYPT_LEVEL, BKEY_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
      
      del VERIFY_CALL_ORDER[UNIQ_COMMAND_ID]
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_2_rre : L KEYS : %s %s %s' % (ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2))
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_2_rre : S DATA : %s' % SEND_DATA)
    
    VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID] = VERIFICATION_PROTOCOL[L2_PROTOCOL][1]
    
    return [ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA]
  
  # 3 - ner (rnr) - REMOTE -> LOCAL - reply SYS
  def verify_protocol_3_ner(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global VERIFICATION_PROTOCOL, VERIFICATION_REPLY_EXPECT, TEMPORARY_ENCRYPT_KEY1, TEMPORARY_ENCRYPT_KEY2
    global WRECON_REMOTE_BOTS_CONTROL_SECRET
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    # DEBUG
    # ~ display_message(BUFFER, '[%s] %s < L2 PROTOCOL - 3 NER' % (COMMAND_ID, SOURCE_BOT_ID))
    
    L2_PROTOCOL   = list(VERIFICATION_PROTOCOL)[3]
    ENCRYPT_LEVEL = VERIFICATION_PROTOCOL[L2_PROTOCOL][0]
    ENCRYPT_KEY1  = TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]
    ENCRYPT_KEY2  = TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]
    SEND_DATA     = ''
    ERROR         = False
    
    # We also received new BKEY in encrypted form
    RECEIVED_DATA  = COMMAND_ARGUMENTS_LIST[1]
    DECRYPTED_DATA = string_decrypt(ENCRYPT_LEVEL, RECEIVED_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
    
    EBKEY_DATA     = DECRYPTED_DATA.split(' ')[1]
    BKEY_DATA      =string_decrypt(ENCRYPT_LEVEL, EBKEY_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
    SYS_DATA       = get_device_secrets()
    
    WRECON_REMOTE_BOTS_CONTROL_SECRET[SOURCE_BOT_ID] = BKEY_DATA
    VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID] = VERIFICATION_PROTOCOL[L2_PROTOCOL][1]
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_3_ner: TEMPORARY_ENCRYPT_KEY1 : %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]))
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_3_ner: TEMPORARY_ENCRYPT_KEY2 : %s' % (TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_3_ner: ENCRYPT_KEY1           : %s' % ENCRYPT_KEY1)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_3_ner: ENCRYPT_KEY2           : %s' % ENCRYPT_KEY2)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_3_ner: SYS_DATA               : %s' % SYS_DATA)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_3_ner: BKEY_DATA              : %s' % BKEY_DATA)
    
    SEND_DATA      = string_encrypt(ENCRYPT_LEVEL, SYS_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
    
    return [ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA]
  
  #### FOLLOWING VERIFICATION IS FOR EXISTING DATA ABOUT REMOTE BOT, BUT DEVICE HAS BEEN CHANGED
  
  # 4 - rvn (vnr) - LOCAL -> REMOTE - verify BKEY
  def verify_protocol_4_rvn(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global VERIFICATION_PROTOCOL, VERIFICATION_REPLY_EXPECT, TEMPORARY_ENCRYPT_KEY1, TEMPORARY_ENCRYPT_KEY2
    global WRECON_REMOTE_BOTS_GRANTED_SECRET
    
    UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    
    # DEBUG
    display_message(BUFFER, '[%s] %s < L2 PROTOCOL - 4 RVN' % (COMMAND_ID, TARGET_BOT_ID))
    
    L2_PROTOCOL   = list(VERIFICATION_PROTOCOL)[4]
    ENCRYPT_LEVEL = VERIFICATION_PROTOCOL[L2_PROTOCOL][0]
    ENCRYPT_KEY1  = WRECON_BOT_KEY
    ENCRYPT_KEY2  = WRECON_REMOTE_BOTS_GRANTED_SECRET[TARGET_BOT_ID][1]
    SEND_DATA     = ''
    ERROR         = False
    
    # Prepare temporary random keys
    RANDOM_NUMBER = random.randint(7,15)
    TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID] = get_random_string(RANDOM_NUMBER)
    RANDOM_NUMBER = random.randint(7,15)
    TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID] = get_random_string(RANDOM_NUMBER)
    
    # DEBUG
    display_message(BUFFER, 'DEBUG - verify_protocol_4_rvn: TEMPORARY_ENCRYPT_KEY1 : %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]))
    display_message(BUFFER, 'DEBUG - verify_protocol_4_rvn: TEMPORARY_ENCRYPT_KEY2 : %s' % (TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
    display_message(BUFFER, 'DEBUG - verify_protocol_4_rvn: ENCRYPT_KEY1           : %s' % ENCRYPT_KEY1)
    display_message(BUFFER, 'DEBUG - verify_protocol_4_rvn: ENCRYPT_KEY2           : %s' % ENCRYPT_KEY2)
    display_message(BUFFER, 'DEBUG - verify_protocol_4_rvn: SYS_DATA               : %s' % SYS_DATA)
    display_message(BUFFER, 'DEBUG - verify_protocol_4_rvn: BKEY_DATA              : %s' % BKEY_DATA)
    
    # Prepare keys as data
    OUT_DATA = '%s %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID], TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID])
    # And encrypt it
    SEND_DATA = string_encrypt(ENCRYPT_LEVEL, OUT_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
    
    VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID] = VERIFICATION_PROTOCOL[L2_PROTOCOL][1]
    
    return [ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA]
  
  # 5 - vnr (rsn) - REMOTE -> LOCAL - verify BKEY
  def verify_protocol_5_vnr(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global VERIFICATION_PROTOCOL, VERIFICATION_REPLY_EXPECT, TEMPORARY_ENCRYPT_KEY1, TEMPORARY_ENCRYPT_KEY2
    global WRECON_REMOTE_BOTS_CONTROL_SECRET
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    # DEBUG
    display_message(BUFFER, '[%s] %s < L2 PROTOCOL - 5 VNR' % (COMMAND_ID, SOURCE_BOT_ID))
      
    L2_PROTOCOL   = list(VERIFICATION_PROTOCOL)[5]
    ENCRYPT_LEVEL = VERIFICATION_PROTOCOL[L2_PROTOCOL][0]
    ENCRYPT_KEY1  = WRECON_REMOTE_BOTS_CONTROL[SOURCE_BOT_ID]
    ENCRYPT_KEY2  = WRECON_REMOTE_BOTS_CONTROL_SECRET[SOURCE_BOT_ID]
    SEND_DATA     = ''
    ERROR         = False
    
    # We received new temporary keys (in encrypted form), we need decrypt, and save them for later use
    SECRET_DATA = COMMAND_ARGUMENTS_LIST.pop(0)
    OUT_DATA = string_decrypt(ENCRYPT_LEVEL, SECRET_DATA[0], ENCRYPT_KEY1, ENCRYPT_KEY2)
    KEY_DATA = SECRET_DATA.split(' ')
    TEMPORARY_ENCRYPT_KEY1 = KEY_DATA[0]
    TEMPORARY_ENCRYPT_KEY2 = KEY_DATA[1]
    
    # DEBUG
    display_message(BUFFER, 'DEBUG - verify_protocol_5_vnr: TEMPORARY_ENCRYPT_KEY1 : %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]))
    display_message(BUFFER, 'DEBUG - verify_protocol_5_vnr: TEMPORARY_ENCRYPT_KEY2 : %s' % (TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
    display_message(BUFFER, 'DEBUG - verify_protocol_5_vnr: ENCRYPT_KEY1           : %s' % ENCRYPT_KEY1)
    display_message(BUFFER, 'DEBUG - verify_protocol_5_vnr: ENCRYPT_KEY2           : %s' % ENCRYPT_KEY2)
    display_message(BUFFER, 'DEBUG - verify_protocol_5_vnr: SYS_DATA               : %s' % SYS_DATA)
    display_message(BUFFER, 'DEBUG - verify_protocol_5_vnr: BKEY_DATA              : %s' % BKEY_DATA)
    
    VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID] = VERIFICATION_PROTOCOL[L2_PROTOCOL][1]
    
    return [ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA]
  
  # 6 - rsn (snr) - LOCAL -> REMOTE - request SYS
  def verify_protocol_6_rsn(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global VERIFICATION_PROTOCOL, VERIFICATION_REPLY_EXPECT, VERIFY_CALL_ORDER, TEMPORARY_ENCRYPT_KEY1, TEMPORARY_ENCRYPT_KEY2
    global WRECON_REMOTE_BOTS_GRANTED_SECRET
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    # DEBUG
    display_message(BUFFER, '[%s] %s < L2 PROTOCOL - 6 RSN' % (COMMAND_ID, SOURCE_BOT_ID))
    
    L2_PROTOCOL   = list(VERIFICATION_PROTOCOL)[6]
    ENCRYPT_LEVEL = VERIFICATION_PROTOCOL[L2_PROTOCOL][0]
    ENCRYPT_KEY1  = WRECON_BOT_KEY
    ENCRYPT_KEY2  = WRECON_REMOTE_BOTS_GRANTED_SECRET[TARGET_BOT_ID][1]
    SEND_DATA     = ''
    ERROR         = False
    
    # First call
    if not UNIQ_COMMAND_ID in VERIFY_CALL_ORDER:
      VERIFY_CALL_ORDER[UNIQ_COMMAND_ID] = ''
    # Second call
    else:
      ENCRYPT_KEY1 = TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]
      ENCRYPT_KEY2 = TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]
      
      # Also prepare BKEY and send to remote PC      
      SYS_DATA, BKEY_DATA = get_granted_secret(SOURCE_BOT_ID)
      
      RANDOM_NUMBER = random.randint(7,15)
      BKEY_DATA     = get_random_string(RANDOM_NUMBER)
      WRECON_REMOTE_BOTS_GRANTED_SECRET[SOURCE_BOT_ID] = [SYS_DATA, BKEY_DATA]
      
      SEND_DATA = string_encrypt(ENCRYPT_LEVEL, BKEY_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
      
      # DEBUG
      display_message(BUFFER, 'DEBUG - verify_protocol_6_rsn: TEMPORARY_ENCRYPT_KEY1 : %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]))
      display_message(BUFFER, 'DEBUG - verify_protocol_6_rsn: TEMPORARY_ENCRYPT_KEY2 : %s' % (TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
      display_message(BUFFER, 'DEBUG - verify_protocol_6_rsn: ENCRYPT_KEY1           : %s' % ENCRYPT_KEY1)
      display_message(BUFFER, 'DEBUG - verify_protocol_6_rsn: ENCRYPT_KEY2           : %s' % ENCRYPT_KEY2)
      display_message(BUFFER, 'DEBUG - verify_protocol_6_rsn: SYS_DATA               : %s' % SYS_DATA)
      display_message(BUFFER, 'DEBUG - verify_protocol_6_rsn: BKEY_DATA              : %s' % BKEY_DATA)
      del VERIFY_CALL_ORDER[UNIQ_COMMAND_ID]
    
    VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID] = VERIFICATION_PROTOCOL[L2_PROTOCOL][1]
    
    return [ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA]
  
  # 7 - snr (aaa) - REMOTE -> LOCAL - reply SYS
  def verify_protocol_7_snr(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global VERIFICATION_PROTOCOL, VERIFICATION_REPLY_EXPECT, TEMPORARY_ENCRYPT_KEY1, TEMPORARY_ENCRYPT_KEY2
    global WRECON_REMOTE_BOTS_CONTROL_SECRET
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    # DEBUG
    display_message(BUFFER, '[%s] %s < L2 PROTOCOL - 7 SNR' % (COMMAND_ID, SOURCE_BOT_ID))
    
    L2_PROTOCOL   = list(VERIFICATION_PROTOCOL)[7]
    ENCRYPT_LEVEL = VERIFICATION_PROTOCOL[L2_PROTOCOL][0]
    ENCRYPT_KEY1  = TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]
    ENCRYPT_KEY2  = TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]
    SEND_DATA     = ''
    ERROR         = False
    
    # We also received new BKEY in encrypted form
    RECEIVED_DATA  = COMMAND_ARGUMENTS_LIST.pop(0)
    DECRYPTED_DATA = string_decrypt(ENCRYPT_LEVEL, RECEIVED_DATA[0], ENCRYPT_KEY1, ENCRYPT_KEY2)
    
    BKEY_DATA      = DECRYPTED_DATA.split(' ')[1]
    SYS_DATA       = get_device_secrets()
    
    WRECON_REMOTE_BOTS_CONTROL_SECRET[SOURCE_BOT_ID] = BKEY_DATA
    
    SEND_DATA      = string_encrypt(ENCRYPT_LEVEL, SYS_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2)
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_7_snr: TEMPORARY_ENCRYPT_KEY1 : %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]))
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_7_snr: TEMPORARY_ENCRYPT_KEY2 : %s' % (TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_7_snr: ENCRYPT_KEY1           : %s' % ENCRYPT_KEY1)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_7_snr: ENCRYPT_KEY2           : %s' % ENCRYPT_KEY2)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_7_snr: SYS_DATA               : %s' % SYS_DATA)
    # ~ display_message(BUFFER, 'DEBUG - verify_protocol_7_snr: BKEY_DATA              : %s' % BKEY_DATA)
    # ~ del VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID]
    # ~ del TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]
    # ~ del TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]
    
    return [ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA]
  
  # a -aaa ()     - LOCAL -> REMOTE (here we know we accepted all data after all verifications followed by protocol)
  # This ensure we call back function
  def verify_protocol_a_aaa(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global VERIFICATION_PROTOCOL, VERIFICATION_REPLY_EXPECT, VERIFY_CALL_ORDER, TEMPORARY_ENCRYPT_KEY1, TEMPORARY_ENCRYPT_KEY2
    global WRECON_BOT_KEY, WRECON_REMOTE_BOTS_GRANTED_SECRET
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    # DEBUG
    # ~ display_message(BUFFER, '[%s] %s < L2 PROTOCOL - A AAA' % (COMMAND_ID, SOURCE_BOT_ID))
    
    L2_PROTOCOL   = list(VERIFICATION_PROTOCOL)[8]
    ENCRYPT_LEVEL = VERIFICATION_PROTOCOL[L2_PROTOCOL][0]
    ENCRYPT_KEY1  = TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]
    ENCRYPT_KEY2  = TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]
    SEND_DATA     = ''
    ERROR         = False
    
    # First call, and final one
    if not UNIQ_COMMAND_ID in VERIFY_CALL_ORDER:
      VERIFY_CALL_ORDER[UNIQ_COMMAND_ID] = ''
      
      SYS_DATA, BKEY_DATA = get_granted_secret(SOURCE_BOT_ID)
      
      # We received SYS_DATA in encrypted form from remote PC
      # This we save
      RECEIVED_DATA  = COMMAND_ARGUMENTS_LIST
      
      # DEBUG
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: COMMAND_ARGUMENTS_LIST : %s' % COMMAND_ARGUMENTS_LIST)
      
      XSYS_DATA       = string_decrypt(ENCRYPT_LEVEL, RECEIVED_DATA, ENCRYPT_KEY1, ENCRYPT_KEY2).split(' ')
      SYS_DATA        = string_decrypt(ENCRYPT_LEVEL, XSYS_DATA[1], ENCRYPT_KEY1, ENCRYPT_KEY2)
      
      WRECON_REMOTE_BOTS_GRANTED_SECRET[SOURCE_BOT_ID] = [SYS_DATA, BKEY_DATA]
      
      # DEBUG
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: TEMPORARY_ENCRYPT_KEY1 : %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]))
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: TEMPORARY_ENCRYPT_KEY2 : %s' % (TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: ENCRYPT_KEY1           : %s' % ENCRYPT_KEY1)
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: ENCRYPT_KEY2           : %s' % ENCRYPT_KEY2)
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: SYS_DATA               : %s' % SYS_DATA)
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: BKEY_DATA              : %s' % BKEY_DATA)
    # Second call, also final one, we prepare standard verification
    else:
      SYS_DATA, BKEY_DATA = get_granted_secret(SOURCE_BOT_ID)
      
      ENCRYPT_KEY1  = WRECON_BOT_KEY
      ENCRYPT_KEY2  = SYS_DATA
      
      # DEBUG
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: TEMPORARY_ENCRYPT_KEY1 : %s' % (TEMPORARY_ENCRYPT_KEY1[UNIQ_COMMAND_ID]))
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: TEMPORARY_ENCRYPT_KEY2 : %s' % (TEMPORARY_ENCRYPT_KEY2[UNIQ_COMMAND_ID]))
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: ENCRYPT_KEY1           : %s' % ENCRYPT_KEY1)
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: ENCRYPT_KEY2           : %s' % ENCRYPT_KEY2)
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: SYS_DATA               : %s' % SYS_DATA)
      # ~ display_message(BUFFER, 'DEBUG - verify_protocol_a_aaa: BKEY_DATA              : %s' % BKEY_DATA)
      
      VERIFICATION_REPLY_EXPECT[UNIQ_COMMAND_ID] = VERIFICATION_PROTOCOL[L2_PROTOCOL][1]
      
    return [ERROR, ENCRYPT_LEVEL, ENCRYPT_KEY1, ENCRYPT_KEY2, SEND_DATA]
  
  # GET REMOTE SECRET
  # for GRANTED BOTs
  def get_granted_secret(REMOTE_ID):
    global WRECON_REMOTE_BOTS_GRANTED_SECRET
    
    SYS_DATA      = ''
    BKEY_DATA     = ''
    ENCRYPT_LEVEL = 1
    
    if REMOTE_ID in WRECON_REMOTE_BOTS_GRANTED_SECRET:
      SYS_DATA      = WRECON_REMOTE_BOTS_GRANTED_SECRET[REMOTE_ID][0]
      BKEY_DATA     = WRECON_REMOTE_BOTS_GRANTED_SECRET[REMOTE_ID][1]
      ENCRYPT_LEVEL = 2
      
    return [ENCRYPT_LEVEL, SYS_DATA, BKEY_DATA]
  
  # GET REMOTE SECRET
  # for CONTROL (ADDED) BOTs
  def get_control_secret(REMOTE_ID):
    global WRECON_REMOTE_BOTS_CONTROL_SECRET
    
    SYS_DATA      = get_device_secrets()
    BKEY_DATA     = ''
    ENCRYPT_LEVEL = 1
    
    if REMOTE_ID in WRECON_REMOTE_BOTS_CONTROL_SECRET:
      BKEY_DATA     = WRECON_REMOTE_BOTS_CONTROL_SECRET[REMOTE_ID]
      ENCRYPT_LEVEL = 2
      
    return [ENCRYPT_LEVEL, SYS_DATA, BKEY_DATA]
  
  #
  # VERIFY - SETUP VARIABLES
  #
  
  def setup_command_variables_verify():
    global BUFFER_CMD_VAL_EXE, BUFFER_CMD_VAL_REP, BUFFER_CMD_VAL_ERR, BUFFER_CMD_VAL_REA, BUFFER_CMD_VAL_FUNCTION, COMMAND_REQUIREMENTS_REMOTE, COMMAND_REQUIREMENTS_LOCAL, SCRIPT_INTERNAL_CALL, PREPARE_USER_CALL, VERIFY_RESULT_VAL
    BUFFER_CMD_VAL_EXE = '%sE-VAL' % (COMMAND_IN_BUFFER)
    BUFFER_CMD_VAL_REP = '%sVAL-R' % (COMMAND_IN_BUFFER)
    BUFFER_CMD_VAL_ERR = '%sVAL-E' % (COMMAND_IN_BUFFER)
    BUFFER_CMD_VAL_REA = '%sVAL-A' % (COMMAND_IN_BUFFER)
    BUFFER_CMD_VAL_FUNCTION = {}
    VERIFY_RESULT_VAL       = {}
    
    SCRIPT_BUFFER_CALL[BUFFER_CMD_VAL_EXE] = buffer_command_verify_1_requested
    SCRIPT_BUFFER_CALL[BUFFER_CMD_VAL_REP] = buffer_command_verify_2_result_received
    SCRIPT_BUFFER_CALL[BUFFER_CMD_VAL_REA] = buffer_command_verify_2_result_received
    SCRIPT_BUFFER_CALL[BUFFER_CMD_VAL_ERR] = buffer_command_verify_2_result_received
    
    PREPARE_USER_CALL['VERIFY']             = prepare_command_verify
    SCRIPT_INTERNAL_CALL['VERIFY']          = prepare_command_verify
    # ~ SCRIPT_COMMAND_CALL[BUFFER_CMD_VAL_EXE] = prepare_command_verify
    
    SCRIPT_COMMAND_CALL['VERIFY']           = buffer_command_verify
    # ~ SCRIPT_COMMAND_CALL[BUFFER_CMD_VAL_EXE] = buffer_command_verify
    
    # BEFORE EXECUTION OF LOCAL COMMAND or RECEIVED BY REMOTE COMMAND
    # following setup ensure ADVERTISE verification automatically
    COMMAND_REQUIREMENTS_LOCAL['VERIFY']            = verify_remote_bot_advertised
    COMMAND_REQUIREMENTS_REMOTE[BUFFER_CMD_VAL_EXE] = verify_remote_bot_advertised
    
    global ARGUMENTS_REQUIRED_MINIMAL
    ARGUMENTS_REQUIRED_MINIMAL['VERIFY']           = 1
    ARGUMENTS_REQUIRED_MINIMAL[BUFFER_CMD_VAL_EXE] = 1
    
    global VERIFICATION_PROTOCOL, VERIFY_CALL_ORDER
    VERIFY_CALL_ORDER = {}
    
    global TEMPORARY_ENCRYPT_KEY1, TEMPORARY_ENCRYPT_KEY2
    TEMPORARY_ENCRYPT_KEY1 = {}
    TEMPORARY_ENCRYPT_KEY2 = {}
    
    # Following variables are protocol for requesting information
    # There should be strict order of following IDs
    
    #                               +------------------ Encryption level
    #                               |
    #                               |    +------------- Next verification ID, when verification was successful
    #                               |    |
    #                               |    |
    #                               |    |
    #                               |    |           +- Call function
    #                               |    |           | 
    VERIFICATION_PROTOCOL['ree'] = [1, 'eer', verify_protocol_0_ree]     # 0 Request         - DATA       - 1st initialisation - from local           + new TEMPKEYS send
    VERIFICATION_PROTOCOL['eer'] = [1, 'rre', verify_protocol_1_eer]     # 1 Reply           - DATA       - 1st initialisation - reply from remote    + new TEMPKEYS received
    VERIFICATION_PROTOCOL['rre'] = [2, 'ner', verify_protocol_2_rre]     # 2 Request SYS     - reDATA     - 1st initialisation - from local for SYS   + new BKEY send
    VERIFICATION_PROTOCOL['ner'] = [2, 'aaa', verify_protocol_3_ner]     # 3 Reply SYS       - neDATA     - 1st initialisation - from remote with SYS + new BKEY received

    # In case verification failed, then we try BKEY as backup verification
    # It is possible that remote system can by running on flashdisk and was changed to different hardware
    # This we verify now
    VERIFICATION_PROTOCOL['rvn'] = [2, 'vnr', verify_protocol_4_rvn]     # 6 Request         - DATA       - verify with BKEY - from local             + new TEMPKEYS send
    VERIFICATION_PROTOCOL['vnr'] = [2, 'rsn', verify_protocol_5_vnr]     # 7 Reply           - DATA       - verify with BKEY - reply from remote      + new TEMPKEYS received
    VERIFICATION_PROTOCOL['rsn'] = [2, 'snr', verify_protocol_6_rsn]     # 8 Request new SYS - DATA       - from local for new SYS                    + new BKEY send
    VERIFICATION_PROTOCOL['snr'] = [2, 'aaa', verify_protocol_7_snr]     # 9 Reply new SYS   - snDATA     - from remote with new SYS                  + new BKEY received
    
    # Latest function is called when all verifications were successful, we save new data
    VERIFICATION_PROTOCOL['aaa'] = [2, '',    verify_protocol_a_aaa]     # a Accepted BKEY or SYS
    
    global VERIFICATION_LAST_L2
    VERIFICATION_LAST_L2 = list(VERIFICATION_PROTOCOL)[8]
    
    global VERIFICATION_INITIAL
    VERIFICATION_INITIAL = [list(VERIFICATION_PROTOCOL)[0], list(VERIFICATION_PROTOCOL)[4]]
    
    return
  
  #
  ##### END BUFFER COMMAND VERIFY REMOTE BOT
  
  #####
  #
  # COMMAND HELP
  
  #
  # HELP - PREPARE COMMAND FOR VALIDATION AND EXECUTION
  #
  
  def prepare_command_help(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_BOT_ID
    
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    COMMAND         = 'HELP'
    
    return [COMMAND, WRECON_BOT_ID, WRECON_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # HELP
  #
  
  def user_command_help(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global SHORT_HELP, ID_CALL_LOCAL, SCRIPT_NAME, SCRIPT_VERSION, SCRIPT_TIMESTAMP
    
    UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    
    if SCRIPT_TIMESTAMP:
      SHOW_TIMESTAMP = ' [%s]' % SCRIPT_TIMESTAMP
    else:
      SHOW_TIMESTAMP = ''
    
    # Display short help of all commands, if argument (command) was not provided
    if not COMMAND_ARGUMENTS_LIST:
      
      OUT_MESSAGE = '''SHORT HELP OF ALL COMMANDS (%s %s%s)

For detailed help of all commands type command /weechat help %s
For detailed help of a command type command /%s help COMMAND

COMMAND            COMMAND [and arguments]
----------------   ----------------------------------------------------------''' % (SCRIPT_NAME, SCRIPT_VERSION, SHOW_TIMESTAMP, SCRIPT_NAME, SCRIPT_NAME)
      
      OUT_MESSAGE = OUT_MESSAGE + SHORT_HELP
      display_message(BUFFER, OUT_MESSAGE)
    # Or display help for given command (if exist)
    else:
      COMMAND_HELP = COMMAND_ARGUMENTS_LIST[0].upper()
      if COMMAND_HELP in HELP_COMMAND:
        OUT_MESSAGE     = ['HELP OF COMMAND > %s' % COMMAND_HELP]
        OUT_MESSAGE.append(HELP_COMMAND[COMMAND_HELP])
        OUT_MESSAGE.append('')
        display_message(BUFFER, OUT_MESSAGE)
      else:
        display_message(BUFFER, 'ERROR: HELP OF UNKNOWN COMMAND -> %s' % COMMAND_HELP)
    
    cleanup_unique_command_id(SOURCE, UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # HELP - SETUP VARIABLES
  #
  
  def setup_command_variables_help():
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_COMMAND_CALL, PREPARE_USER_CALL, COLOR_TEXT
    
    global HELP_COMMAND
    
    HELP_COMMAND['H'] = '''
%(bold)s%(italic)s--- H[ELP] [COMMAND]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
 Without argument will show short help of commands (overview). For detailed help of all commands use /help wrecon.
 With argument (command) will show help of given command (argument).
   /wrecon H
   /wrecon HELP
   /wrecon H ADV
'''
    
    HELP_COMMAND['HELP'] = HELP_COMMAND['H']
    
    SCRIPT_ARGS                 = SCRIPT_ARGS + ' | [H[ELP] [COMMAND]'
    SCRIPT_ARGS_DESCRIPTION     = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['HELP']
    SCRIPT_COMPLETION           = SCRIPT_COMPLETION + ' || H || HELP'
    SCRIPT_COMMAND_CALL['HELP'] = user_command_help
    
    global SHORT_HELP
    
    SHORT_HELP                  = SHORT_HELP + '''
HELP               H[ELP] [COMMAND]'''
    
    global ARGUMENTS_OPTIONAL
    
    ARGUMENTS_OPTIONAL['HELP'] = 1
    
    PREPARE_USER_CALL['H']      = prepare_command_help
    PREPARE_USER_CALL['HELP']   = PREPARE_USER_CALL['H']
    
    return
  
  #
  ##### END COMMAND HELP
  
  ######
  #
  # COMMAND ADVERTISEMENT
  
  # ADVERTISE - CALLED FROM USER (PREPARE FOR VALIDATION)
  
  def prepare_command_advertise(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global BUFFER_CMD_ADV_REQ, BUFFER_CMD_ADV_ADA, ID_CALL_LOCAL, WRECON_BOT_ID, SCRIPT_COMMAND_CALL, WRECON_REMOTE_BOTS_ADVERTISED
    
    SOURCE_BOT_ID = WRECON_BOT_ID
    
    if COMMAND == 'ADA':
      if len(COMMAND_ARGUMENTS_LIST) == 0:
        TARGET_BOT_ID   = ''
        UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
      else:
        TARGET_BOT_ID   = COMMAND_ARGUMENTS_LIST[0]
        UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
      if TARGET_BOT_ID in WRECON_REMOTE_BOTS_ADVERTISED:
        del WRECON_REMOTE_BOTS_ADVERTISED[TARGET_BOT_ID]
    else:
      COMMAND         = 'ADVERTISE'
      TARGET_BOT_ID   = COMMAND_ID
      UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    
    # ~ display_data('prepare_command_advertise', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # ADVERTISE
  # 
  
  def user_command_advertise(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global BUFFER_CMD_ADV_REQ, BUFFER_CMD_ADA_REQ, ID_CALL_LOCAL, WRECON_BOT_ID, WRECON_BUFFER_CHANNEL, COUNT_ADVERTISED_BOTS, TIMEOUT_COMMAND_SHORT, WAIT_FOR_ADVERTISE
    
    COUNT_ADVERTISED_BOTS = 0
    
    if COMMAND == 'ADVERTISE':
      COMMAND         = BUFFER_CMD_ADV_REQ
      UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
      TARGET_BOT_ID   = COMMAND_ID
    else:
      COMMAND         = BUFFER_CMD_ADA_REQ
      UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    # current user command no need to be validated, and will be executed without additional istelsf validation
    weechat.command(WRECON_BUFFER_CHANNEL, '%s %s %s %s' % (COMMAND, TARGET_BOT_ID, WRECON_BOT_ID, COMMAND_ID))
    
    # Following part ensure we will remember our call,
    # and We will wait for all results until TIMEOUT_COMMAND_SHORT, then later results will be refused
    # ~ VERIFY_RESULT_ADV[COMMAND_ID] =
    
    WAIT_FOR_ADVERTISE[UNIQ_COMMAND_ID] = weechat.hook_timer(TIMEOUT_COMMAND_SHORT*1000, 0, 1, 'function_advertise_wait_result', UNIQ_COMMAND_ID)
    
    # ~ display_data('user_command_advertise', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    return weechat.WEECHAT_RC_OK
  
  #
  # ADVERTISE - RECEIVED FROM BUFFER (REQUESTED INFORMATION ABOUT BOT, WE NOW REPLY)
  #
  
  def buffer_command_advertise_1_requested(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global BUFFER_CMD_ADV_REP, BUFFER_CMD_ADA_REP, BUFFER_CMD_ADA_REQ, SCRIPT_VERSION, SCRIPT_TIMESTAMP, WRECON_BOT_NAME, WRECON_BOT_ID
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    if COMMAND == BUFFER_CMD_ADA_REQ:
      COMMAND_REPLY = BUFFER_CMD_ADA_REP
    else:
      COMMAND_REPLY = BUFFER_CMD_ADV_REP
    
    SCRIPT_FULL_VERSION = 'v%s %s' % (SCRIPT_VERSION, SCRIPT_TIMESTAMP)
    SCRIPT_FULL_VERSION = SCRIPT_FULL_VERSION.rstrip()
    
    display_message(BUFFER, '[%s] %s < ADVERTISE REQUESTED' % (COMMAND_ID, SOURCE_BOT_ID))
    weechat.command(BUFFER, '%s %s %s %s %s [%s]' % (COMMAND_REPLY, SOURCE_BOT_ID, WRECON_BOT_ID, COMMAND_ID, WRECON_BOT_NAME, SCRIPT_FULL_VERSION))
    
    # Clean up variables, we finished
    cleanup_unique_command_id('REMOTE', UNIQ_COMMAND_ID)
    
    # ~ display_data('buffer_command_advertise_1_requested', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    return weechat.WEECHAT_RC_OK
  
  #
  # ADVERTISE - RECEIVED FROM BUFFER (RECEIVED INFORMATION ABOUT BOT, WE NOW SAVE)
  #
  
  def buffer_command_advertise_2_result_received(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global ID_CALL_LOCAL, BUFFER_CMD_ADV_REP, BUFFER_CMD_ADA_REP, WAIT_FOR_ADVERTISE, COUNT_ADVERTISED_BOTS, WAIT_FOR_VERIFICATION
    
    # ~ display_message(BUFFER, 'ADV RESULT RECEIVED %s' % [WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST])
    # ~ display_data('buffer_command_advertise_2_result_received', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    
    if COMMAND == BUFFER_CMD_ADA_REP:
      UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    else:
      UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    
    # This is prevetion against replies after timeout, or fake replies
    if not UNIQ_COMMAND_ID in ID_CALL_LOCAL:
      function_advertise_refuse_data(BUFFER, COMMAND_ID, SOURCE_BOT_ID)
    else:
      COUNT_ADVERTISED_BOTS +=1
      function_advertise_save_data(BUFFER, TAGS, PREFIX, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
      
      # In case it was additional advertise, we can stop hook and remove variables immediately
      # ~ UNIQ_ID = SOURCE_BOT_ID + COMMAND_ID
      # DEBUG
      # ~ display_message(BUFFER, 'DEBUG - buffer_command_advertise_2_result_received: WAIT_FOR_VERIFICATION : %s' % WAIT_FOR_VERIFICATION)
      if COMMAND == BUFFER_CMD_ADA_REP and UNIQ_COMMAND_ID in WAIT_FOR_ADVERTISE:
        weechat.unhook(WAIT_FOR_ADVERTISE[UNIQ_COMMAND_ID])
        del WAIT_FOR_ADVERTISE[UNIQ_COMMAND_ID]
      
      # ADDITIONAL ADVERTISE IS USUALLY CALLED WHEN DATA NEEDED
      # THEN WE CHECK WHICH COMMAND INITIATED
        if UNIQ_COMMAND_ID in WAIT_FOR_VERIFICATION:
          RECALL_FUNCTION, WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID = WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID]
          RECALL_FUNCTION(WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID)
    
    # Clean up variables, we finished
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    cleanup_unique_command_id('REMOTE', UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # ADVERTISE - HOOK TIMER (WAIT FOR RESULT)
  #
  
  def function_advertise_wait_result(UNIQ_COMMAND_ID, REMAINING_CALLS):
    global WRECON_BUFFER_CHANNEL, ID_CALL_LOCAL, COUNT_ADVERTISED_BOTS, WAIT_FOR_ADVERTISE, WRECON_BOT_ID, WAIT_FOR_VERIFICATION
    
    if int(REMAINING_CALLS) == 0:
      if len(UNIQ_COMMAND_ID) > 16:
        TARGET_BOT_ID = UNIQ_COMMAND_ID[0:15]
        COMMAND_ID    = UNIQ_COMMAND_ID[16:]
      else:
        TARGET_BOT_ID = WRECON_BOT_ID
        COMMAND_ID    = UNIQ_COMMAND_ID[0:8]
      
      # DEBUG
      # ~ display_message(WRECON_BUFFER_CHANNEL, 'DEBUG - function_advertise_wait_result: UNIQ_COMMAND_ID : %s' % UNIQ_COMMAND_ID)
      # ~ display_message(WRECON_BUFFER_CHANNEL, 'DEBUG - function_advertise_wait_result: TARGET_BOT_ID   : %s' % TARGET_BOT_ID)
      # ~ display_message(WRECON_BUFFER_CHANNEL, 'DEBUG - function_advertise_wait_result: COMMAND_ID      : %s' % COMMAND_ID)
      
      display_message(WRECON_BUFFER_CHANNEL, '[%s] Number of bots advertised : %s' % (COMMAND_ID, COUNT_ADVERTISED_BOTS))
      
      # Command has been called locally, we also clean up LOCAL CALL ID
      cleanup_unique_command_id('LOCAL', UNIQ_COMMAND_ID)
      
      # We need unhook our timer
      weechat.unhook(WAIT_FOR_ADVERTISE[UNIQ_COMMAND_ID])
      
      # ~ display_message(WRECON_BUFFER_CHANNEL, 'ADV RESULT : %s' % WAIT_FOR_VERIFICATION)
      
      # And recall requested command, when was requested for additional verification (advertisement)
      if UNIQ_COMMAND_ID in WAIT_FOR_VERIFICATION:
        RECALL_FUNCTION, WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID = WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID]
        RECALL_FUNCTION(WEECHAT_DATA, BUFFER, SOURCE, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS, UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # ADVERTISE - SAVE AND DISPLAY DATA OF REMOTE BOT
  #
  
  def function_advertise_save_data(BUFFER, TAGS, PREFIX, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS):
    global WRECON_REMOTE_BOTS_ADVERTISED
    
    WRECON_REMOTE_BOTS_ADVERTISED[SOURCE_BOT_ID] = get_basic_data_of_remote_bot(TAGS, PREFIX, COMMAND_ARGUMENTS)
    SOURCE_BOT_NAME                              = WRECON_REMOTE_BOTS_ADVERTISED[SOURCE_BOT_ID].split('|')[0]
    SOURCE_BOT_VERSION                           = WRECON_REMOTE_BOTS_ADVERTISED[SOURCE_BOT_ID].split('|')[1]
    
    display_message(BUFFER, '[%s] REMOTE BOT REGISTERED -> %s (%s) [v%s]' % (COMMAND_ID, SOURCE_BOT_ID, SOURCE_BOT_NAME, SOURCE_BOT_VERSION))
    # ~ display_message(BUFFER, '[%s] DATA SAVED : %s' % (COMMAND_ID, WRECON_REMOTE_BOTS_ADVERTISED[SOURCE_BOT_ID]))
    
    return weechat.WEECHAT_RC_OK
  
  #
  # ADVERTISE - REFUSE DATA AFTER TIMEOUT, OR FAKE DATA OF REMOTE BOT
  #
  
  def function_advertise_refuse_data(BUFFER, COMMAND_ID, SOURCE_BOT_ID):
    global WRECON_REMOTE_BOTS_ADVERTISED
    
    if SOURCE_BOT_ID in WRECON_REMOTE_BOTS_ADVERTISED:
      del WRECON_REMOTE_BOTS_ADVERTISED[SOURCE_BOT_ID]
    
    OUT_MESSAGE     = ['[%s] REMOTE BOT REFUSED -> %s ' % (COMMAND_ID, SOURCE_BOT_ID)]
    OUT_MESSAGE.append('[%s] TIMEOUT OR FAKE REPLY' % COMMAND_ID)

    display_message(BUFFER, OUT_MESSAGE)

    return weechat.WEECHAT_RC_OK
  
  #
  # ADVERTISE - SETUP VARIABLES
  #
  
  def setup_command_variables_advertise():
    global BUFFER_CMD_ADV_REQ, BUFFER_CMD_ADV_REP, BUFFER_CMD_ADA_REQ, BUFFER_CMD_ADA_REP, BUFFER_CMD_ADV_ERR, COLOR_TEXT
    BUFFER_CMD_ADV_REQ = '%sE-ADV' % (COMMAND_IN_BUFFER)
    BUFFER_CMD_ADV_REP = '%sADV-R' % (COMMAND_IN_BUFFER)
    BUFFER_CMD_ADV_ERR = '%sADV-E' % (COMMAND_IN_BUFFER)
    BUFFER_CMD_ADA_REQ = '%sE-ADA' % (COMMAND_IN_BUFFER)
    BUFFER_CMD_ADA_REP = '%sADA-R' % (COMMAND_IN_BUFFER)
    
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION
    
    global HELP_COMMAND
    
    HELP_COMMAND['ADV'] = '''
%(bold)s%(italic)s--- ADV[ERTISE]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
 Show your BOT ID in Channel and also other bots will show their IDs
   /wrecon ADV
   /wrecon ADVERTISE
'''
    
    HELP_COMMAND['ADVERTISE'] = HELP_COMMAND['ADV']
    
    SCRIPT_ARGS                      = SCRIPT_ARGS + ' | [ADV[ERTISE]]'
    SCRIPT_ARGS_DESCRIPTION          = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['ADVERTISE']
    
    global SHORT_HELP
    SHORT_HELP                       = SHORT_HELP + '''
ADVERTISE          ADV[ERTISE]'''
    
    
    global SCRIPT_COMPLETION, SCRIPT_COMMAND_CALL, PREPARE_USER_CALL, SCRIPT_BUFFER_CALL, SCRIPT_INTERNAL_CALL
    SCRIPT_COMPLETION                = SCRIPT_COMPLETION + ' || ADV || ADVERTISE'
    SCRIPT_COMMAND_CALL['ADVERTISE'] = user_command_advertise
    SCRIPT_COMMAND_CALL['ADA']       = SCRIPT_COMMAND_CALL['ADVERTISE']
    
    PREPARE_USER_CALL['ADV']         = prepare_command_advertise
    PREPARE_USER_CALL['ADVERTISE']   = PREPARE_USER_CALL['ADV']
    SCRIPT_INTERNAL_CALL['ADA']      = PREPARE_USER_CALL['ADV']
    
    SCRIPT_BUFFER_CALL[BUFFER_CMD_ADV_REQ] = buffer_command_advertise_1_requested
    SCRIPT_BUFFER_CALL[BUFFER_CMD_ADV_REP] = buffer_command_advertise_2_result_received
    
    SCRIPT_BUFFER_CALL[BUFFER_CMD_ADA_REQ] = SCRIPT_BUFFER_CALL[BUFFER_CMD_ADV_REQ]
    SCRIPT_BUFFER_CALL[BUFFER_CMD_ADA_REP] = SCRIPT_BUFFER_CALL[BUFFER_CMD_ADV_REP]
    
    SCRIPT_BUFFER_CALL[BUFFER_CMD_ADV_ERR] = ignore_buffer_command
    
    global ARGUMENTS_REQUIRED
    ARGUMENTS_REQUIRED['ADA'] = 1
    
    return
    
  #
  ###### END COMMAND ADVERTISEMENT
  
  ######
  #
  # COMMAND ME - PREPARE COMMAND FOR VALIDATION (CALLED FROM )
  
  def prepare_command_me(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_BOT_ID
    
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    
    TARGET_BOT_ID = WRECON_BOT_ID
    SOURCE_BOT_ID = WRECON_BOT_ID
    
    COMMAND = 'ME'
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # ME - DISPLAY INFORMATION (CALLED AFTER COMMAND VALIDATED)
  #
  
  def user_command_me(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_BOT_NAME, WRECON_BOT_ID, WRECON_BOT_KEY, SCRIPT_VERSION, SCRIPT_TIMESTAMP
    
    WRECON_VER, WRECON_STM = get_version_and_timestamp(SCRIPT_VERSION, SCRIPT_TIMESTAMP)
    
    OUT_MESSAGE     = []
    OUT_MESSAGE.append('Bot name  : %s' % WRECON_BOT_NAME)
    OUT_MESSAGE.append('Bot ID    : %s' % WRECON_BOT_ID)
    OUT_MESSAGE.append('Bot KEY   : %s' % WRECON_BOT_KEY)
    OUT_MESSAGE.append('VERSION   : %s' % WRECON_VER)
    OUT_MESSAGE.append('TIMESTAMP : %s' % WRECON_STM)
    
    global WRECON_CHANNEL, WRECON_SERVER, WRECON_CHANNEL_KEY, WRECON_CHANNEL_ENCRYPTION_KEY
    
    if WRECON_CHANNEL and WRECON_SERVER:
      OUT_MESSAGE.append('--- REGISTERED SERVER and CHANNEL ---')
      OUT_MESSAGE.append('SERVER                 : %s' % WRECON_SERVER)
      OUT_MESSAGE.append('CHANNEL                : %s' % WRECON_CHANNEL)
      OUT_MESSAGE.append('CHANNEL KEY            : %s' % WRECON_CHANNEL_KEY)
      OUT_MESSAGE.append('CHANNEL ENCRYPTION KEY : %s' % WRECON_CHANNEL_ENCRYPTION_KEY)
    
    OUT_MESSAGE.append('')
    display_message_info(BUFFER, 'INFO ME', OUT_MESSAGE)
    
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    cleanup_unique_command_id('LOCAL', UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # ME - SETUP VARIABLES
  #
  
  def setup_command_variables_me():
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCSCRIPT_COMMAND_CALLRIPT_COMMAND_CALL, COLOR_TEXT
    
    global HELP_COMMAND
    
    HELP_COMMAND['M'] = '''
%(bold)s%(italic)s--- M[E]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
 Show information about your bot Name, ID and KEY. In case you have registered Server and Channel, these informations will be shown as well.
 Information is displayed only to your buffer and not send to the Channel.
   /wrecon M
   /wrecon ME
'''
    
    HELP_COMMAND['ME'] = HELP_COMMAND['M']
    
    SCRIPT_ARGS               = SCRIPT_ARGS + '[M[E]]'
    SCRIPT_ARGS_DESCRIPTION   = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['ME']
    SCRIPT_COMPLETION         = SCRIPT_COMPLETION + 'M || ME'
    SCRIPT_COMMAND_CALL['ME'] = user_command_me
    
    global SHORT_HELP
    SHORT_HELP                       = SHORT_HELP + '''
ME                 M[E]'''
    
    global PREPARE_USER_CALL
    PREPARE_USER_CALL['M']    = prepare_command_me
    PREPARE_USER_CALL['ME']   = PREPARE_USER_CALL['M']
    
    return
  
  #
  ###### END COMMAND ME
  
  ######
  #
  # COMMAND REGISTER
  
  #
  # REGISTER - PREPARE COMMAND
  #
  
  def prepare_command_register(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_BOT_ID
    
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    COMMAND = 'REGISTER'
    
    TARGET_BOT_ID = WRECON_BOT_ID
    SOURCE_BOT_ID = WRECON_BOT_ID
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # REGISTER
  #
  
  def user_command_register(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_SERVER, WRECON_CHANNEL, WRECON_CHANNEL_KEY, WRECON_CHANNEL_ENCRYPTION_KEY, WRECON_BUFFER_CHANNEL
    
    ERROR_REGISTER = False
    
    WRECON_SERVERX  = weechat.string_eval_expression("${sec.data.wrecon_server}",{},{},{})
    WRECON_CHANNELX = weechat.string_eval_expression("${sec.data.wrecon_channel}",{},{},{})
    
    OUT_MESSAGE = ['']
    
    # Check previously registered Server and Channel
    if WRECON_SERVERX and WRECON_CHANNELX:
      ERROR_REGISTER = True
      OUT_MESSAGE.append('ALREADY REGISTERED > First UNREGISTER, then REGISTER again.')
    
    # Check we have two parameters
    if not len(COMMAND_ARGUMENTS_LIST) == 2:
      ERROR_REGISTER = True
      OUT_MESSAGE.append('INCORRECT NUMBER OF PARAMETERS > 2 expected. See help.')
    
    # Now we can register Server and Channel when registration is prepared
    if ERROR_REGISTER == False:
      # Setup basic variables, CHANNEL KEY and CHANNEL ENCRYPT KEY is provided by USER
      WRECON_CHANNEL_KEY, WRECON_CHANNEL_ENCRYPTION_KEY = COMMAND_ARGUMENTS_LIST
      
      # Rest of variables are taken from actual BUFFER
      WRECON_SERVER         = weechat.buffer_get_string(BUFFER, 'localvar_server')
      WRECON_CHANNEL        = weechat.buffer_get_string(BUFFER, 'localvar_channel')
      WRECON_BUFFER_CHANNEL = BUFFER
      
      # Prepare output message of successful registration
      OUT_MESSAGE.append('SERVER                 : %s' % WRECON_SERVER)
      OUT_MESSAGE.append('CHANNEL                : %s' % WRECON_CHANNEL)
      OUT_MESSAGE.append('CHANNEL KEY            : %s' % WRECON_CHANNEL_KEY)
      OUT_MESSAGE.append('CHANNEL ENCRYPTION KEY : %s' % WRECON_CHANNEL_ENCRYPTION_KEY)
      
      # Save all variables into Weechat ()
      weechat.command(BUFFER, '/secure set wrecon_server %s' % (WRECON_SERVER))
      weechat.command(BUFFER, '/secure set wrecon_channel %s' % (WRECON_CHANNEL))
      weechat.command(BUFFER, '/secure set wrecon_channel_key %s' % (WRECON_CHANNEL_KEY))
      weechat.command(BUFFER, '/secure set wrecon_channel_encryption_key %s' % (WRECON_CHANNEL_ENCRYPTION_KEY))
      
      # Setup encryption for current SERVER and CHANNEL
      weechat.command(BUFFER, '/ircrypt set-key -server %s %s %s' % (WRECON_SERVER, WRECON_CHANNEL, WRECON_CHANNEL_ENCRYPTION_KEY))
      weechat.command(BUFFER, '/ircrypt set-cipher -server %s %s aes256' % (WRECON_SERVER, WRECON_CHANNEL))
      
      # Setup AUTOCONNECT, AUTORECONNECT, AUTOJOIN and AUTOREJOIN
      SETUP_RESULT = setup_autojoin(BUFFER, 'ADD', WRECON_SERVER, WRECON_CHANNEL)
      if SETUP_RESULT == True:
        OUT_MESSAGE.append('New options has been saved')
      else:
        OUT_MESSAGE.append('Nothing has been changed')
      
      # Setup MODE of Channel (lock by CHANNEL KEY)
      setup_channel(WRECON_BUFFER_CHANNEL)
      
      # And finally HOOK THE BUFFER
      hook_buffer()
    
    OUT_MESSAGE.append('')
    
    if ERROR_REGISTER == True:
      display_message_info(BUFFER, 'REGISTER ERROR', OUT_MESSAGE)
    else:
      display_message_info(BUFFER, 'REGISTER INFO', OUT_MESSAGE)
    
    UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    cleanup_unique_command_id('LOCAL', UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # REGISTER - SETUP VARIABLES
  #
  
  def setup_command_variables_register():
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_COMMAND_CALL, COLOR_TEXT, PREPARE_USER_CALL
    
    global HELP_COMMAND
    
    HELP_COMMAND['REG'] = '''
%(bold)s%(italic)s--- REG[ISTER] <ChannelKEY> <ChannelEncryptKEY>%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
 Register current channel for controling remote bot's. You have to be actively connected to server and joined in channel you need register.
 Opposite of command REGISTER is command UNREGISTER.
   /wrecon REG %s %s
   /wrecon REGISTER %s %s
''' % (get_random_string(8), get_random_string(16), get_random_string(8), get_random_string(16))
    
    HELP_COMMAND['REGISTER'] = HELP_COMMAND['REG']
    
    SCRIPT_ARGS                     = SCRIPT_ARGS + ' | [REG[ISTER] <ChannelKEY> <ChannelEncryptKEY>]'
    SCRIPT_ARGS_DESCRIPTION         = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['REGISTER']
    SCRIPT_COMPLETION               = SCRIPT_COMPLETION + ' || REG || REGISTER'
    SCRIPT_COMMAND_CALL['REGISTER'] = user_command_register
    
    global SHORT_HELP
    SHORT_HELP                       = SHORT_HELP + '''
REGISTER           REG[ISTER] <ChannelKEY> <ChannelEncryptKEY>'''
    
    PREPARE_USER_CALL['REG']      = prepare_command_register
    PREPARE_USER_CALL['REGISTER'] = prepare_command_register
    
    global ARGUMENTS_REQUIRED
    ARGUMENTS_REQUIRED['REGISTER'] = 2
    
    return
  
  #
  ###### END COMMAND REGISTER
  
  ######
  #
  # COMMAND UNREGISTER
  
  def prepare_command_unregister(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_BOT_ID
    
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    TARGET_BOT_ID   = WRECON_BOT_ID
    SOURCE_BOT_ID   = WRECON_BOT_ID
    
    COMMAND = 'UNREGISTER'
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # UNREGISTER
  #
  
  def user_command_unregister(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global SCRIPT_NAME, WRECON_SERVER, WRECON_CHANNEL, WRECON_CHANNEL_ENCRYPTION_KEY, WRECON_CHANNEL_ENCRYPTION_KEY
    
    UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    
    WRECON_SERVER  = weechat.string_eval_expression("${sec.data.wrecon_server}",{},{},{})
    WRECON_CHANNEL = weechat.string_eval_expression("${sec.data.wrecon_channel}",{},{},{})
    
    ERROR_UNREGISTER = False
    
    OUT_MESSAGE = ['']
    
    if not WRECON_SERVER and not WRECON_CHANNEL:
      ERROR_UNREGISTER = True
      OUT_MESSAGE.append('YOU HAVE NOTE REGISTERED SERVER AND CHANNEL')
      OUT_MESSAGE.append('Nothing to do')
    else:
      OUT_MESSAGE.append('SERVER  : %s' % WRECON_SERVER)
      OUT_MESSAGE.append('CHANNEL : %s' % WRECON_CHANNEL)
      
      SETUP_RESULT = setup_autojoin(BUFFER, 'DEL', WRECON_SERVER, WRECON_CHANNEL)
      
      # Remove all variables from Weechat
      weechat.command(BUFFER, '/secure del wrecon_server')
      weechat.command(BUFFER, '/secure del wrecon_channel')
      weechat.command(BUFFER, '/secure del wrecon_channel_key')
      weechat.command(BUFFER, '/secure del wrecon_channel_encryption_key')
      
      # Remove encryption for current SERVER and CHANNEL
      weechat.command(BUFFER, '/ircrypt remove-key -server %s %s %s' % (WRECON_SERVER, WRECON_CHANNEL, WRECON_CHANNEL_ENCRYPTION_KEY))
      weechat.command(BUFFER, '/ircrypt remove-cipher -server %s %s aes256' % (WRECON_SERVER, WRECON_CHANNEL))
      
      WRECON_SERVER                 = ''
      WRECON_CHANNEL                = ''
      WRECON_CHANNEL_KEY            = ''
      WRECON_CHANNEL_ENCRYPTION_KEY = ''
      
      if SETUP_RESULT == True:
        OUT_MESSAGE.append('Unregistration completed successfully')
      else:
        OUT_MESSAGE.append('Unexpected error occured during unregistration,')
        OUT_MESSAGE.append('options of autojoin has been removed out, but not by %s' % SCRIPT_NAME)
        ERROR_UNREGISTER = True
    
    OUT_MESSAGE.append('')
    
    if ERROR_UNREGISTER == True:
      display_message_info(BUFFER, 'UNREGISTER ERROR', OUT_MESSAGE)
    else:
      display_message_info(BUFFER, 'UNREGISTER INFO', OUT_MESSAGE)
    
    cleanup_unique_command_id(SOURCE, UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # UNREGISTER - SETUP VARIABLES
  #
  
  def setup_command_variables_unregister():
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_COMMAND_CALL, COLOR_TEXT, PREPARE_USER_CALL
    
    global HELP_COMMAND
    
    HELP_COMMAND['UN'] = '''
%(bold)s%(italic)s--- UN[REGIISTER]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
 Unregister channel of controling remote bot's.
   /wrecon UN
   /wrecon UNREGISTER
'''
    
    HELP_COMMAND['UNREGISTER'] = HELP_COMMAND['UN']
    
    global SHORT_HELP
    SHORT_HELP                        = SHORT_HELP + '''
UNREGISTER         UN[REGISTER]'''
    
    SCRIPT_ARGS                       = SCRIPT_ARGS + ' | [UN[REGISTER]]'
    SCRIPT_ARGS_DESCRIPTION           = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['UNREGISTER']
    
    SCRIPT_COMPLETION                 = SCRIPT_COMPLETION + ' || UNREG || UNREGISTER'
    SCRIPT_COMMAND_CALL['UNREGISTER'] = user_command_unregister
    
    PREPARE_USER_CALL['UN']           = prepare_command_unregister
    PREPARE_USER_CALL['UNREGISTER']   = PREPARE_USER_CALL['UN']
    
    return
    
  #
  ###### END COMMAND UNREGISTER
  
  ######
  #
  # COMMAND ADD - ADD REMOTE BOT YOU WANT CONTROL
  
  #
  # ADD - PREPARE
  #
  
  def prepare_command_add(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_REMOTE_BOTS_CONTROL, WRECON_BOT_ID
    
    COMMAND = 'ADD'
    
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - prepare_command_add: COMMAND_ARGUMENTS_LIST : %s' % COMMAND_ARGUMENTS_LIST)
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # ADD - COMMAND
  #
  
  def user_command_add(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global ID_CALL_LOCAL, WRECON_REMOTE_BOTS_CONTROL, WRECON_REMOTE_BOTS_CONTROL_SECRET
    
    OUT_MESSAGE = []
    
    UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - user_command_add: COMMAND_ARGUMENTS_LIST : %s' % COMMAND_ARGUMENTS_LIST)
    
    NEW_BOT_ID  = COMMAND_ARGUMENTS_LIST[0]
    NEW_BOT_KEY = COMMAND_ARGUMENTS_LIST[1]
    
    COMMAND_ARGUMENTS_LIST.pop(0)
    COMMAND_ARGUMENTS_LIST.pop(0)
    
    if len(COMMAND_ARGUMENTS_LIST) > 0:
      NEW_BOT_INFO = ' '.join(COMMAND_ARGUMENTS_LIST)
    else:
      NEW_BOT_INFO = ''
    
    if NEW_BOT_ID in WRECON_REMOTE_BOTS_CONTROL:
      OUT_MESSAGE_TAG = 'ADD ERROR'
      OUT_MESSAGE.append('BOT ID %s ALREADY EXIST IN YOUR LIST.' % NEW_BOT_ID)
    else:
      OUT_MESSAGE_TAG = 'ADD INFO'
      OUT_MESSAGE.append('NEW BOT ID %s (%s) HAS BEEN SUCCESSFULLY ADDED.' % (NEW_BOT_ID, WRECON_REMOTE_BOTS_CONTROL[WRECON_REMOTE_BOTS_CONTROL][1]))
      WRECON_REMOTE_BOTS_CONTROL[NEW_BOT_ID]         = [NEW_BOT_KEY, NEW_BOT_INFO]
      WRECON_REMOTE_BOTS_CONTROL_SECRET[NEW_BOT_ID] = []
      OUT_MESSAGE.append('%s (%s)' % (NEW_BOT_ID, WRECON_REMOTE_BOTS_CONTROL[NEW_BOT_ID][1]))
      weechat.command(BUFFER, '/secure set wrecon_remote_bots_control %s' % (WRECON_REMOTE_BOTS_CONTROL))
      weechat.command(BUFFER, '/secure set wrecon_remote_bots_control_secret %s' % (WRECON_REMOTE_BOTS_CONTROL_SECRET))
    
    OUT_MESSAGE.append('')
    
    display_message_info(BUFFER, OUT_MESSAGE_TAG, OUT_MESSAGE)
    
    if UNIQ_COMMAND_ID in ID_CALL_LOCAL:
      del ID_CALL_LOCAL[UNIQ_COMMAND_ID]
    
    return weechat.WEECHAT_RC_OK
  
  #
  # ADD - SETUP VARIABLES
  #
  
  def setup_command_variables_add():
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_COMMAND_CALL, COLOR_TEXT, WRECON_DEFAULT_BOTNAMES, PREPARE_USER_CALL
    
    global HELP_COMMAND
    
    HELP_COMMAND['ADD'] = '''
%(bold)s%(italic)s--- ADD <BotID> <BotKEY> [a note]%(nitalic)s%(nbold)s
 Add remote bot for your control. By command ADVERTISE you will know %(italic)sbotid%(nitalic)s, but the %(italic)sbotkey%(nitalic)s you need receive by safe way.''' % COLOR_TEXT + '''
 Opposite of command ADD is command DEL.
   /wrecon ADD %s %s
   /wrecon ADD %s %s %s
''' % (get_random_string(16), get_random_string(64), get_random_string(16), get_random_string(64), random.choice(WRECON_DEFAULT_BOTNAMES))
    
    SCRIPT_ARGS                = SCRIPT_ARGS + ' | [ADD <BotID> <BotKEY> [a note]]'
    SCRIPT_ARGS_DESCRIPTION    = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['ADD']
    SCRIPT_COMPLETION          = SCRIPT_COMPLETION + ' || ADD'
    SCRIPT_COMMAND_CALL['ADD'] = user_command_add
    
    PREPARE_USER_CALL['ADD']   = prepare_command_add
    
    global SHORT_HELP
    
    SHORT_HELP                        = SHORT_HELP + '''
ADD                ADD <BotID> <BotKEY> [a note]'''
    
    global ARGUMENTS_REQUIRED_MINIMAL
    ARGUMENTS_REQUIRED_MINIMAL['ADD'] = 2
    
    return
  
  #
  ###### END COMMAND ADD
  
  ######
  #
  # COMMAND DEL
  
  #
  # DEL - PREPARE
  #
  
  def prepare_command_del(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_REMOTE_BOTS_CONTROL, WRECON_BOT_ID, WRECON_REMOTE_BOTS_CONTROL_SECRET
    
    COMMAND = 'DELETE'
    
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # DEL -COMMAND
  #
  
  def user_command_del(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global ID_CALL_LOCAL, WRECON_REMOTE_BOTS_CONTROL, WRECON_REMOTE_BOTS_CONTROL_SECRET
    
    OUT_MESSAGE = []
    
    UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - user_command_del: COMMAND_ARGUMENTS_LIST : %s' % COMMAND_ARGUMENTS_LIST)
    
    DEL_BOT_ID = get_bot_id(COMMAND_ARGUMENTS_LIST[0], WRECON_REMOTE_BOTS_CONTROL)
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - user_command_del: DEL_BOT_ID                 : %s' % DEL_BOT_ID)
    # ~ display_message(BUFFER, 'DEBUG - user_command_del: WRECON_REMOTE_BOTS_CONTROL : %s ' % WRECON_REMOTE_BOTS_CONTROL)
    
    if not DEL_BOT_ID in WRECON_REMOTE_BOTS_CONTROL:
      OUT_MESSAGE_TAG = 'DEL ERROR'
      OUT_MESSAGE.append('BOT ID %s DOES NOT EXISTS IN YOUR LIST.' % DEL_BOT_ID)
    else:
      OUT_MESSAGE_TAG = 'DEL INFO'
      OUT_MESSAGE.append('DELETE : %s (%s)' % (DEL_BOT_ID, WRECON_REMOTE_BOTS_CONTROL[DEL_BOT_ID][1]))
      OUT_MESSAGE.append('BOT ID %s HAS BEEN SUCCESSFULLY DELETED.' % DEL_BOT_ID)
      del WRECON_REMOTE_BOTS_CONTROL[DEL_BOT_ID]
      if DEL_BOT_ID in WRECON_REMOTE_BOTS_CONTROL_SECRET:
        del WRECON_REMOTE_BOTS_CONTROL_SECRET[DEL_BOT_ID]
      weechat.command(BUFFER, '/secure set wrecon_remote_bots_control %s' % (WRECON_REMOTE_BOTS_CONTROL))
      weechat.command(BUFFER, '/secure set wrecon_remote_bots_control_secret %s' % (WRECON_REMOTE_BOTS_CONTROL_SECRET))
    
    OUT_MESSAGE.append('')
    
    display_message_info(BUFFER, OUT_MESSAGE_TAG, OUT_MESSAGE)
    
    cleanup_unique_command_id(SOURCE, UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # DEL - SETUP VARIABLES
  #
  
  def setup_command_variables_del():
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_COMMAND_CALL, COLOR_TEXT, PREPARE_USER_CALL
    
    global HELP_COMMAND
    HELP_COMMAND['DEL'] = '''
%(bold)s%(italic)s--- DEL <BotID>|<INDEX>%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
 Delete remote bot from your control.
 Remote BOT can be chosen by BOT ID or INDEX number of list of ADDED bots.
   /wrecon DEL 4
   /wrecon DEL %s
''' % (get_random_string(16))
    
    HELP_COMMAND['DELETE'] = HELP_COMMAND['DEL']
    
    SCRIPT_ARGS                   = SCRIPT_ARGS + ' | [DEL[ETE] <botid>|<INDEX>]'
    SCRIPT_ARGS_DESCRIPTION       = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['DELETE']
    SCRIPT_COMPLETION             = SCRIPT_COMPLETION + ' || DEL || DELETE'
    SCRIPT_COMMAND_CALL['DELETE'] = user_command_del
    
    PREPARE_USER_CALL['DEL']      = prepare_command_del
    PREPARE_USER_CALL['DELETE']   = PREPARE_USER_CALL['DEL']
    
    global SHORT_HELP
    
    SHORT_HELP                        = SHORT_HELP + '''
DELETE             DEL[ETE] <BotID>|<INDEX>'''
    
    global ARGUMENTS_REQUIRED
    ARGUMENTS_REQUIRED['DELETE'] = 1
    
    return
  #
  ###### END COMMAND DEL
  
  ######
  #
  # COMMAND GRANT
  
  #
  # GRANT - PREPARE COMMAND
  #
  
  def prepare_command_grant(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_REMOTE_BOTS_CONTROL, WRECON_BOT_ID
    
    COMMAND = 'GRANT'
    
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # GRANT - COMMAND
  #
  
  def user_command_grant(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_REMOTE_BOTS_GRANTED, WRECON_REMOTE_BOTS_GRANTED_SECRET
    
    OUT_MESSAGE = []
    
    ADD_GRANTED = COMMAND_ARGUMENTS_LIST[0]
    
    COMMAND_ARGUMENTS_LIST.pop(0)
    
    ADD_GRANTED_INFO = ' '.join(COMMAND_ARGUMENTS_LIST)
    
    if ADD_GRANTED in WRECON_REMOTE_BOTS_GRANTED:
      OUT_MESSAGE_TAG  = 'GRANT ERROR'
      OUT_MESSAEG.append('BOT ID %s ALREADY EXIST IN YOUR LIST.' % ADD_GRANTED)
    else:
      WRECON_REMOTE_BOTS_GRANTED[ADD_GRANTED]         = ADD_GRANTED_INFO
      WRECON_REMOTE_BOTS_GRANTED_SECRET[ADD_GRANTED] = []
      OUT_MESSAGE_TAG = 'GRANT INFO'
      OUT_MESSAGE.append('NEW BOT ID %s (%s) HAS BEEN SUCCESSFULLY GRANTED.' % (ADD_GRANTED, WRECON_REMOTE_BOTS_GRANTED[ADD_GRANTED]))
      weechat.command(BUFFER, '/secure set wrecon_remote_bots_granted %s' % (WRECON_REMOTE_BOTS_GRANTED))
      weechat.command(BUFFER, '/secure set wrecon_remote_bots_granted_secret %s' % (WRECON_REMOTE_BOTS_GRANTED_SECRET))
    
    OUT_MESSAGE.append('')
    
    display_message_info(BUFFER, OUT_MESSAGE_TAG, OUT_MESSAGE)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # GRANT - PREPARE VARIABLES
  #
  
  def setup_command_variables_grant():
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_COMMAND_CALL, WRECON_DEFAULT_BOTNAMES, COLOR_TEXT, PREPARE_USER_CALL
    
    global HELP_COMMAND
    
    HELP_COMMAND['G'] = '''
%(bold)s%(italic)s--- G[RANT] <BotID> [a note]%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
 Grant access to your system for remote bot by botid. For update of your note of bot you can do execute GRANT command again.
 Opposite of command GRANT is command REVOKE.
   /wrecon GRANT %s
   /wrecon G %s
   /wrecon G %s %s
''' % (get_random_string(16), get_random_string(16), get_random_string(16), random.choice(WRECON_DEFAULT_BOTNAMES))
    
    HELP_COMMAND['GRANT']        = HELP_COMMAND['G']
    
    SCRIPT_ARGS                  = SCRIPT_ARGS + ' | [G[RANT] <BotID> [a note]]'
    SCRIPT_ARGS_DESCRIPTION      = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['GRANT']
    SCRIPT_COMPLETION            = SCRIPT_COMPLETION + ' || G || GRANT'
    SCRIPT_COMMAND_CALL['GRANT'] = user_command_grant 
    
    PREPARE_USER_CALL['G']       = prepare_command_grant
    PREPARE_USER_CALL['GRANT']   = PREPARE_USER_CALL['G']
    
    global SHORT_HELP
    
    SHORT_HELP                   = SHORT_HELP + '''
GRANT              G[RANT] <BotID> [a note]'''
    
    global ARGUMENTS_REQUIRED_MINIMAL
    ARGUMENTS_REQUIRED_MINIMAL['GRANT'] = 1
    
    return
  
  #
  ###### END COMMAND GRANT
  
  ######
  #
  # COMMAND REVOKE
  
  #
  # REVOKE - PREPARE COMMAND
  #
  def prepare_command_revoke(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_REMOTE_BOTS_CONTROL, WRECON_BOT_ID
    
    COMMAND = 'REVOKE'
    
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # REVOKE - COMMAND
  #
  
  def user_command_revoke(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_REMOTE_BOTS_GRANTED, WRECON_REMOTE_BOTS_GRANTED_SECRET
    
    OUT_MESSAGE = []
    
    UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - user_command_del: COMMAND_ARGUMENTS_LIST : %s' % COMMAND_ARGUMENTS_LIST)
    
    REVOKE_BOT_ID = get_bot_id(COMMAND_ARGUMENTS_LIST[0], WRECON_REMOTE_BOTS_GRANTED)
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - user_command_del: REVOKE_BOT_ID              : %s' % REVOKE_BOT_ID)
    # ~ display_message(BUFFER, 'DEBUG - user_command_del: WRECON_REMOTE_BOTS_GRANTED : %s' % WRECON_REMOTE_BOTS_GRANTED)
    
    if not REVOKE_BOT_ID in WRECON_REMOTE_BOTS_GRANTED:
      OUT_MESSAGE_TAG = 'REVOKE ERROR'
      OUT_MESSAGE.append('BOT ID %s DOES NOT EXISTS IN YOUR LIST.' % REVOKE_BOT_ID)
    else:
      OUT_MESSAGE_TAG = 'REVOKE INFO'
      OUT_MESSAGE.append('REVOKE : %s (%s)' % (REVOKE_BOT_ID, WRECON_REMOTE_BOTS_GRANTED[REVOKE_BOT_ID]))
      OUT_MESSAGE.append('BOT ID %s HAS BEEN SUCCESSFULLY REVOKED.' % REVOKE_BOT_ID)
      del WRECON_REMOTE_BOTS_GRANTED[REVOKE_BOT_ID]
      if REVOKE_BOT_ID in WRECON_REMOTE_BOTS_GRANTED_SECRET:
        del WRECON_REMOTE_BOTS_GRANTED_SECRET[REVOKE_BOT_ID]
      weechat.command(BUFFER, '/secure set wrecon_remote_bots_granted %s' % (WRECON_REMOTE_BOTS_GRANTED))
      weechat.command(BUFFER, '/secure set wrecon_remote_bots_granted_secret %s' % (WRECON_REMOTE_BOTS_GRANTED_SECRET))
    
    OUT_MESSAGE.append('')
    
    display_message_info(BUFFER, OUT_MESSAGE_TAG, OUT_MESSAGE)
    
    cleanup_unique_command_id(SOURCE, UNIQ_COMMAND_ID)
    return weechat.WEECHAT_RC_OK
  
  #
  # REVOKE - SETUP VARIABLES
  #
  
  def setup_command_variables_revoke():
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_COMMAND_CALL, COLOR_TEXT, PREPARE_USER_CALL
    
    global HELP_COMMAND
    
    HELP_COMMAND['REV'] = '''
%(bold)s%(italic)s--- REV[OKE] <BotID>|<INDEX>%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
 Revoke granted access to your system of remote bot.
 Remote BOT can be chosen by BOT ID or INDEX number of list of GRANTED.
   /wrecon REVOKE %s
   /wrecon REV %s
   /wrecon REV 3
''' % (get_random_string(16), get_random_string(16))
    
    HELP_COMMAND['REVOKE']        = HELP_COMMAND['REV']
    
    SCRIPT_ARGS                   = SCRIPT_ARGS + ' | [REV[OKE] <BotID>|<INDEX>]'
    SCRIPT_ARGS_DESCRIPTION       = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['REVOKE']
    
    SCRIPT_COMPLETION             = SCRIPT_COMPLETION + ' || REV || REVOKE'
    SCRIPT_COMMAND_CALL['REVOKE'] = user_command_revoke
    
    PREPARE_USER_CALL['REV']      = prepare_command_revoke
    PREPARE_USER_CALL['REVOKE']   = PREPARE_USER_CALL['REV']
    
    global ARGUMENTS_REQUIRED
    ARGUMENTS_REQUIRED['REVOKE']  = 1
    
    global SHORT_HELP
    
    SHORT_HELP                    = SHORT_HELP + '''
REVOKE             REV[OKE] <BotID>|<INDEX>'''
    
    return
  
  #
  ###### END COMMAND REVOKE
  
  ######
  #
  # COMMAND RENAME
  #
  
  #
  # RENAME - PREPARE COMMAND
  #
  
  def prepare_command_rename(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_BOT_ID, WRECON_REMOTE_BOTS_CONTROL
    
    COMMAND = 'RENAME'
    
    TARGET_BOT = COMMAND_ARGUMENTS_LIST[0].upper()
    
    if TARGET_BOT in ['M', 'MYBOT']:
      TARGET_BOT_ID = WRECON_BOT_ID
    else:
      TARGET_BOT_ID = get_bot_id(COMMAND_ARGUMENTS_LIST[0], WRECON_REMOTE_BOTS_CONTROL)
    
    COMMAND_ARGUMENTS_LIST.pop(0)
    
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # RENAME - COMMAND
  #
  
  def user_command_rename(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global BUFFER_CMD_REN_EXE, WRECON_BOT_ID, WAIT_FOR_RENAME, ID_CALL_LOCAL
    
    NEW_NAME        = ' '.join(COMMAND_ARGUMENTS_LIST)

    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - user_command_rename: %s' % [WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST])
    # ~ display_message(BUFFER, 'DEBUG - user_command_rename: NEW_NAME : %s' % NEW_NAME)
    
    if TARGET_BOT_ID == WRECON_BOT_ID:
      function_rename_save_data(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    else:
      UNIQ_COMMAND_ID                  = TARGET_BOT_ID + COMMAND_ID
      weechat.command(BUFFER, '%s %s %s %s %s' % (BUFFER_CMD_REN_EXE, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, NEW_NAME))
      ID_CALL_LOCAL[UNIQ_COMMAND_ID]   = 'RENAME %s' % TARGET_BOT_ID
      WAIT_FOR_RENAME[UNIQ_COMMAND_ID] = weechat.hook_timer(TIMEOUT_COMMAND_SHORT*1000, 0, 1, 'function_rename_wait_result', UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # RENAME - REQUEST RECEIVED
  #
  
  def buffer_command_rename_1_requested(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    function_rename_save_data(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    
    cleanup_unique_command_id('REMOTE', UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # RENAME - RESULT RECEIVED
  #
  
  def buffer_command_rename_2_result_received(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_BOT_ID, ID_CALL_LOCAL, WAIT_FOR_RENAME, WAIT_FOR_VERIFICATION
    display_message(BUFFER, '[%s] %s < RENAME HAS BEEN ACCEPTED' % (COMMAND_ID, SOURCE_BOT_ID))
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    
    # DEBUG
    # ~ display_data('DEBUG - buffer_command_rename_2_result_received', WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST)
    # ~ display_message(BUFFER, 'DEBUG - buffer_command_rename_2_result_received: UNIQ_COMMAND_ID : %s' % UNIQ_COMMAND_ID)
    # ~ display_message(BUFFER, 'DEBUG - buffer_command_rename_2_result_received: WAIT_FOR_RENAME : %s' % WAIT_FOR_RENAME)
    
    # We unhook previous waiting for RENAME
    if UNIQ_COMMAND_ID in WAIT_FOR_RENAME:
      weechat.unhook(WAIT_FOR_RENAME[UNIQ_COMMAND_ID])
      del WAIT_FOR_RENAME[UNIQ_COMMAND_ID]
    
    if UNIQ_COMMAND_ID in WAIT_FOR_VERIFICATION:
      del WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID]
    
    # We will wait for additional advertise to get new data of remote bot
    ID_CALL_LOCAL[UNIQ_COMMAND_ID]   = 'RENAME - READVERTISE %s' % SOURCE_BOT_ID
    WAIT_FOR_RENAME[UNIQ_COMMAND_ID] = weechat.hook_timer(TIMEOUT_COMMAND_SHORT*1000, 0, 1, 'function_rename_wait_result', UNIQ_COMMAND_ID)
    
    SOURCE = 'INTERNAL' 
    COMMAND_ADA = 'ADA %s %s %s' % (SOURCE_BOT_ID, COMMAND_ID, UNIQ_COMMAND_ID)
    command_pre_validation('', BUFFER, SOURCE, '', '', '', '', '', COMMAND_ADA)
    
    # And cleanup received remote command
    cleanup_unique_command_id('REMOTE', UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # RENAME - WAIT FOR RESULT
  #
  
  def function_rename_wait_result(UNIQ_COMMAND_ID, REMAINING_CALLS):
    global WRECON_BUFFER_CHANNEL, ID_CALL_LOCAL, COUNT_ADVERTISED_BOTS, WRECON_BOT_ID, WAIT_FOR_RENAME, WAIT_FOR_VERIFICATION
    
    if int(REMAINING_CALLS) == 0:
      if len(UNIQ_COMMAND_ID) > 16:
        TARGET_BOT_ID = UNIQ_COMMAND_ID[0:15]
        COMMAND_ID    = UNIQ_COMMAND_ID[16:]
      else:
        TARGET_BOT_ID = WRECON_BOT_ID
        COMMAND_ID    = UNIQ_COMMAND_ID[0:8]
      
      # DEBUG
      # ~ display_message(WRECON_BUFFER_CHANNEL, 'DEBUG - function_advertise_wait_result: UNIQ_COMMAND_ID : %s' % UNIQ_COMMAND_ID)
      # ~ display_message(WRECON_BUFFER_CHANNEL, 'DEBUG - function_advertise_wait_result: TARGET_BOT_ID   : %s' % TARGET_BOT_ID)
      # ~ display_message(WRECON_BUFFER_CHANNEL, 'DEBUG - function_advertise_wait_result: COMMAND_ID      : %s' % COMMAND_ID)
      
      display_message(WRECON_BUFFER_CHANNEL, '[%s] Number of bots advertised : %s' % (COMMAND_ID, COUNT_ADVERTISED_BOTS))
      
      # Command has been called locally, we also clean up LOCAL CALL ID
      cleanup_unique_command_id('LOCAL', UNIQ_COMMAND_ID)
      
      # We need unhook our timer
      weechat.unhook(WAIT_FOR_RENAME[UNIQ_COMMAND_ID])
      
      if UNIQ_COMMAND_ID in WAIT_FOR_RENAME:
        del WAIT_FOR_RENAME[UNIQ_COMMAND_ID]
      
      if UNIQ_COMMAND_ID in WAIT_FOR_VERIFICATION:
        del WAIT_FOR_VERIFICATION[UNIQ_COMMAND_ID]
      
    return weechat.WEECHAT_RC_OK
  
  #
  # RENAME - SAVE DATA
  #
  
  def function_rename_save_data(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_BOT_NAME, BUFFER_CMD_REN_REP
    
    NEW_NAME = ' '.join(COMMAND_ARGUMENTS_LIST)
    
    # DEBUG
    # ~ display_message(BUFFER, 'DEBUG - function_rename_save_data: %s' % [WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST])
    # ~ display_message(BUFFER, 'DEBUG - function_rename_save_data: NEW_NAME : %s' % NEW_NAME)
    
    WRECON_BOT_NAME = NEW_NAME
    
    weechat.command('', '/secure set wrecon_bot_name %s' % WRECON_BOT_NAME)
    
    if not TARGET_BOT_ID == SOURCE_BOT_ID:
      weechat.command(BUFFER, '%s %s %s %s RENAME ACCEPTED' % (BUFFER_CMD_REN_REP, SOURCE_BOT_ID, TARGET_BOT_ID, COMMAND_ID))
    
    UNIQ_COMMAND_ID = SOURCE_BOT_ID + COMMAND_ID
    cleanup_unique_command_id('LOCAL', UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # RENAME - SETUP VARIABLES
  #
  
  def setup_command_variables_rename():
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, COLOR_TEXT, SCRIPT_COMPLETION, SCRIPT_COMMAND_CALL, BUFFER_CMD_REN_EXE, BUFFER_CMD_REN_REP, PREPARE_USER_CALL, COMMAND_VERSION, GLOBAL_VERSION_LIMIT, WRECON_DEFAULT_BOTNAMES
    BUFFER_CMD_REN_EXE   = '%sE-REN'   % (COMMAND_IN_BUFFER)
    BUFFER_CMD_REN_REP   = '%sREN-R'   % (COMMAND_IN_BUFFER)
    
    global HELP_COMMAND
    
    HELP_COMMAND['REN'] = '''
%(bold)s%(italic)s--- REN[AME] <M[YBOT]|<BotID>|<INDEX> <New Name>%(nitalic)s%(nbold)s''' % COLOR_TEXT + '''
 Rename a BOT. For local bot use option M or MYBOT.
 For remote BOT can be chosen BOT ID or INDEX number of list of ADDED bots.
   /wrecon RENAME MYBOT %s
   /wrecon RENAME 3 %s
   /wrecon RENAME %s %s
   /wrecon REN M %s
   /wrecon REN 5 %s
''' % (random.choice(WRECON_DEFAULT_BOTNAMES), random.choice(WRECON_DEFAULT_BOTNAMES), get_random_string(16), random.choice(WRECON_DEFAULT_BOTNAMES), random.choice(WRECON_DEFAULT_BOTNAMES), random.choice(WRECON_DEFAULT_BOTNAMES))
    
    HELP_COMMAND['RENAME']        = HELP_COMMAND['REN']
    
    SCRIPT_ARGS                   = SCRIPT_ARGS + ' | [REN[AME] <M[YBOT]|BotID>|<INDEX> <New Name>]'
    SCRIPT_ARGS_DESCRIPTION       = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['RENAME']
    SCRIPT_COMPLETION             = SCRIPT_COMPLETION + ' || REN || RENAME'
    SCRIPT_COMMAND_CALL['RENAME'] = user_command_rename
    
    SCRIPT_BUFFER_CALL[BUFFER_CMD_REN_EXE]          = buffer_command_rename_1_requested
    SCRIPT_BUFFER_CALL[BUFFER_CMD_REN_REP]          = buffer_command_rename_2_result_received
    COMMAND_REQUIREMENTS_REMOTE[BUFFER_CMD_REN_EXE] = verify_remote_bot_granted
    
    PREPARE_USER_CALL['REN']      = prepare_command_rename
    PREPARE_USER_CALL['RENAME']   = PREPARE_USER_CALL['REN']
    
    global ARGUMENTS_REQUIRED_MINIMAL
    ARGUMENTS_REQUIRED_MINIMAL['RENAME']           = 2
    ARGUMENTS_REQUIRED_MINIMAL[BUFFER_CMD_REN_EXE] = 1
    
    COMMAND_VERSION[BUFFER_CMD_REN_EXE] = GLOBAL_VERSION_LIMIT
    
    global SHORT_HELP
    
    SHORT_HELP                    = SHORT_HELP + '''
RENAME             REN[AME] M[YBOT]|<BotID>|<INDEX> <New Name>'''
    
    return
  
  #
  ###### END COMMAND RENAME
  
  ######
  #
  # COMMAND LIST
  #
  
  #
  # LIST - PREPARE COMMAND
  #
  
  def prepare_command_list(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global WRECON_BOT_ID
    
    COMMAND         = 'LIST'
    UNIQ_COMMAND_ID = WRECON_BOT_ID + COMMAND_ID
    
    if len(COMMAND_ARGUMENTS_LIST) == 1:
      COMMAND_ARGUMENT = COMMAND_ARGUMENTS_LIST[0].upper()
      
      if COMMAND_ARGUMENT in ['A', 'ADDED']:
        COMMAND_ARGUMENTS_LIST[0] = 'ADDED'
      
      if COMMAND_ARGUMENT in ['G', 'GRANTED']:
        COMMAND_ARGUMENTS_LIST[0] = 'GRANTED'
    
    return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  #
  # LIST
  #
  
  def user_command_list(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    global SCRIPT_NAME, WRECON_REMOTE_BOTS_CONTROL, WRECON_REMOTE_BOTS_GRANTED, WRECON_REMOTE_BOTS_ADVERTISED
    
    OUT_MESSAGE_TAG = 'LIST INFO'
    
    UNIQ_COMMAND_ID = TARGET_BOT_ID + COMMAND_ID
    
    COMMAND_ARGUMENT = COMMAND_ARGUMENTS_LIST[0]
    
    if not COMMAND_ARGUMENT in ['ADDED', 'GRANTED']:
      OUT_MESSAGE_TAG = 'LIST ERROR'
      OUT_MESSAGE     = ['ERROR: INCORRECT ARGUMENT']
      OUT_MESSAGE.append('See help for command /%s HELP %s' % (SCRIPT_NAME, COMMAND))
      OUT_MESSAGE.append('')
    else:
      if COMMAND_ARGUMENT == 'ADDED':
        LIST_OF_BOTS = WRECON_REMOTE_BOTS_CONTROL
      else:
        LIST_OF_BOTS = WRECON_REMOTE_BOTS_GRANTED
      
      OUT_MESSAGE_TAG = 'LIST OF %s BOT(s)' % COMMAND_ARGUMENT
      OUT_MESSAGE     = ['INDEX    BOT ID              Info                         Advertised']
      OUT_MESSAGE.append('------   -----------------   --------------------------   --------------------------')
      
      if len(LIST_OF_BOTS) == 0:
        OUT_MESSAGE.append('No records found in table of %s BOTs' % COMMAND_ARGUMENT)
      else:
        BOT_INDEX = 0
        
        for REMOTE_BOT in LIST_OF_BOTS:
          BOT_INDEX += 1
          SHOW_DATA       = ''
          if REMOTE_BOT in WRECON_REMOTE_BOTS_ADVERTISED:
            DATA_ADVERTISED  = '   %s' % WRECON_REMOTE_BOTS_ADVERTISED[REMOTE_BOT]
            
            SHOW_BOT_NAME    = DATA_ADVERTISED.split('|')[0]
            if SHOW_BOT_NAME == '':
              SHOW_BOT_NAME = 'Unnamed'
            
            SHOW_BOT_VERSION = DATA_ADVERTISED.split('|')[1]
            if SHOW_BOT_VERSION != '':
              SHOW_BOT_VERSION = 'v' + SHOW_BOT_VERSION
            
            if SHOW_BOT_VERSION == '':
              SHOW_DATA        = '%s (No version detected)' % SHOW_BOT_NAME
            else:
              SHOW_DATA        = '%s (%s)' % (SHOW_BOT_NAME, SHOW_BOT_VERSION)
          
          if COMMAND_ARGUMENT == 'ADDED':
            OUT_MESSAGE.append('%5d    %s    %-26s%s' % (BOT_INDEX, REMOTE_BOT, LIST_OF_BOTS[REMOTE_BOT][1], SHOW_DATA))
          else:
            OUT_MESSAGE.append('%5d    %s    %-26s%s' % (BOT_INDEX, REMOTE_BOT, LIST_OF_BOTS[REMOTE_BOT], SHOW_DATA))
      
      OUT_MESSAGE.append('')
      
    display_message_info(BUFFER, OUT_MESSAGE_TAG, OUT_MESSAGE)
    
    cleanup_unique_command_id(SOURCE, UNIQ_COMMAND_ID)
    
    return weechat.WEECHAT_RC_OK
  
  #
  # LIST - SETUP VARIABLES
  #
  
  def setup_command_variables_list():
    global SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_COMMAND_CALL, COLOR_TEXT, PREPARE_USER_CALL
    
    global HELP_COMMAND
    HELP_COMMAND['L'] = '''
%(bold)s%(italic)s--- L[IST] <A[DDED]>|<G[RANTED]>%(nitalic)s%(nbold)s
 List of ADDED bots you can control, or GRANTED bots which can control your system.
 List also contain INDEX numbers of ADDED or GRANTED bots.
   /wrecon LIST ADDED
   /wrecon L A
   /wrecon LIST G
   /wrecon L GRANTED
''' % COLOR_TEXT
    
    HELP_COMMAND['LIST']        = HELP_COMMAND['L']
    
    SCRIPT_ARGS                 = SCRIPT_ARGS + ' | [L[IST] <A[DDED]>|<G[RANTED]>]'
    SCRIPT_ARGS_DESCRIPTION     = SCRIPT_ARGS_DESCRIPTION + HELP_COMMAND['LIST']
    SCRIPT_COMPLETION           = SCRIPT_COMPLETION + ' || L || LIST'
    SCRIPT_COMMAND_CALL['LIST'] = user_command_list
    
    PREPARE_USER_CALL['L']      = prepare_command_list
    PREPARE_USER_CALL['LIST']   = PREPARE_USER_CALL['L']
    
    global SHORT_HELP
    
    SHORT_HELP                        = SHORT_HELP + '''
LIST               L[IST] A[DDED]|G[RANTED]'''
    
    global ARGUMENTS_REQUIRED
    ARGUMENTS_REQUIRED['LIST']  = 1
    
    return
  
  #
  ###### END COMMAND LIST
  
  #
  ###### END ALL COMMANDS
  
  # TEMPLATE OF COMMANDS
  # ~ def prepare_command_(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    # ~ return [COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST, UNIQ_COMMAND_ID]
  
  # ~ def user_command_(WEECHAT_DATA, BUFFER, SOURCE, DATE, TAGS, DISPLAYED, HIGHLIGHT, PREFIX, COMMAND, TARGET_BOT_ID, SOURCE_BOT_ID, COMMAND_ID, COMMAND_ARGUMENTS_LIST):
    # ~ return weechat.WEECHAT_RC_OK
  
  # ~ def setup_command_variables_():
    # ~ return
  
  ######
  #
  # START WRECON
  
  #
  # SETUP COMMAND VARIABLES
  #
  
  def setup_wrecon_variables():
    
    # SETUP INTERNAL VARIABLES AND VARIABLES FOR FUNCTIONS
    setup_wrecon_variables_of_local_bot()
    setup_wrecon_variables_of_server_and_channel()
    setup_wrecon_variables_of_public_key()
    setup_wrecon_variables_of_functions()
    setup_wrecon_variables_of_setup_autojoin()
    setup_wrecon_variables_of_validate_command()
    setup_wrecon_variables_of_remote_bots()
    
    # SETUP VARIABLES OF COMMANDS
    # This ensure alphabetical sort of help instructions, because command
    # functions are not sorted alphabetically
    setup_command_variables_add()
    setup_command_variables_advertise()
    setup_command_variables_del()
    setup_command_variables_grant()
    setup_command_variables_help()
    setup_command_variables_list()
    setup_command_variables_me()
    setup_command_variables_register()
    setup_command_variables_rename()
    setup_command_variables_revoke()
    setup_command_variables_unregister()
    setup_command_variables_update()
    setup_command_variables_verify()
    
    global SHORT_HELP
    SHORT_HELP = SHORT_HELP + '''

'''
    
    return
  
  #
  # START WRECON
  #
  
  def start_wrecon():
    
    setup_wrecon_variables()
    
    wrecon_hook_local_commands = weechat.hook_command(SCRIPT_NAME, SCRIPT_DESC, SCRIPT_ARGS, SCRIPT_ARGS_DESCRIPTION, SCRIPT_COMPLETION, SCRIPT_CALLBACK, '')
    
    SCRIPT_FULL_VERSION = 'v%s %s' % (SCRIPT_VERSION, SCRIPT_TIMESTAMP)
    SCRIPT_FULL_VERSION = SCRIPT_FULL_VERSION.rstrip()
    
    display_message('', 'Script %s %s initialization complete' % (SCRIPT_NAME, SCRIPT_FULL_VERSION))
    
    autoconnect()
    
    return
  
  start_wrecon()
    
  #
  ##### END START WRECON
