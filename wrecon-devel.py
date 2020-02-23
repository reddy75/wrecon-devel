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
for import_mod in ['ast', 'base64', 'contextlib', 'datetime', 'gnupg', 'hashlib', 'json', 'os', 'random', 'shutil', 'string', 'sys', 'tarfile', 'time', 'urllib', 'weechat']:
  try:
    import_object = importlib.import_module(import_mod, package=None)
    globals()[import_mod] = import_object
    # ~ print('[%s v%s] > module %s imported' % (SCRIPT_NAME, SCRIPT_VERSION, import_mod))
  except ImportError:
    SCRIPT_CONTINUE = False
    print('[%s v%s] > module >> %s << import error' % (SCRIPT_NAME, SCRIPT_VERSION, import_mod))


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
  
  def get_random_string(mylength):
    lettersAndDigits = string.ascii_letters + string.digits
    return ''.join(random.choice(lettersAndDigits) for i in range(mylength))
  
  #####
  #
  # FUNCTION GET HASH OF A STRING
  
  def get_hash(mystring):
    result = hashlib.md5(mystring.encode())
    return str(result.hexdigest())
  
  #####
  #
  # FUNCTION FOR COUNTING COMMANDS AND ADD UNIQ HASH
  
  def get_command_uniq_id():
    global wrecon_command_counter
    wrecon_command_counter = wrecon_command_counter + 1
    if wrecon_command_counter > 9999:
      wrecon_command_counter = 0
    return '%04d-%s' % (wrecon_command_counter, get_random_string(4))
  
  #####
  #
  # FUNCTION FOR VERIFY CHANNEL SETUP AND POSSIBILITY TO CHANGE MODE IF NECESSARY
  
  def setup_channel(data, buffer, servername, channelname):
    global wrecon_channel_key
    result      = 0
    resultnick  = 0
    resultchan  = 0
    resultmode  = 0
    my_nickname = weechat.info_get('irc_nick', servername)
    infolist    = weechat.infolist_get('irc_nick', '', '%s,%s' % (servername, channelname))
    while weechat.infolist_next(infolist):
      found_nickname = weechat.infolist_string(infolist, 'name')
      if my_nickname == found_nickname:
        my_prefix   = weechat.infolist_string(infolist, 'prefix')
        my_prefixes = weechat.infolist_string(infolist, 'prefixes')
        if '@' in my_prefixes:
          resultnick = 1
    weechat.infolist_free(infolist)

    infolist   = weechat.infolist_get('irc_channel', '', '%s,%s' % (servername, channelname))
    while weechat.infolist_next(infolist):
      my_channel_name = weechat.infolist_string(infolist, 'name')
      my_channel_key  = weechat.infolist_string(infolist, 'key')
      my_channel_mode = weechat.infolist_string(infolist, 'modes')
      if my_channel_name == channelname:
        if not wrecon_channel_key in my_channel_mode:
          resultchan = 1
        if not 'k' in my_channel_mode:
          resultmode = 1
        
    weechat.infolist_free(infolist)
    
    if resultnick == 1:
      if resultmode == 1 or resultchan == 1:
        weechat.command(buffer, '/mode %s -n+sk %s' % (channelname, wrecon_channel_key))
    return result
    
  #####
  #
  # FUNCTION ENCRYPT AND DECTRYPT STRING
  #
  # CORRECT LENGTH OF ENCRYPT/DECRYPT KEY

  def encdec_keylen(istring, ikey):
    xkey = ikey
    while len(istring) > len(ikey):
      ikey += xkey
    return ikey
  
  #
  # ENCRYPT
  #
  
  def encrypt_string(level, estring, encrypt_key):
    global ENCRYPT_LEVEL
    return ENCRYPT_LEVEL[level]

  def encrypt_string_L0(estring, encrypt_key):
    encrypt_key = encdec_keylen(estring, encrypt_key)
    out         = []
    for i in range(len(estring)):
      k_c = estring[i % len(estring)]
      o_c = chr((ord(encrypt_key[i]) + ord(k_c)) % 256)
      out.append(o_c)
    return base64.urlsafe_b64encode(''.join(out).encode()).decode()
  
  def encrypt_string_L1(estring, encrypt_key):
    encrypt_key     = encdec_keylen(estring, encrypt_key)
    new_encrypt_key = get_hash(encrypt_key)
    my_salt         = f_random_generator(8)
    enc_result_l1   = encrypt_string_L0(estring, my_salt + encrypt_key)
    enc_result_l2   = encrypt_string_L0(my_salt + enc_result_l1, new_encrypt_key)
    return base64.urlsafe_b64encode(enc_result_l2.encode()).decode()
  
  global ENCRYPT_LEVEL
  ENCRYPT_LEVEL[0] = encrypt_string_L0
  ENCRYPT_LEVEL[1] = encrypt_string_L1
  
  #
  # DECRYPT
  #
  
  def decrypt_string(level, dstring, decrypt_key):
    global DECRYPT_LEVEL
    return DECRYPT_LEVEL[level] 
  
  def decrypt_string_L0(dstring, decrypt_key):
    decrypt_key = encdec_keylen(dstring, decrypt_key)
    out         = []
    dec         = base64.urlsafe_b64decode(dstring).decode()
    for i in range(len(dec)):
      k_c = decrypt_key[i % len(decrypt_key)]
      d_c = chr((256 + ord(dec[i]) - ord(k_c)) % 256)
      out.append(d_c)
    return ''.join(out)
  
  def decrypt_string_L1(dstring, decrypt_key):
    decrypt_key     = encdec_keylen(dstring, decrypt_key)
    str_dec         = base64.urlsafe_b64decode(dstring).decode()
    new_decrypt_key = get_hash(decrypt_key)
    dec_result_l2   = decrypt_string_L0(str_dec, new_decrypt_key)
    my_salt         = dec_result_l2[:8]
    dec_result_l1   = decrypt_string_L0(dec_result_l2[8:], my_salt + decrypt_key)
    return dec_result_l1
  
  global DECRYPT_LEVEL
  DECRYPT_LEVEL[0] = decrypt_string_L0
  DECRYPT_LEVEL[1] = decrypt_string_L1
  
  #
  #### END FUNCTION ENCRYPT AND DECTRYPT STRING

  #####
  #
  # FUNCTION DISPLAY MESSAGE
  
  def display_message(data, buffer, out_msg):
    global SCRIPT_NAME

    if isinstance(out_msg, list):
      for out_m in out_msg:
        weechat.prnt(buffer, '[%s]\t%s' % (SCRIPT_NAME, str(out_m)))
    else:
      weechat.prnt(buffer, '[%s]\t%s' % (SCRIPT_NAME, str(out_msg)))

    return weechat.WEECHAT_RC_OK
  
  #
  ##### END FUNCTION DISPLAY MESSAGE
  
  #####
  #
  # FUNCTION CHECK AND UPDATE
  
  #
  # UPDATE
  #
  
  def update(data, buffer):
    out_msg = ['--- WRECON UPDATE CHECK AND INSTALL ---']
    
    # CALL CHECK FOR NEW UPDATE
    upd_continue, upd_next_fnc, out_msg, latest_release, archive_file, download_url, extract_subdir = update_1_check(out_msg)
    
    # CALL PREPARE DIR
    if upd_continue == True:
      upd_continue, upd_next_fnc, out_msg, download_dir = upd_next_fnc(out_msg)
    
    # CALL DOWNLOAD FILE
    if upd_continue == True:
      upd_continue, upd_next_fnc, out_msg = upd_next_fnc(out_msg, download_dir, archive_file, download_url)
    
    # CALL EXTRACT ARCHIVE
    if upd_continue == True:
      upd_continue, upd_next_fnc, out_msg = upd_next_fnc(out_msg, download_dir, archive_file)
    
    # CALL VERIFY EXTRACTED FILE
    if upd_continue == True:
      upd_continue, upd_next_fnc, out_msg, install_file = upd_next_fnc(out_msg, extract_subdir)
    
    # CALL INSTALL NEW FILE
    if upd_continue == True:
      upd_continue, upd_next_fnc, out_msg = upd_next_fnc(out_msg, install_file)
    
    display_message(data, buffer, out_msg)  
    
    # AFTER SUCCESSFUL INSTALLATION WE CAN RESTART
    if upd_continue == True:
      global SCRIPT_FILE
      display_message(data, buffer, 'RESTARTING WRECON...')
      weechat.command(buffer, '/wait 3s /script reload %s' % SCRIPT_FILE)
    
    return update_result
    
  #
  # UPDATE - CHECK (new version in URL)
  #
  
  def update_1_check(out_msg):
    global SCRIPT_VERSION, SCRIPT_BASE_NAME
    import urllib.request
    
    update_me      = False
    next_function  = pass
    
    latest_release, archive_file, download_url, extract_subdir  = ['', '', '', '']

    actual_version = SCRIPT_VERSION.split(' ')[0]
    base_url       = 'https://github.com/%s/archive' % SCRIPT_BASE_NAME
    base_api       = 'https://api.github.com/repos/%s/releases/latest' % SCRIPT_BASE_NAME
    
    out_msg.append('ACTUAL VERSION  : %s' % actual_version)
    out_msg.append('REQUESTING URL  : %s' % base_api)
    
    error_get = False
    try:
      url_data = urllib.request.urlopen(base_api)
    except (urllib.error.HTTPError, urllib.error.URLerror, urllib.error.ContentTooShortError()) as e:
      error_get = True
      error_data = e.__dict__
    
    if error_get == True:
      out_msg.append('AN ERROR OCCURED DURING CHECK OF LATEST VERSION FROM GITHUB')
      if 'code' in error_data and 'msg' in error_data:
        out_msg.append('ERROR CODE    : %s' % error_data['code'])
        out_msg.append('ERROR MESSAGE : %s' % error_data['msg'])
      out_msg.append('ERROR DATA    : %s' % error_data)
    else:
      get_data       = json.loads(url_data.read().decode('utf8'))
      latest_release = get_data['tag_name'].split('v')[1]
      
      out_msg.append('LATEST RELEASE  : %s' % latest_release)
      
      if actual_version >= latest_release:
        out_msg.append('WRECON IS UP TO DATE')
      else:
        global SCRIPT_FILE
        update_me      = True
        next_function  = update_2_prepare_dir
        archive_file   = '%s.tar.gz' % latest_release
        download_url   = '%s/%s' % (base_url, archive_file)
        extract_subdir = '%s-%s' % (SCRIPT_FILE.split('.')[0], latest_release)
        
        out_msg.append('FOUND NEW RELEASE')        
        out_msg.append('DOWNLOAD URL    : %s' % download_url)

    return [update_me, next_function, out_msg, latest_release, archive_file, download_url, extract_subdir]
  
  #
  # UPDATE - PREPARE DOWNLOAD DIR
  #
  
  def update_2_prepare_dir(out_msg):
    env_vars           = os.environ
    download_dir       = '%s/%s' % (env_vars['HOME'], '.wrecon-update')
    
    dir_prepared       = False
    next_function      = pass
    
    out_msg.append('DOWNLOAD DIR    : %s' % download_dir)
    
    if not os.path.exists(os.path.join(download_dir)):
      try:
        os.mkdir(os.path.join(download_dir))
        dir_prepared  = True
      except OSError as e:
        out_msg.append('ERROR, DOWNLOAD DIRECTORY CAN NOT BE CREATED')
        out_msg.append('ERROR : %s' % e.__dict__)
    else:
      if not os.path_isdir(s.path.join(download_dir)):
        out_msg.append('ERROR, OBJECT EXIST, BUT IS NOT DIRECTORY')
      else:
        dir_prepared == True
    
    if dir_prepared == True:
      next_function = update_3_download
    
    return [dir_prepared, next_function, out_msg, download_dir]
  
  #
  # UPDATE - DOWNLOAD (new file from URL)
  # 
  
  def update_3_download(out_msg, download_dir, archive_file, download_url):
    import urllib.request
    
    download_prepared = False
    next_function     = pass
    
    download_file     = os.path.join(download_dir, archive_file)
    
    with urllib.request.urlopen(download_url) as response, open(download_file, 'wb') as out_file:
        shutil.copyfileobj(response, out_file)
      out_file.close()
      download_prepared = True
      download_result   = 'SUCCESSFUL'
    except (urllib.error.URLerror, urllib.error.ContentTooShortError()) as e:
      download_result = 'FAILED'
    
    download_result = 'DOWNLOAD STATUS : %' % download_result
    out_msg.append(download_result)
    
    if download_prepared == False:
      out_msg.append('ERROR : %s' % e.__dict__)
    else:
      next_function     = update_4_extract
    
    return [download_prepared, next_function, out_msg]
  
  #
  # UPDATE - EXTRACT ARCHIVE (from downloaded file)
  #
  
  def update_4_extract(out_msg, download_dir, archive_file):
    extract_prepared = False
    next_function    = pass
    
    os.chdir(download_dir)
    
    try:
      out_msg.append('EXTRACT FILE    : %' % archive_file)
      extract_file = tarfile.open(archive_file)
      for o_msg in extract_me.extractall():
        out_msg.append('EXTRACTING .... : %s' % o_msg)
      extract_prepared = True
      extract_result   = 'SUCCESSFUL'
    except (TarError, ReadError, CompressionError, StreamError, ExtractError, HeaderError) as e:
      extract_result = 'FAILED'
    
    out_msg.append('EXTRACT RESULT  : %' % extract_result)
    
    if extract_prepared == False:
      out_msg.append('ERROR : %s' % e.__dict__)
    else:
      next_function = update_5_verify_signature
    
    return [extract_prepared, next_function, out_msg]
  
  #
  # UPDATE - VERIFY FILE (SIGNATURE)
  #
  
  def update_5_verify_signature(out_msg, download_dir, extract_subdir):
    global SCRIPT_FILE, SCRIPT_FILE_SIG, PUBLIC_KEY
    
    verify_successful = False
    next_function     = pass
    
    verify_new_file   = os.path.join(download_dir, extract_subdir, SCRIPT_FILE)
    verify_signature  = os.path.join(download_dir, extract_subdir, SCRIPT_FILE_SIG)
    
    gpg        = gnupg.GPG()
    public_key = gpg.import_keys(PUBLIC_KEY)
    
    verification_msg = 'FAILED'
    
    try:
      with open(file_signature, 'rb') as sigfile:
        verify_me = gpg.verify_file(sigfile, '%s' % verify_new_file)
      sigfile.close()  
    finally:
      if verify_me:
        pk_content = public_key.__dict__
        vf_content = verify_me.__dict__
        fp_pk      = str(pk_content['results'][0]['fingerprint'])
        fp_vf      = str(vf_content['fingerprint'])
        if fp_pk == fp_vf:
          verification_msg  = 'SUCCESSFUL'
          verify_successful = True
          next_function     = update_6_install
    
    out_msg.append('VERIFICATION    : %s' % verification_msg)
    
    del gpg
    del public_key
    del pk_content
    del vf_content

    return [verify_successful, next_function, out_msg, verify_new_file]
  
  #
  # UPDATE - INSTALL NEW FILE
  #
  
  def update_6_install(out_msg, install_file):
    global SCRIPT_FILE
    
    installation_successful = False
    installation_message    = 'FAILED'
    
    destination_dir  = weechat.string_eval_path_home('%h', {}, {}, {})
    destination_dir  = str(os.path.join(destination_dir, 'python'))
    destination_file = str(os.path.join(destination_dir, SCRIPT_FILE))
    source_file      = str(os.path.join(install_file)
    
    try:
      copy_result = shutil.copyfile(source_file, destination_file, follow_symlinks=True)
      installation_successful = True
      installation_message    = 'SUCCESSFUL'
    except (OSError, shutil.SameFileError) as e:
      err_msg = e.__dict__
    
    out_msg.append('INSTALLATION    : %s' % installation_message)
    
    if installation_successful == False:
      out_msg.append('ERROR : %s' % err_msg)
    
    return [installation_successful, next_function, out_msg]
  
  #
  ##### END FUNCTION CHECK AND UPDATE
