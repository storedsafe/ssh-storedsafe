#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ssssh.py: Initiate a SSH session to a remote host. Obtain credentials from StoredSafe.
"""

import sys
import os
import os.path
import sys
import socket
import getopt
import re
import base64
import getpass
import traceback
import requests
import json
import paramiko
from paramiko.py3compat import u
# windows does not have termios...
try:
    import termios
    import tty
    has_termios = True
except ImportError:
    has_termios = False

__author__     = "Fredrik Soderblom"
__copyright__  = "Copyright 2020, AB StoredSafe"
__license__    = "GPL"
__version__    = "1.0.2"
__maintainer__ = "Fredrik Soderblom"
__email__      = "fredrik@storedsafe.com"
__status__     = "Production"

# Globals

url              = False
token            = False
verbose          = False
debug            = False

def main():
  global token, url, verbose, debug

  port = 22
  user = apikey = token = supplied_token = storedsafe = target = ''
  rc_file = os.path.expanduser('~/.storedsafe-client.rc')

  try:
    opts, args = getopt.getopt(sys.argv[1:], "s:u:a:t:vd?", \
      [ "verbose", "debug", "storedsafe=", "token=", "user=", "apikey=", "rc=", "help" ])

  except getopt.GetoptError as err:
    print("%s" % str(err))
    usage()
    sys.exit()

  if opts:
    for opt, arg in opts:
      if opt in ("--verbose"):
        verbose = True
      elif opt in ("--debug"):
        debug = True
        verbose = True
      elif opt in ("-s", "--storedsafe"):
        storedsafe = arg
      elif opt in ("-u", "--user"):
        user = arg
      elif opt in ("-a", "--apikey"):
        if len(str(arg)) == 10:
          apikey = arg
        else:
          print("Invalid API key.")
          sys.exit()
      elif opt in ("-t", "--token"):
        if len(str(arg)) == 42:
          supplied_token = arg
        else:
          print("Invalid token.")
          sys.exit()
      elif opt in ("--rc"):
        rc_file = arg
      elif opt in ("-?", "--help"):
        usage()
        sys.exit()
      else:
        assert False, "Unrecognized option"

  for arg in args:
    if '@' in arg:
      target = arg

  if supplied_token:
    token = supplied_token

  if not token:
    if user and apikey:
      if not storedsafe:
        print("ERROR: You need to specify a StoredSafe server. (--storedsafe)")
        sys.exit()
      url = "https://" + storedsafe + "/api/1.0"
      pp = passphrase(user)
      otp = OTP(user)
      token = login(user, pp + apikey + otp)
    elif rc_file:
      (storedsafe, token) = readrc(rc_file)
  url = "https://" + storedsafe + "/api/1.0"
  
  if not authCheck():
    sys.exit()

  if not target:
    print("ERROR: You need to specify a destination. (user@host.cc)")
    sys.exit()

  (user, server) = target.split('@')
  if server.find(':') >= 0:
    (server, portstr) = server.split(':')
    port = int(portstr)

  password = searchForCredentials(user, server)
  spawnShell(user, password, server, port)
  sys.exit()

def usage():
  print("Usage: %s [-vdsuat] user@host.domain.cc[:port]" % sys.argv[0])
  print(" --verbose (or -v)              (Boolean) Enable verbose output.")
  print(" --debug (or -d)                (Boolean) Enable debug output.")
  print(" --rc <rc file>                 Use this file to obtain a valid token and a server address.")
  print(" --storedsafe (or -s) <Server>  Use this StoredSafe server.")
  print(" --user (or -u) <user>          Authenticate as this user to the StoredSafe server.")
  print(" --apikey (or -a) <API Key>     Use this unique API key when communicating with the StoredSafe server.")
  print(" --token (or -t) <Auth Token>   Use pre-authenticated token instead of --user and --apikey.")
  print("\nObtain password for the user from StoredSafe and connect on port 1234:")
  print("$ %s user@server.domain.cc:1234" % sys.argv[0])

def readrc(rc_file):
  if os.path.isfile(rc_file):
    f = open(rc_file, 'r')
    for line in f:
      if "token" in line:
        token = re.sub('token:([a-zA-Z0-9]+)\n$', r'\1', line)
        if token == 'none':
          print("ERROR: No valid token found in \"%s\". Have you logged in?" % rc_file)
          sys.exit()
      if "mysite" in line:
        server = re.sub('mysite:([a-zA-Z0-9.]+)\n$', r'\1', line)
        if server == 'none':
          print("ERROR: No valid server specified in \"%s\". Have you logged in?" % rc_file)
          sys.exit()
    f.close()
    if not token:
      print("ERROR: Could not find a valid token in \"%s\"" % rc_file)
      sys.exit()
    if not server:
      print("ERROR: Could not find a valid server in \"%s\"" % rc_file)
      sys.exit()
    return (server, token)
  else:
    print("ERROR: Can not open \"%s\"." % rc_file)
    sys.exit()

def passphrase(user):
  p = getpass.getpass('Enter ' + user + '\'s passphrase: ')
  return(p)

def OTP(user):
  otp = getpass.getpass('Press ' + user + '\'s Yubikey: ')
  return(otp)

def login(user, key):
  global url

  payload = { 'username': user, 'keys': key }
  try:
    r = requests.post(url + '/auth', data=json.dumps(payload))
  except:
    print("ERROR: No connection to \"%s\"" % url)
    sys.exit()

  if not r.ok:
    print("ERROR: Failed to login.")
    sys.exit()

  data = json.loads(r.content)
  return data['CALLINFO']['token']

def authCheck():
  global token, url, verbose, debug

  payload = { 'token': token }
  try:
    r = requests.post(url + '/auth/check', data=json.dumps(payload))
  except:
    print("ERROR: Can not reach \"%s\"" % url)
    sys.exit()

  if not r.ok:
    print("Not logged in to StoredSafe.")
    sys.exit()

  data = json.loads(r.content)
  if data['CALLINFO']['status'] == 'SUCCESS':
    if debug: print("DEBUG: Authenticated using token \"%s\"." % token)
  else:
    print("ERROR: Session not authenticated with server. Token invalid?")
    return(False)

  return(True)

def searchForCredentials(user, server):
  password = False
  payload = { 'token': token, 'needle': server }
  r = requests.get(url + '/find', params=payload)
  data = json.loads(r.content)
  if not r.ok:
    return(False)

  if (len(data['OBJECT'])): # Unless result is empty
    for object in data['OBJECT']:
      if server == object['public']['host']:
        if user == object['public']['username']:
          if verbose: print("Found credentials for \"%s@%s\" (Object-ID %s in Vault-ID %s)" % (user, server, object['id'], object['groupid']))
        password = getPassword(object['id'])

  if password:
    return(password)
  else:
    print("ERROR: Could not find credentials in StoredSafe.")
    sys.exit()

def getPassword(id):
  payload = { 'token': token, 'decrypt': 'true' }
  r = requests.get(url + '/object/' + id, params=payload)
  data = json.loads(r.content)
  if not r.ok:
    return(False)

  try:
    if (len(data['OBJECT'][0]['crypted']['password'])):
      return(data['OBJECT'][0]['crypted']['password'])
  except:
    sys.stderr.write("WARNING: Could not find any credentials in Object-ID \"%s\".\n" % id)
    return(False)

def spawnShell(user, password, server, port):
  global debug, verbose

# if debug: paramiko.util.log_to_file(os.path.expanduser('~/.ssssh.log'))
  if debug: paramiko.common.logging.basicConfig(level=paramiko.common.DEBUG)

  try:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    if verbose: print("Connecting to \"%s\" on port %s" % (server, port))

    try:
      client.connect(server, port, user, password)
    except paramiko.ssh_exception.AuthenticationException:
      print("Invalid credentials. Username or password incorrect.")
      client.close()
      sys.exit()
    except paramiko.ssh_exception.BadHostKeyException:
      print("Rejecting bad host key.")
      client.close()
      sys.exit()
    except paramiko.ssh_exception.SSHException:
      t = client.get_transport()
      key = t.get_remote_server_key()
      # https://www.adampalmer.me/iodigitalsec/2014/11/24/ssh-fingerprint-and-hostkey-with-paramiko-in-python/
      key_type = key.get_name()
      key_ascii = base64.encodestring(key.__str__()).replace('\n', '')
      if verbose: print("[%s]:%s %s %s" % (server, port, key_type, key_ascii))
      print("Rejecting unknown host key for %s. (%s)" % (server, key_type))
      client.close()
      sys.exit()
    except socket.error: 
      print("Can not connect to %s on port %s." % (server, port))
      client.close()
      sys.exit()
    except Exception as e:
      print("ERROR: Caught exception: %s: %s" % (e.__class__, e))
      client.close()
      sys.exit()
    c = client.invoke_shell()
    if debug: print(repr(client.get_transport()))
    interactive_shell(c)
    c.close()
    client.close()
  except Exception as e:
    print("ERROR: Caught exception: %s: %s" % (e.__class__, e))
#   traceback.print_exc()
    try:
      client.close()
    except:
      pass
    sys.exit()

'''
Thanks to paramiko for this code from demos/interactive.py
Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
'''

def interactive_shell(chan):
  if has_termios:
      posix_shell(chan)
  else:
      windows_shell(chan)

def posix_shell(chan):
  import select
  
  oldtty = termios.tcgetattr(sys.stdin)
  try:
    tty.setraw(sys.stdin.fileno())
    tty.setcbreak(sys.stdin.fileno())
    chan.settimeout(0.0)

    while True:
      r, w, e = select.select([chan, sys.stdin], [], [])
      if chan in r:
        try:
          x = u(chan.recv(1024))
          if len(x) == 0:
#             sys.stdout.write('\r\n*** EOF\r\n')
              break
          sys.stdout.write(x)
          sys.stdout.flush()
        except socket.timeout:
          pass
      if sys.stdin in r:
        x = sys.stdin.read(1)
        if len(x) == 0:
          break
        chan.send(x)
  finally:
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)

# thanks to Mike Looijmans for this code
def windows_shell(chan):
  import threading

  sys.stdout.write("Line-buffered terminal emulation. Press F6 or ^Z to send EOF.\r\n\r\n")
      
  def writeall(sock):
    while True:
      data = sock.recv(256)
      if not data:
#       sys.stdout.write('\r\n*** EOF ***\r\n\r\n')
        sys.stdout.flush()
        break
      sys.stdout.write(data)
      sys.stdout.flush()
      
  writer = threading.Thread(target=writeall, args=(chan,))
  writer.start()
      
  try:
    while True:
      d = sys.stdin.read(1)
      if not d:
        break
      chan.send(d)
  except EOFError:
    # user hit ^Z or F6
    pass

if __name__ == '__main__':
  main()
