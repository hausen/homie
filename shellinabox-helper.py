#!/usr/bin/python
import os, re, sys, subprocess, threading

HOMIE='/opt/homie/homie.py'
SSH='/usr/bin/ssh'

def is_valid_username(username):
  return bool(re.match(r'^[a-zA-Z0-9][-a-zA-Z0-9_.]*$', username))

def timeout():
  print "Timeout on user input!"
  os._exit(1)

def read_username(hostname):
  tries = 3
  while tries:
    t = threading.Timer(60.0, timeout)
    t.start()
    username = raw_input('%s login: ' % host)[:128]
    t.cancel()
    if is_valid_username(username):
      return username
    print "Invalid username!"
    tries -= 1
  exit(1)

if len(sys.argv) != 2:
  print >> sys.stderr, "Usage: shellinabox-helper.py hostname"
  exit(1)

class FindIpAddrThread(threading.Thread):
  def __init__(self, hostname):
    threading.Thread.__init__(self)
    self.hostname = hostname
  def run(self):
    global ipaddr
    p = subprocess.Popen([ HOMIE , 'ipaddr', host ],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=open('/dev/null', 'w'))
    p.stdin.close()
    ipaddr = p.stdout.readline().strip()
    p.wait()
    if not ipaddr:
      print 'Host not found!'
      os._exit(1)

try:
  ipaddr = None
  host = sys.argv[1]
  ipfinder = FindIpAddrThread(host)
  ipfinder.start()

  username = read_username(host)

  ipfinder.join()

  cmd = [ SSH, '-a', '-e', 'none', '-i', '/dev/null', '-x',
          '-oChallengeResponseAuthentication=no', '-oCheckHostIP=no',
          '-oClearAllForwardings=yes', '-oCompression=no', '-oControlMaster=no',
          '-oGSSAPIAuthentication=no', '-oHostbasedAuthentication=no',
          '-oIdentitiesOnly=yes', '-oKbdInteractiveAuthentication=yes',
          '-oPasswordAuthentication=yes',
          '-oPreferredAuthentications=keyboard-interactive,password',
          '-oPubkeyAuthentication=no', '-oRhostsRSAAuthentication=no',
          '-oRSAAuthentication=no', '-oStrictHostKeyChecking=no', '-oTunnel=no',
          '-oUserKnownHostsFile=/dev/null',
          '-oVerifyHostKeyDNS=no', '-oLogLevel=QUIET',
          username + '@' + ipaddr ]

  os.execv(cmd[0], cmd)
except KeyboardInterrupt:
  exit(1)
