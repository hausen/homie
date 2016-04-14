#!/usr/bin/python
import os, re, sqlite3, sys, subprocess, tempfile, threading

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

def get_known_hosts_file(host, ipaddr):
  dbfile = os.path.expanduser('~/.ssh/homie.db')
  if not os.path.isfile(dbfile):
    print >> sys.stderr, "%s does not exist!" % dbfile
    exit(1)
  conn=sqlite3.connect(dbfile)
  c = conn.cursor()
  c.execute('''SELECT k.value FROM key AS k, host AS h 
               WHERE h.alias = ? AND h.keyid = k.keyid''', (host, ))
  result = c.fetchone()
  if not result:
    print >> sys.stderr, "No key for host %s!" % host
    exit(1)
  keys = result[0].split('\n')
  key_file = tempfile.NamedTemporaryFile(suffix=".homie", mode='w')
  for key in keys:
    key_file.write(ipaddr + ' ' + key + '\n')
  key_file.flush()
  return key_file

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

  known_hosts_file = get_known_hosts_file(host, ipaddr)

  cmd = [ SSH, '-a', '-e', 'none', '-i', '/dev/null', '-x',
          '-oChallengeResponseAuthentication=no', '-oCheckHostIP=no',
          '-oClearAllForwardings=yes', '-oCompression=no', '-oControlMaster=no',
          '-oGSSAPIAuthentication=no', '-oHostbasedAuthentication=no',
          '-oIdentitiesOnly=yes', '-oKbdInteractiveAuthentication=yes',
          '-oPasswordAuthentication=yes',
          '-oPreferredAuthentications=keyboard-interactive,password',
          '-oPubkeyAuthentication=no', '-oRhostsRSAAuthentication=no',
          '-oRSAAuthentication=no', '-oStrictHostKeyChecking=yes',
          '-oTunnel=no', '-oUserKnownHostsFile=' + known_hosts_file.name,
          '-oVerifyHostKeyDNS=no', '-oLogLevel=FATAL',
          username + '@' + ipaddr ]

  os.execv(cmd[0], cmd)
except KeyboardInterrupt:
  exit(1)
