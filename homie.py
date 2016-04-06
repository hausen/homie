#!/usr/bin/python
import atexit, fcntl, os, re, select, socket, sqlite3, struct, subprocess, \
       sys, thread, time

SSH_KEYSCAN = '/usr/bin/ssh-keyscan'
IFCONFIG = '/sbin/ifconfig'
SSH_CONFIG_DIR = os.path.expanduser("~") + "/.ssh"
KNOWN_HOSTS_DIR = SSH_CONFIG_DIR
ALIAS_DB = SSH_CONFIG_DIR + '/homie.db'

def help(exit_error=True):
  print >> sys.stderr, """\
usage: homie.py <command> [<args>]

Avaliable commands:
  add <alias> <ip>[:<port>] <netmask> - add host bound to a network
  bind <alias> <ip>[:<port>] <netmask> - bind host to a network
  connect <alias> [<port>] - connects to a host
  daemonize - start proxy service (not implemented)
  exorcise - stop proxy service (not implemented)
  export <alias> - export host (try export localhost[:port])
  get <option> - get value for option (try help set)
  help - shows this help text
  import <alias> - import host not bound to a network
  remove <alias> - forget host
  set <option> <value> - set option (try help set)
  show [<alias>] - show host info
  unbind <alias> - unbind host from network
  unset <option> - unset option
"""
  if exit_error: exit(1)
  else: exit(0)

OPTIONS = {
  'interfaces' :
          ( """names of the interfaces to scan for hosts, separated by
               spaces (default: scan all interfaces)""", None )
}

def help_set():
  print >> sys.stderr, "Homie options:"
  for name, (helptext, default) in sorted(OPTIONS.iteritems()):
    sys.stderr.write('  ' + name + ' - ' + helptext)
    if default != None and len(str(default)) > 0:
      sys.stderr.write(" (default: %s)" % default)
    sys.stderr.write("\n")
  exit(0)

def help_command(cmd):
  if cmd == 'set' or cmd == 'get' or cmd == 'unset':
    help_set()
  else:
    print >> sys.stderr, "%s is not a valid command!\nrun homie.py help" % cmd

def ensure_dir_exists(dirpath):
  if not os.path.isdir(dirpath):
    try:
      os.mkdir(dirpath, 0700)
    except OSError as exception:
      print >> sys.stderr, "ERROR! Cannot create directory %s: %s" % \
                           (dirpath, exception.message)
      exit(1)

DBCONN_=None
def create_alias_db():
  c = DBCONN_.cursor()
  c.executescript('''
    CREATE TABLE host (
      hostid INTEGER PRIMARY KEY AUTOINCREMENT,
      keyid INTEGER NOT NULL,
      alias TEXT NOT NULL,
      network INTEGER,
      netmask INTEGER,
      port INTEGER NOT NULL,
      last_known_ip INTEGER,
      UNIQUE(alias),
      FOREIGN KEY(keyid) REFERENCES key(keyid)
    );
    CREATE TABLE key (
      keyid INTEGER PRIMARY KEY AUTOINCREMENT,
      value TEXT NOT NULL,
      UNIQUE(value)
    );
    CREATE TABLE option (
      name TEXT PRIMARY KEY,
      value TEXT
    );
  ''')

def dbdisconnect():
  global DBCONN_
  if DBCONN_:
    DBCONN_.commit()
    DBCONN_.close()
    DBCONN_ = None

def dbconn():
  global DBCONN_
  if not DBCONN_:
    ensure_dir_exists(SSH_CONFIG_DIR)
    if not os.path.isfile(ALIAS_DB):
      DBCONN_=sqlite3.connect(ALIAS_DB)
      create_alias_db()
    else:
      DBCONN_=sqlite3.connect(ALIAS_DB)
    atexit.register(dbdisconnect)
  return DBCONN_

def dbcommit():
# uncomment the following line to commit operations to the db immediately
# dbconn().commit()
  pass

def get_config(name):
  if not OPTIONS.get(name.lower()): raise Exception("Unknown option!")
  c = dbconn().cursor()
  c.execute("SELECT value FROM option WHERE name = ?", (name.lower(),))
  result = c.fetchone()
  if result:
    return result[0]
  else:
    return None

def set_config(name, value):
  if not OPTIONS.get(name.lower()): raise Exception("Unknown option!")
  c = dbconn().cursor()
  c.execute("UPDATE OR IGNORE option SET value = ? WHERE name = ?", \
                                         (value, name.lower()))
  c.execute("INSERT OR IGNORE INTO option(name, value) VALUES (?,?)", \
                                         (name.lower(), value))
  dbcommit()

def unset_config(name):
  if not OPTIONS.get(name.lower()): raise Exception("Unknown option!")
  c = dbconn().cursor()
  c.execute("DELETE FROM option WHERE name = ?", (name.lower(),))
  dbcommit()

def addrtoint(ipaddr):
  try:
    ipaddr = ipaddr.split(':')[0]
    return struct.unpack("!I", socket.inet_aton(ipaddr))[0]
  except:
    return None

def addrgetport(ipaddr):
  try:
    return int(ipaddr.split(':')[1])
  except:
    return 22

def inttoaddr(integer):
  try:
    return socket.inet_ntoa(struct.pack("!I", integer))
  except:
    return None

def netmaskbits(ipaddr):
  intaddr = addrtoint(ipaddr)
  if not intaddr:
    return -1
  bits = 0
  while intaddr % 2 == 0:
    bits += 1
    intaddr = intaddr >> 1
  while intaddr % 2 == 1:
    intaddr = intaddr >> 1
  if intaddr == 0:
    return bits
  else:
    return None

# 0x8915 = SIOCGIFADDR = get PA address (ioctls.h)
# 0x891b = SIOCGIFNETMASK = get network PA mask (ioctls.h)
def get_ip_netmask(ifname):
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  i = struct.pack('256s', str(ifname[:15])) # (IF_NAMESIZE in include/net/if.h)
  try:
    addr = socket.inet_ntoa(fcntl.ioctl(s, 0x8915, i)[20:24])
    netmask = socket.inet_ntoa(fcntl.ioctl(s, 0x891b, i)[20:24])
    return addr, netmask
  except IOError as e:
    raise IOError('Cannot open interface %s' % ifname)

def list_interfaces():
  p = subprocess.Popen([IFCONFIG], stdin=open(os.devnull, 'r'),
                       stdout=subprocess.PIPE,
                       stderr=open(os.devnull, 'w'))
  ifaces = [ line.split()[0]
             for line in p.stdout if re.match(r"^[^\s]+", line) ]
  p.wait()
  return ifaces

def ssh_keyscan_interface(ifname, port=None):
  ipaddr, netmask = get_ip_netmask(ifname)
  if (ipaddr == '127.0.0.1'): return []
  return ssh_keyscan(ipaddr, netmask, port)

def ssh_keyscan_interfaces(port=None):
  interfaces = get_config('interfaces')
  result = []
  if interfaces:
    for ifname in interfaces.split():
      result.extend(ssh_keyscan_interface(ifname, port))
  else:
    for ifname in list_interfaces():
      result.extend(ssh_keyscan_interface(ifname, port))
  return result
 
def ssh_keyscan(network, netmask='255.255.255.255', port=None):
  current_ip = addrtoint(network) & addrtoint(netmask)
  hosts_to_go = 2 ** netmaskbits(netmask)
  if hosts_to_go >= 2: hosts_to_go -= 1 # skip broadcast address
  if not port: port = addrgetport(network)
  p = subprocess.Popen([SSH_KEYSCAN, '-f', '-', '-p', str(port) ],
                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                       stderr=open(os.devnull, 'w'))
  while hosts_to_go > 0:
    p.stdin.write(inttoaddr(current_ip) + '\n')
    current_ip += 1
    hosts_to_go -= 1
  p.stdin.close()
  keys = [ line.split() for line in p.stdout ]
  p.wait()
  return keys

def flatten_keys(keys):
  keys = [ [key[-2], key[-1]] for key in keys ]
  keys.sort(key=lambda key: key[-2])
  return '\n'.join([ key[-2] + ' ' + key[-1] for key in keys ])

def group_keys_by_ip(keys):
  ips = set(map(lambda x: x[0], keys))
  grouped_keys = [[ [x[1],x[2]] for x in keys if x[0]==ip] for ip in ips ]
  result = {}
  i=0
  for ip in ips:
    result[ip] = flatten_keys(grouped_keys[i])
    i += 1
  return result

def group_keys_by_key(keys):
  ips = set(map(lambda x: x[0], keys))
  grouped_keys = [[ [x[1],x[2]] for x in keys if x[0]==ip] for ip in ips ]
  result = {}
  i=0
  for ip in ips:
    result[flatten_keys(grouped_keys[i])] = ip
    i += 1
  return result

def add_to_known_hosts(alias, ipaddr, keys):
  ensure_dir_exists(KNOWN_HOSTS_DIR)
  filename = KNOWN_HOSTS_DIR + '/known_hosts.homie'
  try:  
    fd = os.open(filename, os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_EXCL, 0600)
  except:
    fd = os.open(filename, os.O_WRONLY|os.O_APPEND|os.O_EXCL)
  if not isinstance(keys, list): keys = keys.split('\n')
  for key in keys:
    if not isinstance(key, list): key = key.split()
    os.write(fd, "%s.homie %s %s\n" % (alias, key[-2], key[-1]))
  os.close(fd)

def remove_from_known_hosts(alias):
  ensure_dir_exists(KNOWN_HOSTS_DIR)
  with open(KNOWN_HOSTS_DIR + '/known_hosts.homie', 'r+') as f:
    fcntl.lockf(f, fcntl.LOCK_EX)
    keys = [ line.split() for line in f.readlines() ]
    newkeys = [ ' '.join(key)
                for key in keys if key[0] != str(alias + '.homie') ]
    f.seek(0, 0)
    for key in newkeys:
      f.write(key)
      f.write("\n")
    f.truncate()
    f.close()

def get_keyid(keys, add_if_not_found=False):
  if isinstance(keys, list):
    keys = flatten_keys(keys)
  c = dbconn().cursor()
  c.execute("SELECT keyid FROM key WHERE value = ?", (keys,))
  row = c.fetchone()
  if not row:
    if add_if_not_found:
      c.execute("INSERT INTO key(value) VALUES (?)", (keys,))
      dbcommit()
      return c.lastrowid
    else:
      return -1
  else:
    return row[0]

def add_host(alias, ipaddr, netmask, keys=None, port=None):
  alias = sanitize_alias(alias)
  if alias == 'localhost': raise Exception("Cannot add localhost!")
  if ipaddr and netmask:
    intaddr, intmask = addrtoint(ipaddr), addrtoint(netmask)
    intnet = intaddr & intmask
    port = addrgetport(ipaddr)
    if not keys: keys = ssh_keyscan(ipaddr)
    if len(keys) == 0:
      raise Exception("Cannot add %s: host %s does not respond." % \
                      (alias, ipaddr))
  else:
    intnet, intmask, intaddr = None, None, None
    if not keys: raise Exception("Cannot add host %s without key!")
    if not port: port = 22
  keyid = get_keyid(keys, add_if_not_found=True)
  c = dbconn().cursor()
  c.execute("""INSERT INTO host(keyid, alias, network, netmask, port,
               last_known_ip) VALUES (?, ?, ?, ?, ?, ?)""", \
              (keyid, alias, intnet, intmask, port, intaddr) )
  dbcommit()
  add_to_known_hosts(alias, ipaddr, keys)

class Host:
  def __init__(self, **fields):
    self.__dict__.update(fields)

def get_host(alias, load_keys = True):
  c = dbconn().cursor()
  c.execute("""SELECT hostid, network, netmask, port, last_known_ip, keyid
               FROM host WHERE alias = ?""", (alias,) )
  data = c.fetchone()
  if not data: raise Exception("Unknown host!")
  network = None if not data[1] else inttoaddr(int(data[1]))
  netmask = None if not data[2] else inttoaddr(int(data[2]))
  last_known_ip = None if not data[4] else inttoaddr(int(data[4]))
  if not data: raise Exception("Unknown alias!")
  host = Host( alias = alias, hostid = int(data[0]), \
               network = network, \
               netmask = netmask, \
               port = int(data[3]), \
               last_known_ip = last_known_ip, \
               keyid = int(data[5]), \
               ipaddr = None, \
               keys = None )
  if load_keys: load_host_keys(host)
  return host

def load_host_keys(host):
  c = dbconn().cursor()
  c.execute('SELECT value FROM key WHERE keyid = ?', ( host.keyid, ) )
  host.keys = c.fetchone()[0]

def rescan_and_update_host_ipaddr(host):
  if host.network:
    keys = ssh_keyscan(host.network, host.netmask, host.port)
  else:
    keys = ssh_keyscan_interfaces(host.port)
  keys = group_keys_by_key(keys)
  ip = keys.get(host.keys)
  if not ip:
    raise Exception("Host not found!")
  host.ipaddr = ip
  host.last_known_ip = ip
  dbconn().cursor().execute("UPDATE host SET last_known_ip=? WHERE hostid=?",
                             (addrtoint(host.ipaddr), host.hostid) )
  dbcommit()

def update_host_ipaddr(host):
  host.ipaddr = None
  if not host.keys:
    raise Exception("No keys for alias %s! (this should never happen!)" % \
                    aliasobj.alias)
  if host.last_known_ip:
    keys = flatten_keys(ssh_keyscan(host.last_known_ip, port=host.port))
  else:
    keys = None
  if keys == host.keys:
    host.ipaddr = host.last_known_ip
  else:
    rescan_and_update_host_ipaddr(host)

def list_host(alias, show_keys=False):
  host = get_host(alias)
  print "alias: %s" % host.alias
  print "last known IP addr.: %s" % host.last_known_ip
  if host.port != 22: print "port: %d" % host.port
  if host.network:
    print "network: %s" % host.network
    print "netmask: %s" % host.netmask
  if show_keys:
    for key in host.keys.split('\n'):
      print "key: %s" % key

def export_host(alias, stream=sys.stdout):
  if alias.lower().split(':')[0] == 'localhost' \
    or alias.lower().split(':')[0] == 'localhost.homie':
    if alias.find(':') > -1:
      port = int(alias.split(':')[1])
      export_localhost(stream, port=port)
    else:
      export_localhost(stream)
    return

  alias = sanitize_alias(alias)
  host = get_host(alias)
  print >> stream, "# %s" % host.alias
  if host.last_known_ip:
    print >> stream, "#@last_known_ip %s" % host.last_known_ip
  if host.network:
    print >> stream, "#@network %s" % host.network
    print >> stream, "#@netmask %s" % host.netmask
  if host.port != 22:
    print >> stream, "#@port %s" % host.port
  print >> stream, "%s.homie %s" % ( host.alias,
                   (host.alias+'.homie ').join(host.keys.split('\n')) )

def export_localhost(alias, stream=sys.stdout, port=22):
  keys = ssh_keyscan('127.0.0.1',port=port)
  if not keys:
    raise Exception('No ssh server running on localhost:%d' % port)
  alias = socket.gethostname()
  print >> stream, "# %s" % alias
  if port != 22:
    print >> stream, "#@port %s" % port
  for key in keys:
    print >> stream, "%s.homie %s %s" % (alias, key[-2], key[-1])

def import_host(alias, stream=sys.stdin):
  alias = sanitize_alias(alias)
  if alias == 'localhost': raise Exception("Cannot add localhost!")
  try:
    keys = []
    last_known_ip, network, netmask, port = None, None, None, None
    for line in stream.readlines():
      line = line.strip()
      if line == '':
        continue
      if line.startswith("#@"):
        (varname, value) = line[2:].split()
        if   varname == 'last_known_ip': last_known_ip = value
        elif varname == 'network':       network = value
        elif varname == 'netmask':       netmask = value
        elif varname == 'port':          port = int(value)
      elif not line.startswith("#"):
        keys.append(line.split())
    keys = flatten_keys(keys)
  except:
    raise Exception("Malformed data on import!")
  add_host(alias, ipaddr=None, netmask=None, keys=keys, port=port)

def list_all_hosts(show_keys=False):
  c = dbconn().cursor()
  c.execute("SELECT alias FROM host ORDER BY alias")
  numaliases = 0
  for alias in c.fetchall():
    numaliases += 1
    alias = alias[0]
    list_host(alias, show_keys)
    print ""
  if numaliases == 0:
    print >> sys.stderr, "No hosts known!"

def unbind_host(alias):
  alias = sanitize_alias(alias)
  c = dbconn().cursor()
  c.execute('UPDATE host SET network = NULL, netmask = NULL WHERE alias = ?', \
            (alias, ) )
  if c.rowcount == 0:
    raise Exception("Uknown alias!")
  dbcommit()

def bind_host(alias, ipaddr, netmask):
  alias = sanitize_alias(alias)
  intaddr, intmask = addrtoint(ipaddr), addrtoint(netmask)
  intnet = intaddr & intmask
  port = addrgetport(ipaddr)
  c = dbconn().cursor()
  c.execute('''UPDATE host SET network = ?, netmask = ?, port = ?
               WHERE alias = ?''', (intnet, intmask, port, alias) )
  if c.rowcount == 0:
    raise Exception("Uknown alias!")
  dbcommit()

def remove_host(alias):
  alias = sanitize_alias(alias)
  remove_from_known_hosts(alias)
  host = get_host(alias)
  c = dbconn().cursor()
  c.execute('DELETE FROM host WHERE hostid = ?', (host.hostid,) )
  c.execute('''DELETE FROM key
               WHERE NOT EXISTS
                 ( SELECT * FROM host WHERE host.keyid = key.keyid )''')
  dbcommit()

def connect(alias, port=None):
  alias = sanitize_alias(alias)
  addr = None
  if alias == 'localhost':
    addr = '127.0.0.1'
    if not port:
      port = 22
  else:
    show_waiting_message('Locating host %s' % alias)
    host = get_host(alias)
    update_host_ipaddr(host)
    stop_waiting_message('found.')
    addr = host.ipaddr
    if not port:
      port = host.port
  dbdisconnect()
  proxify(addr, port)

def proxify(addr, port):
  BUFSIZE=4096
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((addr, port))
  while True:
    try:
      read_ready, write_ready, in_error = \
                  select.select( [sys.stdin, s], [], [sys.stdin, s] )
    except KeyboardInterrupt:
      exit(0)
    if s in in_error or sys.stdin in in_error:
      exit(1)
    if s in read_ready:
      data = s.recv(BUFSIZE)
      if len(data) == 0:
        exit(0)
      sys.stdout.write(data)
      sys.stdout.flush()
    if sys.stdin in read_ready:
      data = os.read(sys.stdin.fileno(), BUFSIZE)
      if len(data) == 0:
        exit(0)
      s.send(data)   

def proxify_with_netcat(addr, port):
  NETCAT = '/bin/netcat'
  cmd = [ NETCAT, addr, str(port) ]
  os.execv(cmd[0], cmd)

def is_valid_alias(alias):
  if re.match(r"^[a-z][-a-z0-9]{2,254}$", alias, re.IGNORECASE):
    return True
  else:
    return False

def sanitize_alias(alias):
  alias = alias.lower()
  if alias.endswith('.homie'): alias = alias[:-len('.homie')]
  if alias == 'homie' or not is_valid_alias(alias):
    raise Exception("Invalid alias name!")
  return alias

SHOWING_WAITING_MESSAGE=False
SHOWED_WAITING_MESSAGE=False
STOP_WAITING_MESSAGE=''
def wait_message_thread(message):
  global SHOWING_WAITING_MESSAGE
  global SHOWED_WAITING_MESSAGE
  time.sleep(1)
  if SHOWING_WAITING_MESSAGE:
    sys.stderr.write(message)
    SHOWED_WAITING_MESSAGE=True
    while SHOWING_WAITING_MESSAGE:
      sys.stderr.write('.')
      time.sleep(1)

def show_waiting_message(message='Please wait'):
  global SHOWING_WAITING_MESSAGE
  global SHOWED_WAITING_MESSAGE
  SHOWING_WAITING_MESSAGE=True
  SHOWED_WAITING_MESSAGE=False
  thread.start_new_thread(wait_message_thread, (message,))

def stop_waiting_message(message=''):
  global SHOWING_WAITING_MESSAGE
  STOP_WAITING_MESSAGE=message
  SHOWING_WAITING_MESSAGE=False
  if SHOWED_WAITING_MESSAGE:
    sys.stderr.write(STOP_WAITING_MESSAGE)
    sys.stderr.write("\n")

#None and '''
#
# MAIN
#

if len(sys.argv) < 2:
  help()

cmd = sys.argv[1].lower()
try:
  if cmd == 'add' and len(sys.argv) == 5:
    add_host(alias=sys.argv[2], ipaddr=sys.argv[3], netmask=sys.argv[4])
    print >> sys.stderr, "Added host %s" % sys.argv[2]
  elif cmd == 'bind' and len(sys.argv) == 5:
    bind_host(alias=sys.argv[2], ipaddr=sys.argv[3], netmask=sys.argv[4])
  elif cmd == 'connect' and len(sys.argv) == 3:
    connect(sys.argv[2])
  elif cmd == 'connect' and len(sys.argv) == 4:
    connect(sys.argv[2], int(sys.argv[3]))
  elif cmd == 'daemonize' and len(sys.argv) == 2:
    print >> sys.stderr, "Not implemented!"; exit(1)
  elif (cmd == 'exorcise' or cmd == 'exorcize') and len(sys.argv) == 2:
    print >> sys.stderr, "Vade retro satana!"; exit(1)
  elif cmd == 'export' and len(sys.argv) == 3:
    export_host(sys.argv[2])
  elif cmd == 'get' and len(sys.argv) == 3:
    value = get_config(sys.argv[2])
    print value if value else "(not set)"
  elif cmd == 'help' and len(sys.argv) == 2:
    help(exit_error=False)
  elif cmd == 'help' and len(sys.argv) == 3:
    help_command(sys.argv[2].lower())
  elif cmd == 'import' and len(sys.argv) == 3:
    import_host(sys.argv[2])
  elif cmd == 'remove' and len(sys.argv) == 3:
    remove_host(alias=sys.argv[2])
  elif cmd == 'set' and len(sys.argv) == 4:
    set_config(sys.argv[2], sys.argv[3])
  elif cmd == 'show' and len(sys.argv) == 2:
    list_all_hosts()
  elif cmd == 'show' and len(sys.argv) == 3:
    list_host(sanitize_alias(sys.argv[2]))
  elif cmd == 'unbind' and len(sys.argv) == 3:
    unbind_host(alias=sys.argv[2])
  elif cmd == 'unset' and len(sys.argv) == 3:
    unset_config(sys.argv[2])
  else:
    help()
except Exception as e:
  print >> sys.stderr, e.message
#  import traceback
#  traceback.print_exc()
  exit(1)
#'''
