# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import '__go__/net'
import '__go__/syscall'
from '__go__/syscall' import (
    AF_INET,
    AF_INET6,
    AF_UNIX,
    AF_UNSPEC,
    IPPROTO_TCP,
    IPPROTO_UDP,
    SHUT_RD,
    SHUT_RDWR,
    SHUT_WR,
    SO_ERROR,
    SO_REUSEADDR,
    SOL_SOCKET,
    SOCK_DGRAM,
    SOCK_RAW,
    SOCK_RDM,
    SOCK_SEQPACKET,
    SOCK_STREAM)
import math
import select_ as select
import time


AI_CANONNAME = 2
AI_NUMERICHOST = 4


#TIPC_*
#has_ipv6  # boolean value indicating if IPv6 is supported
# UNIX
#SO_*
#SOMAXCONN
#MSG_*
#SOL_*
#IPPROTO_*
#IPPORT_*
#INADDR_*
#IP_*
#IPV6_*
#EAI_*
#AI_*
#NI_*
#TCP_*
# Windows
#SIO_*
#RCVALL_*

#SHUT_RD
#SHUT_WR
#SHUT_RDWR


_defaulttimeout = None


class error(IOError):
  pass


class gaierror(error):
  pass


class herror(error):
  pass


class timeout(error):
  pass


class socket(object):

  def __init__(self, family=AF_INET, type=SOCK_STREAM, proto=0, fd=None):
    if fd is None:
      fd, err = syscall.Socket(family, type, proto)
      if err:
        raise error(err.Error())
    self._fd = fd
    self.family = family
    self.type = type
    self.proto = proto
    self._timeout = _defaulttimeout
    if self._timeout is not None:
      self._setblocking(False)

  def accept(self):
    fd, sockaddr = self._timed_call(False, syscall.Accept, self._fd)
    return (socket(self.family, self.type, self.proto, fd),
            self._get_address(sockaddr))

  def bind(self, address):
    sockaddr = self._parse_address(address)
    self._syscall_invoke(syscall.Bind, self._fd, sockaddr)

  def close(self):
    if self._fd != -1:
      self._syscall_invoke(syscall.Close, self._fd)
      self._fd = -1

  def connect(self, address):
    self.connect_ex(address)

  def connect_ex(self, address):
    sockaddr = self._parse_address(address)
    err = syscall.Connect(self._fd, sockaddr)
    if not err:
      return
    if not self._timeout or err != syscall.EINPROGRESS:
      raise error(err.Error())
    def check_conn():
      err = syscall.Errno(self.getsockopt(SOL_SOCKET, SO_ERROR))
      if err and err != syscall.EISCONN:
        raise error(err.Error())
    self._timed_call(True, check_conn)

  def fileno(self):
    return self._fd

  def listen(self, backlog):
    self._syscall_invoke(syscall.Listen, self._fd, backlog)

  def getpeername(self):
    sockaddr = self._syscall_invoke(syscall.Getpeername, self._fd)
    return self._get_address(sockaddr)

  def getsockname(self):
    sockaddr = self._syscall_invoke(syscall.Getsockname, self._fd)
    return self._get_address(sockaddr)

  def getsockopt(self, level, optname, buflen=None):
    return self._syscall_invoke(syscall.GetsockoptInt, self._fd, level, optname)

  def recv(self, bufsize, flags=0):
    buffer = bytearray(bufsize)
    n = self.recv_into(buffer, bufsize, flags)
    return str(buffer[:n])

  def recv_into(self, buffer, nbytes=0, flags=0):
    if flags:
      raise NotImplementedError
    n = self._timed_call(False, syscall.Read, self._fd, buffer)
    return n

  def recvfrom(self, bufsize, flags=0):
    buffer = bytearray(bufsize)
    n, addr = self.recvfrom_into(buffer, bufsize, flags)
    return str(buffer[:n]), addr

  def recvfrom_into(self, buffer, nbytes=0, flags=0):
    n, _ = self._timed_call(False, syscall.Recvfrom, self._fd, buffer, flags)
    return n, None

  def setsockopt(self, level, optname, value):
    self._syscall_invoke(syscall.SetsockoptInt, self._fd, level, optname, value)

  def send(self, string, flags=0):
    sockaddr = self._syscall_invoke(syscall.Getsockname, self._fd)
    self._timed_call(True, syscall.Sendto, self._fd, string, flags, sockaddr)
    return len(string)

  def sendto(self, string, flags_or_address, address=None):
    if not address:
      address = flags_or_address
      flags = 0
    else:
      flags = flags_or_address
    sockaddr = self._parse_address(address)
    self._timed_call(True, syscall.Sendto, self._fd, string, flags, sockaddr)
    return len(string)

  def sendall(self, string, flags=0):
    return self.send(string, flags)

  def setblocking(self, block):
    self._timeout = None if block else 0.0
    self._setblocking(block)

  def settimeout(self, value):
    if value is None or value >= 0:
      self._timeout = value
      self._setblocking(value is None)
    else:
      raise ValueError('Timeout value out of range')

  def gettimeout(self):
    return self._timeout

  def shutdown(self, how):
    self._syscall_invoke(syscall.Shutdown, self._fd, how)

  def _parse_address(self, address):
    if self.family == AF_UNIX:
      sockaddr = syscall.SockaddrUnix.new()
      sockaddr.Name, = address
      return sockaddr
    host, port = address
    if port < 0 or port > 65535:
      raise OverflowError
    if not host:
      host = '127.0.0.1'
    ip = net.ParseIP(host)
    if ip:
      ips = [ip]
    else:
      ips, err = net.LookupIP(host)
      if err:
        raise error(err.Error())
    if self.family == AF_INET:
      convert = net.IP.To4
    else:
      convert = net.IP.To6
    for ip in ips:
      ip = convert(ip)
      if ip:
        break
    else:
      raise error('cannot resolve address')
    if self.family == AF_INET:
      sockaddr = syscall.SockaddrInet4.new()
    else:
      sockaddr = syscall.SockaddrInet6.new()
    sockaddr.Port = port
    sockaddr.Addr[:] = ip
    return sockaddr

  def _get_address(self, sockaddr):
    if isinstance(sockaddr, type(syscall.SockaddrUnix.new())):
      return (sockaddr.Name,)
    return net.IPv4(*sockaddr.Addr).String(), sockaddr.Port

  def _timed_call(self, for_write, func, *args):
    t = self._timeout
    if t == 0:
      return self._syscall_invoke(func, *args)
    fds = [self._fd]
    if t is not None:
      deadline = time.time() + t
    while True:
      if for_write:
        _, ready, _ = select.select([], fds, [], t)
      else:
        ready, _, _ = select.select(fds, [], [], t)
      if not ready:
        raise timeout
      try:
        return self._syscall_invoke(func, *args)
      except OSError as e:
        if t is None or e.errno not in (syscall.EWOULDBLOCK, syscall.EAGAIN):
          raise
      t = deadline - time.time()
      if t <= 0:
        raise timeout

  def _syscall_invoke(self, func, *args):
    result = func(*args)
    if isinstance(result, tuple):
      err = result[-1]
      if len(result) == 2:
        result = result[0]
      else:
        result = result[:-1]
    else:
      err = result
      result = None
    if err:
      raise error(err)
    return result

  def _setblocking(self, block):
    self._syscall_invoke(syscall.SetNonblock, self._fd, not block)


def fromfd(fd, family, type, proto=None):
  return socket(family, type, proto, fd)


def gethostbyname(hostname):
  raise NotImplementedError


def gethostbyaddr(ipaddr):
  names, err = net.LookupAddr(ipaddr)
  if err:
    return error(err)
  return names[0], [], [ipaddr]


def gethostname():
  raise NotImplementedError


def getprotobyname(proto):
  raise NotImplementedError


# --> port number
def getservbyname(servicename, protocolname=None):
  raise NotImplementedError


def getservbyport(portnumber, protocolname=None):
  raise NotImplementedError


def socketpair(family=None, type=None, proto=None):
  raise NotImplementedError


def ntohs(n):
  raise NotImplementedError


def ntohl(n):
  raise NotImplementedError


def htons(n):
  raise NotImplementedError


def htonl(n):
  raise NotImplementedError


_family_map = {
    0: ('', [AF_INET, AF_INET6]),
    AF_UNSPEC: ('', [AF_INET, AF_INET6]),
    AF_INET: ('4', [AF_INET]),
    AF_INET6: ('6', [AF_INET6]),
}

_proto_map = {
    (0, 0): ('tcp', [(SOCK_DGRAM, IPPROTO_UDP), (SOCK_STREAM, IPPROTO_TCP)]),
    (0, IPPROTO_TCP): ('tcp', [(SOCK_STREAM, IPPROTO_TCP)]),
    (SOCK_STREAM, 0): ('tcp', [(SOCK_STREAM, IPPROTO_TCP)]),
    (SOCK_STREAM, IPPROTO_TCP): ('tcp', [(SOCK_STREAM, IPPROTO_TCP)]),
    (0, IPPROTO_UDP): ('udp', [(SOCK_DGRAM, IPPROTO_UDP)]),
    (SOCK_DGRAM, 0): ('udp', [(SOCK_DGRAM, IPPROTO_UDP)]),
    (SOCK_DGRAM, IPPROTO_UDP): ('udp', [(SOCK_DGRAM, IPPROTO_UDP)]),
}

# --> List of (family, socktype, proto, canonname, sockaddr)
def getaddrinfo(host, port, family=0, socktype=0, proto=0, flags=0):
  if family not in _family_map:
    raise error('invalid family')
  family_str, families = _family_map[family]
  if (socktype, proto) not in _proto_map:
    raise error('invalid socktype/proto combination')
  proto_str, proto_pairs = _proto_map[(socktype, proto)]

  if not port:
    port = 0
  elif isinstance(port, str):
    port, err = net.LookupPort(proto_str + family_str, port)
    if err:
      raise error(err.Error())
  elif not isinstance(port, (int, long)):
    raise error('getaddrinfo() argument 2 must be integer or string got %r')

  cname = ''
  if not host:
    host = ''
  ip = net.ParseIP(host)
  if ip:
    ips = [ip]
  elif not flags & AI_NUMERICHOST:
    ips, err = net.LookupIP(host)
    if err:
      raise error(err.Error())
    if flags & AI_CANONNAME:
      cname, err = net.LookupCNAME(host)
      if err:
        raise error(err.Error())
  else:
    raise error('expected numeric host')

  results = []
  for family in families:
    for socktype, proto in proto_pairs:
      for ip in ips:
        ip_str = ip.String()
        sockaddr = None
        if family == AF_INET and '.' in ip_str:
          sockaddr = (ip_str, port)
        elif family == AF_INET6 and ':' in ip_str:
          sockaddr = (ip_str, port, 0, 0)
        if sockaddr:
          results.append((family, socktype, proto, cname, sockaddr))
  return results


# --> (host, port)
def getnameinfo(sockaddr, flags):
  raise NotImplementedError


# -> 32-bit packed IP representation
def inet_aton(ipaddr):
  return ''.join(chr(int(n)) for n in ipaddr.split('.'))


# -> IP address string
def inet_ntoa(ipaddr):
  return ''.join(ord(c) for c in ipaddr)


# -> None | float
def getdefaulttimeout():
  return _defaulttimeout


def setdefaulttimeout(t):
  _defaulttimeout = t
