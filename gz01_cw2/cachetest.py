from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep

from gz01.collections_backport import OrderedDict
from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."   
ROOTNS_IN_ADDR = "192.5.5.241"

class ACacheEntry:
  ALPHA = 0.8

  def __init__(self, dict, srtt = None):
    self._srtt = srtt
    self._dict = dict

  def __repr__(self):
    return "<ACE %s, srtt=%s>" % \
      (self._dict, ("*" if self._srtt is None else self._srtt),)

  def update_rtt(self, rtt):
    old_srtt = self._srtt
    self._srtt = rtt if self._srtt is None else \
      (rtt*(1.0 - self.ALPHA) + self._srtt*self.ALPHA)
    logger.debug("update_rtt: rtt %f updates srtt %s --> %s" % \
       (rtt, ("*" if old_srtt is None else old_srtt), self._srtt,))

class CacheEntry:
  def __init__(self, expiration = MAXINT, authoritative = False):
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CE exp=%ds auth=%s>" % \
           (self._expiration - now, self._authoritative,)

class CnameCacheEntry:
  def __init__(self, cname, expiration = MAXINT, authoritative = False):
    self._cname = cname
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CCE cname=%s exp=%ds auth=%s>" % \
           (self._cname, self._expiration - now, self._authoritative,)


# Initialize the name server cache data structure; 
# [domain name --> [nsdn --> CacheEntry]]:
nscache = dict([(DomainName("."), 
            OrderedDict([(DomainName(ROOTNS_DN), 
                   CacheEntry(expiration=MAXINT, authoritative=True))]))])

# Initialize the address cache data structure;
# [domain name --> [in_addr --> CacheEntry]]:
acache = dict([(DomainName(ROOTNS_DN),
           ACacheEntry(dict([(InetAddr(ROOTNS_IN_ADDR),
                       CacheEntry(expiration=MAXINT,
                       authoritative=True))])))]) 

# Initialize the cname cache data structure;
# [domain name --> CnameCacheEntry]
cnamecache = dict([])




def acache_debug():
	print "-"*70
	print "ACACHE: "
	keys=acache.keys()
	for key in keys:
		print key,"vvv"
		key2s=acache[key]._dict.keys()
		for key2 in key2s:
			print "\t",key2,"-->",acache[key]._dict[key2]
	print "-"*70

def nscache_debug():
	print "-"*70
	print "NSCACHE: "
	keys=nscache.keys()
	for key in keys:
		print key,"vvv"
		key2s=nscache[key].keys()
		for key2 in key2s:
			print "\t",key2,"-->",nscache[key][key2]
	print "-"*70

def cnamecache_debug():
	print "-"*70
	print "CNAMECACHE: "
	keys=cnamecache.keys()
	for key in keys:
		print key,"-->",cnamecache[key]
	print "-"*70

def cache_debug():
	print "#"*70
	acache_debug()
	nscache_debug()
	cnamecache_debug()
	print "#"*70


acache["blabla.com."]= ACacheEntry(dict([(InetAddr("123.34.34.3"),
                       CacheEntry(expiration=MAXINT,
                       authoritative=True))]))

cache_debug()

