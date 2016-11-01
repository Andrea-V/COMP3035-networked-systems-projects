#!/usr/bin/python

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


TTL		= 600	# default time-to-live
DNS_PORT= 53	# DNS port
MAXLEN	= 512	# max lenght of DNS UDP packets
TIMEOUT = 1		# timeout in seconds to wait for reply

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


#extract useful information from a DNS packet
def parse_dns_packet(packet):
	offset=0
	
	#parse the header	
	head=Header.fromData(packet,offset)
	offset+=head.__len__()

	#parse the question section
	quest=QE.fromData(packet,offset)
	offset+=quest.__len__()

	#parse the answer section
	answs=[]	
	c=head._ancount	
	while c>0:
		(rr,lenght)=RR.fromData(packet,offset)	
		offset+=lenght
		answs.append(rr)
		c=c-1

	#parse the authority section
	auths=[]	
	c=head._nscount	
	while c>0:
		(rr,lenght)=RR.fromData(packet,offset)	
		offset+=lenght
		auths.append(rr)
		c=c-1
	
	#parse the additional section
	addts=[]	
	c=head._arcount	
	while c>0:
		(rr,lenght)=RR.fromData(packet,offset)
		offset+=lenght
		addts.append(rr)
		c=c-1
	
	return (head,quest,answs,auths,addts)

#print the dns packet in a dig-style layout	
def print_dns_packet((head,quest,answs,auths,addts)):
	print "*"*70
	print "\n;; HEADER\n",head
	print "\n;; QUESTION SECTION\n",quest
	print "\n;; ANSWER SECTION"
	for answ in answs:
		print answ
	print "\n;; AUTHORITY SECTION"
	for auth in auths:
		print auth
	print "\n;; ADDITIONAL SECTION"
	for addt in addts:
		print addt	
	print "*"*70
	
#build a DNS query packet
def build_dns_query(ide,querysec):
	head=Header(ide,Header.OPCODE_QUERY,Header.RCODE_NOERR,qdcount=1)	
	packet=head.pack()
	packet+=querysec.pack()
	return packet

#build a DNS response packet
def build_dns_response(ide,querysec,(answl,authl,addtl)):
	head=Header(ide,Header.OPCODE_QUERY,Header.RCODE_NOERR,qdcount=1,ancount=len(answl),nscount=len(authl),arcount=len(addtl),qr=1)
	packet=head.pack()
	packet+=querysec.pack()
	
	for answ in answl:
		packet+=answ.pack()
	for auth in authl:
		packet+=auth.pack()
	for addt in addtl:
		packet+=addt.pack()

	return packet

#build a DNS error packet
def build_dns_err(ide,querysec,rcode):
	head=Header(ide,Header.OPCODE_QUERY,rcode,qdcount=1,qr=1)
	packet=head.pack()
	packet+=querysec.pack()
	return packet

#return a DomainName given a QE (or a RR) as argument
def extract_dn(query_entry):
	return DomainName.fromData(query_entry.pack())

#####
## cache debug functions

def acache_debug():
	print "-"*70
	print "ACACHE: "
	keys=acache.keys()
	for key in keys:
		print key
		key2s=acache[key]._dict.keys()
		for key2 in key2s:
			print "\t",key2.__str__(),"-->",acache[key]._dict[key2]
	print "-"*70

def nscache_debug():
	print "-"*70
	print "NSCACHE: "
	keys=nscache.keys()
	for key in keys:
		print key
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
#####

#add a new entry in acache
# key: DomainName, value: InetAddr
def acache_add(key,value,ttl):
	now=int(time())
	entry=CacheEntry(expiration=ttl+now,authoritative=True)
	acache[key]=ACacheEntry(dict([(value,entry)]))


#add a new entry in nscache
# key: DomainName, value: DomainName
def nscache_add(key,value,ttl):
	now=int(time())

	#if nscache[key] doesn't already exists, it will raise a KeyError	
	try:
		nscache[key][value]=CacheEntry(expiration=ttl+now, authoritative=True)
	except KeyError:
		entry=dict([(value,CacheEntry(expiration=ttl+now, authoritative=True))])
		nscache[key]=entry

#add a new entry in cnamecache
# key: DomainName, value: DomainName
def cnamecache_add(key,value,ttl):
	now=int(time())
	cnamecache[key]=CnameCacheEntry(value,expiration=ttl+now,authoritative=True)	

#send packet and wait for response
def send_and_wait(pkt,tries,dest_addr):
	while tries>0:	
		try:
			cs.sendto(pkt,(dest_addr,DNS_PORT))
			(data,address)=cs.recvfrom(MAXLEN)
		except error:
			tries-=1
		else:
			break

	else:#i've finished my tries
		raise error

	return (data,address)


#perform a lookup in cache of the address and all the cnames
def addr_lookup(domain_name):
	now=int(time())
	#first, i check directly for the address	
	try:
		addrs=acache[domain_name]._dict.keys()
		
		for addr in addrs:
			exp=acache[domain_name]._dict[addr]._expiration		
			
			if now > exp: #ttl control
				del acache[domain_name]._dict[addr]
				continue

			return ([RR_A(domain_name,exp-now,addr.toNetwork())],[],[])
	except KeyError:
		#i don't have an address for this domain name, then i look for a cname
		try:
			cname=cnamecache[domain_name]._cname
			exp  =cnamecache[domain_name]._expiration

			if now > exp: #ttl control
				del cnamecache[domain_name]
				raise KeyError

			#found the cname, now i look for the cname address
			tmp=addr_lookup(cname)
			if not tmp:
				raise KeyError
			
			(answl,authl,addtl)=tmp

			#append cname entry in the aswer section 
			tmp=list(answl)
			tmp=[RR_CNAME(domain_name,exp-now,cname)]+tmp

			return (tmp,authl,addtl)
		except KeyError:
			return None


#perform a lookup in cache for an authoritative nameserver
def ns_lookup(domain_name):
	now=int(time())
	try:
		nss=nscache[domain_name].keys()			

		for ns in nss:
			exp=nscache[domain_name][ns]._expiration
			if now > exp: #ttl control
				del nscache[domain_name][ns]
				continue
			return ([],[RR_NS(domain_name,exp-now,ns)],[])
	
	except KeyError:
		if domain_name.__str__() == ".":
			return None
		else:
			return ns_lookup(domain_name.parent())


#perform a cache lookup
# domain_name: DomainName
#return: ([ANSWER entries],[AUTHORITY entries],[ADDITIONAL entries])
def lookup(domain_name):
	#first I look for the address

	tmp=addr_lookup(domain_name)
	if not tmp:
		raise error
	
	(answl0,authl0,addtl0)=tmp
	#now I look for an authoritative nameserver
	tmp=ns_lookup(domain_name)

	if not tmp:
		raise error

	(answl1,authl1,addtl1)=tmp
	glue_recs=[]

	#try to find the the glue records
	for auth1 in authl1:
		tmp=addr_lookup(auth1._nsdn)
		if not tmp:
			raise error
		(answl2,authl2,addtl2)=tmp
		glue_recs+=list(answl2)

	return (answl0,authl1,glue_recs)

# send a DNS query to a remote server
def remote_query(ide,query_entry,dest_addr):
	pkt=build_dns_query(ide,query_entry)
	(data,address)=send_and_wait(pkt,5,inet_ntoa(dest_addr))
	return parse_dns_packet(data)


#perfom an iterative query
#ide: int, query_entry: QE , dest_addr: packed 4 bytes IP network representation
#return: ([ANSWER entries],[AUTHORITY entries],[ADDITIONAL entries],error code)
def iterative_query(ide,query_entry,dest_addr):
	query_dn=extract_dn(query_entry)
	response=None

	# lookup in cache for the address
	try:
		cresult=lookup(query_dn)
	except error:
		# if cache miss, send a query to a remote DNS server
		response=remote_query(ide,query_entry,dest_addr)	
	else:
		#if cache hit, then return the result
		(head,quest,answs,auths,addts)=parse_dns_packet(build_dns_response(ide,query_entry,cresult))
		return (answs,auths,addts,0)

	(head,quest,answs,auths,addts)=response

	#If the server sent me an error, return immediately
	if head._rcode != Header.RCODE_NOERR:
		return ([],[],[],head._rcode)

	#if I have an answer record, it can be either A or CNAME type
	if head._ancount>0:
		for answ in answs:
			#A type: cache response and return the answer to the client
			if answ._type == RR.TYPE_A:
				acache_add(answ._dn,InetAddr(inet_ntoa(answ._addr)),answ._ttl)
				return ([RR_A(answ._dn,answ._ttl,answ._addr)],[],[],0)
			
			#CNAME type: cache response,save the alias in the response
			#            and lookup the address for the alias
			elif answ._type == RR.TYPE_CNAME:			
				try:
					new_query=QE(QE.TYPE_A,answ._cname)				
					(answl,authl,addtl,err)=iterative_query(ide,new_query,inet_aton(ROOTNS_IN_ADDR))
			
				except error:
					continue #try another answer entry		
				else:
					#cache result and return it adding a CNAME entry to the answers
					tmp=list(answl)
					tmp=[RR_CNAME(answ._dn,answ._ttl,answ._cname)]+tmp
					
					cnamecache_add(answ._dn,answ._cname,answ._ttl)
					return (tmp,authl,addtl,0)	
		else:
			#if I exited from the for-loop, then all the answers had given me an error
			raise error

	#if i don't receive answers, check for a delegation,
	#and check whether there is a glue record
	else:
		#filter the innapropriate types of rr (AAAA,SOA, etc. etc.)
		auths=filter((lambda x: x._type == RR.TYPE_NS),auths)
		addts=filter((lambda x: x._type == RR.TYPE_A) ,addts)
		
		# first, I look for a glue record
		if len(auths)>0 and len(addts)>0:
			for auth in auths:
				nscache_add(auth._dn,auth._nsdn,auth._ttl)
				for addt in addts:
					if auth._nsdn.__str__() == addt._dn.__str__():#i've found a glue record
						acache_add(addt._dn,InetAddr(inet_ntoa(addt._addr)),addt._ttl)					
						try:
							#now i can go ahead with my query
							(answl,authl,addtl,err)=iterative_query(ide,quest,addt._addr)
							
							# I add the authoritative ns and the glue record before
							# returning the result (if nobody hasn't already done it before)
							if not authl and not addtl:					
								return (answl,[RR_NS(auth._dn,auth._ttl,auth._nsdn)],[RR_A(addt._dn,addt._ttl,addt._addr)],0)
							else:
								return (answl,authl,addtl,0)
						except error:
							continue #try to find another glue record
					
		#if I don't find a glue record, I have to find for the adress of the ns
		#before I can go ahead with my original query
		if len(auths)>0:
			for auth in auths:
				nscache_add(auth._dn,auth._nsdn,auth._ttl)
				new_query=QE(QE.TYPE_A,auth._nsdn)
				try:
					(answl,authl,addtl,err)=iterative_query(ide,new_query,inet_aton(ROOTNS_IN_ADDR))
				except error:
					continue #try the next authoritative entry			
					
				#now i can go ahead with my original query
				answl1=filter((lambda x : x._type == RR.TYPE_A),answl)
				for answ in answl1:									
					try:					
						return iterative_query(ide,quest,answ._addr)
					except error:
						continue #try the next answer entry
			else:
				raise error

	raise error #this instruction should never be executed


# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

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

# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
  if value < 32768 or value > 61000:
    raise OptionValueError("need 32768 <= port <= 61000")
  parser.values.port = value

parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
reply=None
while 1:
	(data, caddress,) = ss.recvfrom(MAXLEN) # DNS limits UDP msgs to 512 bytes

	if not data:
		log.error("client provided no data")
		continue

	(head,quest,answs,auths,addts)=parse_dns_packet(data)

	try:
		(answl,authl,addtl,err)=iterative_query(head._id,quest,inet_aton(ROOTNS_IN_ADDR))		
	except error:
		logger.error("iterative query failed")
		reply=build_dns_err(head._id,quest,Header.RCODE_SRVFAIL)
	else:	
		if err!=0:
			reply=build_dns_err(head._id,quest,err)
		else:	
			reply=build_dns_response(head._id,quest,(answl,authl,addtl))

	logger.log(DEBUG2, "our reply in full:") 
	logger.log(DEBUG2, hexdump(reply))

	ss.sendto(reply, caddress)


