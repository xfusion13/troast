from troast.logger import console, logger
from troast.lib.ldap import get_dn
import ldap3
import json
import struct

def convert(binary):
    version = struct.unpack('B', binary[0:1])[0]
    # I do not know how to treat version != 1 (it does not exist yet)
    assert version == 1, version
    length = struct.unpack('B', binary[1:2])[0]
    authority = struct.unpack(b'>Q', b'\x00\x00' + binary[2:8])[0]
    string = 'S-%d-%d' % (version, authority)
    binary = binary[8:]
    assert len(binary) == 4 * length
    for i in range(length):
        value = struct.unpack('<L', binary[4*i:4*(i+1)])[0]
        string += '-%d' % value
    return string


class MachineHunter:
    
    def __init__(self, ldap_server, ldap_session, domain, targeted):
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.search_base = get_dn(domain)
        self.attributes = ["sAMAccountName","objectSid"]
        self.domain = domain
        self.targeted = targeted

    def fetch_computers(self, ldap_session):
        rids = {}
        num = 0
        with console.status(f"Searching...", spinner="dots") as status:
            addline = ''
            search_filter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            if self.targeted:
                search_filter = "(&(objectCategory=computer)(logonCount=0)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                addline = ' with logonCount=0'
            try:
                ldap_session.extend.standard.paged_search(self.search_base, search_filter, attributes=self.attributes, paged_size=500, generator=False)
            except ldap3.core.exceptions.LDAPAttributeError as e:
                print()
                logger.error (f'Error: {str(e)}')
                exit()
            for entry in ldap_session.entries:
                num += 1
                status.update(f"Retrieved {num} results.")
                json_entry = json.loads(entry.entry_to_json())
                attributes = json_entry['attributes'].keys()
                
                if type(entry['objectSid'].value) is bytes:
                    rid = convert(entry['objectSid'].value).split('-')[-1]
                else:
                    rid = entry['objectSid'].value.split('-')[-1]

                rids[int(rid)] = {'name':entry['sAMAccountName'].value}
            logger.info (f'Retrieved {len(self.ldap_session.entries)} enabled machines{addline}.')
            return rids