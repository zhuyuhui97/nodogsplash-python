import util
from conf import *
import random,string
import urllib3.request,subprocess,signal
from fw_iptables import *
from flags import *

global arr
arr=[]
idxcount=0

class c_client:
    def __init__(self,ip,mac):
        self.ip=ip
        self.mac=mac
        self.token=''.join(random.sample(['f','e','d','c','b','a','9','8','7','6','5','4','3','2','1','0'], 8)).replace(' ','')
        global idxcount
        self.idx=idxcount
        idxcount=(idxcount+1)%maxclients
        arr.append(self)

    def do_auth(self):
        if (self.fw_connection_state==AUTH_DEAUTHENTICATED):
            rc = 1
            print("[INFO]\t\tAuthenticating {} {}".format(self.ip, self.mac))
            rc |= iptables_do_command(
                "-t mangle -A " + CHAIN_OUTGOING + " -s {} -m mac --mac-source {} -j MARK {} 0x{:x}{:x}",
                self.ip, self.mac, markop, self.idx + 10, FW_MARK_AUTHENTICATED)
            rc |= iptables_do_command("-t mangle -A " + CHAIN_INCOMING + " -d {} -j MARK {} 0x{:x}{:x}", self.ip,
                                      markop,
                                      self.idx + 10, FW_MARK_AUTHENTICATED)
            rc |= iptables_do_command("-t mangle -A " + CHAIN_INCOMING + " -d {} -j ACCEPT", self.ip)
            if (rc == 1):
                fw_connection_state = AUTH_AUTHENTICATED
            return rc
        else:
            print('[ERROR]\t{} is authenticated, skipping.'.format(self.ip))

    def do_deauth(self):
        if (self.fw_connection_state == AUTH_AUTHENTICATED):
            rc = 1
            print("[INFO]\t\tDeauthenticating {} {}".format(self.ip, self.mac))
            rc |= iptables_do_command(
                "-t mangle -D " + CHAIN_OUTGOING + " -s {} -m mac --mac-source {} -j MARK {} 0x{:x}{:x}",
                self.ip, self.mac, markop, self.idx + 10, FW_MARK_AUTHENTICATED)
            rc |= iptables_do_command("-t mangle -D " + CHAIN_INCOMING + " -d {} -j MARK {} 0x{:x}{:x}", self.ip,
                                      markop,
                                      self.idx + 10, FW_MARK_AUTHENTICATED)
            rc |= iptables_do_command("-t mangle -D " + CHAIN_INCOMING + " -d {} -j ACCEPT", self.ip)
            if (rc == 1):
                fw_connection_state = AUTH_DEAUTHENTICATED
            return rc
        else:
            print('[ERROR]\t{} is not authenticated, skipping.'.format(self.ip))

    def gen_auth_target_content(self):
        request_content={
            'token':self.token,
            'clientip':self.ip,
            'clientmac':self.mac
        }
        return request_content

    def gen_auth_target(self):
        str=urllib3.request.urlencode(self.gen_auth_target_content(), doseq=False)
        return ('/'+authdir+'?'+str).encode()


    ip=''
    mac=''
    token=''
    fw_connection_state=AUTH_DEAUTHENTICATED
    #added_time=0
    #counters
    #attempts=0
    #download_limit=0
    #upload_limit=0
    idx=0

def find_by_ip(ip):
    global arr
    for host in arr:
        if host.ip==ip:
            return host
    return None


