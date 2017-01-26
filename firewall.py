from  fw_iptables import *
#Firewall marks
FW_MARK_NONE = 0,           #No mark set.
FW_MARK_PROBATION = 1       #The client is in probation period and must be authenticated
FW_MARK_KNOWN = 2           #The client is known to the firewall
FW_MARK_AUTH_IS_DOWN = 253  #The auth servers are down
FW_MARK_LOCKED = 254        #The client has been locked out


#TODO get ip adress
def arp_get(req_ip):
    reply=""
    return reply

def fw_destroy():
    # TODO DEBUG OUTPUT
    return iptables_fw_destroy()

