import client_list

from scapy.all import srp, Ether, ARP
import threading
global client_list
class scanlooper:
    stop = 0
    def scanloop(self):
        iparr = []
        while self.stop == 0:
            iparr.clear()
            for item in client_list.arr:
                iparr.append(item.ip)
                item.online = 0
            try:
                ans, unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF") / ARP(pdst=iparr), timeout=60)
            except Exception as e:
                print(e)
            else:
                for send, rcv in ans:
                    ip_addr = rcv.sprintf("%ARP.psrc%")
                    mac_addr = rcv.sprintf("%Ether.src%")
                    host = client_list.find_by_ip(ip_addr)
                    if host.mac == mac_addr:
                        host.online = 1
            for item in client_list.arr:
                if item.online == 0:
                    item.do_deauth()
    def __init__(self):
        threading.Thread(target=self.scanloop())