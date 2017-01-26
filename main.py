import fw_iptables
from http.server import HTTPServer
from auth_http_server import HttpHandler,MultiThreadedHTTPServer
from client_list import arr
import util
from conf import *
import os,subprocess,signal

config_read('/home/zhuyuhui/NBIC/democfg.json')
fw_iptables.iptables_fw_init()
server = MultiThreadedHTTPServer(('', gw_port), HttpHandler)


try:
    print('[INFO]\t\tStarting HTTP server for analyzer on {}, use <Ctrl-C> to stop'.format(gw_port))
    server.serve_forever()
except KeyboardInterrupt:
    print("\n")
    server.shutdown()
    for client in arr:
        client.stop_watch()
    fw_iptables.iptables_fw_destroy()


