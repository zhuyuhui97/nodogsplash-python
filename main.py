import fw_iptables
from http.server import HTTPServer
from auth_http_server import HttpHandler,MultiThreadedHTTPServer
from client_list import arr
import util
from conf import *
import os,subprocess,signal
import plugin_manager
import threading
import arping


config_read('/home/zhuyuhui/NBIC/democfg.json')
fw_iptables.iptables_fw_init()
server = MultiThreadedHTTPServer(('', gw_port), HttpHandler)
plugin_manager.plug_handler=plugin_manager.plugman()
arping_looper=arping.scanlooper()


try:
    plugin_manager.plug_handler.onevent('on_load',None)
    print('[INFO]\t\tStarting HTTP server for analyzer on {}, use <Ctrl-C> to stop'.format(gw_port))
    server.serve_forever()
except KeyboardInterrupt:
    arping_looper.stop=1
    print("\n")
    server.shutdown()
    for client in arr:
        client.stop_watch()
    fw_iptables.iptables_fw_destroy()


