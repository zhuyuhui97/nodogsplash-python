from http.server import BaseHTTPRequestHandler
import client_list
import json

global client_list
class CtrlHttpHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            objr=json.load(self.rfile,parse_int=True)
            if (objr['op']=='list'):
                self.send_response(200)
                json.dump(self.gen_list(),self.wfile)
            elif(objr['op']=='auth'):
                #objw={

                #}
                pass
            elif(objr['op']=='deauth'):
                pass
            elif(objr['op']=='startcap'):
                pass
            elif(objr['op']=='stopcap'):
                pass
        except:
            self.send_error(500)

    def gen_list(self):
        global client_list
        obj={
            'opr':"list",
            'result':0,
            'content':client_list.arr
        }