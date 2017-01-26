from http.server import BaseHTTPRequestHandler
import client_list, util, os.path, urllib.parse
from socketserver import StreamRequestHandler,ThreadingMixIn
from http.server import HTTPServer
from flags import *
from conf import *
import threading


class MultiThreadedHTTPServer(ThreadingMixIn, HTTPServer):
 pass

mutex=threading.Lock()

class HttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global client_list
        urlinfo=urllib.parse.urlparse(self.path)
        urlquery=urllib.parse.parse_qs(urlinfo.query)
        reqpath=urlinfo.path
        ip = self.client_address[0]
        mutex.acquire()
        client = client_list.find_by_ip(ip)
        if (client == None):
            client = client_list.c_client(ip, util.arp_get_mac(ip))
            print('[INFO]\t\tAssigned token {} for {}'.format(client.token, client.ip))
        mutex.release()
        if (reqpath.startswith(splashdir)):
            # Send splash page to client
            if reqpath!=splashdir:
                filepath = reqpath.split(splashdir+'/')[1]
            else:
                filepath=''
            pathstr = os.path.join(webroot, filepath)
            try:
                file = open(pathstr, 'rb')
                self.send_response(200)
                self.end_headers()
                if filepath.endswith('.html'):
                    filecontent = file.read()
                    file.close()
                    page = gen_auth_splash_page(filecontent, client)
                    self.wfile.write(page)
                else:
                    self.wfile.write(file.read())
                    file.close()
            except FileNotFoundError:
                self.send_error(404)
            except IsADirectoryError:
                self.send_response(302)
                self.send_header('Location', 'index.html')
                self.end_headers()
        elif (('/' + authdir) in reqpath and ip in self.path):
            # Check info and try to do authencation
            arglist = urlquery
            if arglist['clientip'][0] == client.ip and arglist['clientmac'][0] == client.mac:
                if arglist['token'][0] == client.token:
                    client.do_auth()
                    print('[INFO]\t\tAuthenticating {} - {}'.format(client.ip, client.mac))
                else:
                    print('[ERROR]\t\tWrong token from {} - {}'.format(client.ip, client.mac))
            else:
                print('[ERROR]\t\tWrong IP addr or MAC addr from {} - {} : {} - {}'.format(client.ip, client.mac,
                                                                                arglist['clientip'],
                                                                                arglist['clientmac']))
            self.send_response(200)
            self.end_headers()
        elif ('favicon' in reqpath):
            self.send_response(200)
            self.end_headers()
        else:
            if client.fw_connection_state == AUTH_DEAUTHENTICATED:
                # Send 302 to redirect HTTP request
                self.send_response(302)
                self.send_header('Location', os.path.join(splashdir, splashpage))
                self.end_headers()
            else:
                print('[ERROR]\t\tCurrent client {} requested an incorrect url or not deauthencated, ignored.', ip)
    def log_request(self, code='-', size='-'):
        pass

def gen_auth_splash_page(content, client):
    # content = content.replace(b'$authaction', b'i')
    # content = content.replace(b'$denyaction', b'i')
    content = content.replace(b'$authtarget', client.gen_auth_target())
    content = content.replace(b'$tok', client.token.encode())
    # content = content.replace(b'$redir', b'i')
    content = content.replace(b'$gatewayname', gw_name.encode())
    # content = content.replace(b'$error_msg', b'i')
    content = content.replace(b'$clientip', client.ip.encode())
    content = content.replace(b'$clientmac', client.ip.encode())
    # content = content.replace(b'$gatewaymac', b'i')
    content = content.replace(b'$imagesdir', imagesdir.encode())
    # content = content.replace(b'$nclients', b'i')
    # content = content.replace(b'$maxclients', b'i')
    # content = content.replace(b'$uptime', b'i')
    return content
