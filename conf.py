import json,os,traceback

#From syslog.h
LOG_WARNING = 4
LOG_DAEMON = (3 << 3)
#From syslog.h

NUM_EXT_INTERFACE_DETECT_RETRY = 0

EXT_INTERFACE_DETECT_RETRY_INTERVAL = 1
MAC_ALLOW = 0
MAC_BLOCK = 1

DEFAULT_DAEMON = 1
DEFAULT_DEBUGLEVEL = LOG_WARNING
DEFAULT_MAXCLIENTS = 20
DEFAULT_GATEWAY_IPRANGE = '0.0.0.0/0'
DEFAULT_GATEWAYNAME = 'NoDogSplash'
DEFAULT_GATEWAYPORT = 2050
DEFAULT_REMOTE_AUTH_PORT = 80
DEFAULT_CHECKINTERVAL = 60
DEFAULT_CLIENTTIMEOUT = 10
DEFAULT_CLIENTFORCEOUT = 360
DEFAULT_WEBROOT = '/etc/nodogsplash/htdocs'
DEFAULT_SPLASHPAGE = 'splash.html'
DEFAULT_INFOSKELPAGE = 'infoskel.html'
DEFAULT_IMAGESDIR = 'images'
DEFAULT_PAGESDIR = 'pages'
DEFAULT_AUTHDIR = 'nodogsplash_auth'
DEFAULT_DENYDIR = 'nodogsplash_deny'
DEFAULT_MACMECHANISM = MAC_BLOCK
DEFAULT_PASSWORD_AUTH = 0
DEFAULT_USERNAME_AUTH = 0
DEFAULT_PASSWORD_ATTEMPTS = 5
DEFAULT_AUTHENTICATE_IMMEDIATELY = 0
DEFAULT_SET_MSS = 1
DEFAULT_MSS_VALUE = 0
DEFAULT_TRAFFIC_CONTROL = 0
DEFAULT_UPLOAD_LIMIT = 0
DEFAULT_DOWNLOAD_LIMIT = 0
DEFAULT_DOWNLOAD_IMQ = 0
DEFAULT_UPLOAD_IMQ = 1
DEFAULT_LOG_SYSLOG = 0
DEFAULT_SYSLOG_FACILITY = LOG_DAEMON
DEFAULT_NDSCTL_SOCK = '/tmp/ndsctl.sock'
DEFAULT_INTERNAL_SOCK = '/tmp/ndsctl.sock'
DEFAULT_FW_MARK_AUTHENTICATED = 0x400
DEFAULT_FW_MARK_TRUSTED = 0x200
DEFAULT_FW_MARK_BLOCKED = 0x100
DEFAULT_DECONGEST_HTTPD_THREADS = 0
DEFAULT_HTTPD_THREAD_THRESHOLD = 3
DEFAULT_HTTPD_THREAD_DELAY_MS = 200

DEFAULT_EMPTY_TRUSTED_USERS_POLICY = 'ACCEPT'
DEFAULT_EMPTY_TRUSTED_USERS_TO_ROUTER_POLICY = 'ACCEPT'
DEFAULT_EMPTY_USERS_TO_ROUTER_POLICY = 'REJECT'
DEFAULT_EMPTY_AUTHENTICATED_USERS_POLICY = 'RETURN'
DEFAULT_EMPTY_PREAUTHENTICATED_USERS_POLICY = 'REJECT'
DEFAULT_IP6 = 0

DEFAULT_SPLASH_DIR='/authsplash'

# struct  t_firewall_target
TARGET_DROP = 0
TARGET_REJECT = 1
TARGET_ACCEPT = 2
TARGET_LOG = 3
TARGET_ULOG = 4


class _firewall_rule_t:
    target = 0  # t_firewall_target
    protocol = ''
    port = ''
    mask = ''
    # next=None #Will use list provided by python, linked list is deprecated.


configfile = ''  # name of the config file
# ndsctl_sock = DEFAULT_NDSCTL_SOCK  # ndsctl path to socket
# internal_sock = DEFAULT_INTERNAL_SOCK  # internal path to socket
ctl_sock = '/tmp/wpdogctl.sock'
daemon = -1  # if daemon > 0, use daemon mode
debuglevel = DEFAULT_DEBUGLEVEL  # Debug information verbosity
maxclients = DEFAULT_MAXCLIENTS  # Maximum number of clients allowed
gw_name = DEFAULT_GATEWAYNAME  # Name of the gateway; e.g. its SSID
gw_interface = ''  # Interface we will manage
gw_iprange = DEFAULT_GATEWAY_IPRANGE  # IP range on gw_interface we will manage
# gw_address = ''  # Internal IP address for our web server
gw_address = '192.168.199.1'  # Internal IP address for our web server
gw_mac = ''  # MAC address of the interface we manage
gw_port = DEFAULT_GATEWAYPORT  # Port the webserver will run on
# gw_port = 80  # Port the webserver will run on
remote_auth_action = ''  # Path for remote auth
# char  enable_preauth;  # enable pre-authentication support
# char * bin_voucher;  # enable voucher support
# char  force_voucher;  # force voucher
webroot = DEFAULT_WEBROOT  # Directory containing splash pages, etc.
splashpage = DEFAULT_SPLASHPAGE  # Name of main splash page
infoskelpage = DEFAULT_INFOSKELPAGE  # Name of info skeleton page
imagesdir = DEFAULT_IMAGESDIR  # Subdir of webroot containing .png .gif files etc
pagesdir = DEFAULT_PAGESDIR  # Subdir of webroot containing other .html files
redirectURL = ''  # URL to direct client to after authentication
authdir = DEFAULT_AUTHDIR  # Notional relative dir for authentication URL
denydir = DEFAULT_DENYDIR  # Notional relative dir for denial URL
passwordauth = DEFAULT_PASSWORD_AUTH  # boolean, whether to use password authentication
usernameauth = DEFAULT_USERNAME_AUTH  # boolean, whether to use username authentication
username = ''  # Username for username authentication
password = ''  # Password for password authentication
passwordattempts = DEFAULT_PASSWORD_ATTEMPTS  # Number of attempted password authentications allowed
clienttimeout = DEFAULT_CLIENTTIMEOUT  # How many CheckIntervals before an inactive client must be re-authenticated
clientforceout = DEFAULT_CLIENTFORCEOUT  # How many CheckIntervals before a client must be re-authenticated
checkinterval = DEFAULT_CHECKINTERVAL  # Period the the client timeout check thread will run, in seconds
authenticate_immediately = DEFAULT_AUTHENTICATE_IMMEDIATELY  # boolean, whether to auth noninteractively
set_mss = DEFAULT_SET_MSS  # boolean, whether to set mss
mss_value = DEFAULT_MSS_VALUE  # int, mss value; <= 0 clamp to pmtu
traffic_control = DEFAULT_TRAFFIC_CONTROL  # boolean, whether to do tc
download_limit = DEFAULT_DOWNLOAD_LIMIT  # Download limit, kb/s
upload_limit = DEFAULT_UPLOAD_LIMIT  # Upload limit, kb/s
download_imq = DEFAULT_DOWNLOAD_IMQ  # Number of IMQ handling download
upload_imq = DEFAULT_UPLOAD_IMQ  # Number of IMQ handling upload
log_syslog = DEFAULT_LOG_SYSLOG  # boolean, whether to log to syslog
syslog_facility = DEFAULT_SYSLOG_FACILITY  # facility to use when using syslog for logging
decongest_httpd_threads = DEFAULT_DECONGEST_HTTPD_THREADS  # boolean, whether to avoid httpd thread congestion
httpd_thread_threshold = DEFAULT_HTTPD_THREAD_THRESHOLD  # number of concurrent httpd threads before trying decongestion
httpd_thread_delay_ms = DEFAULT_HTTPD_THREAD_DELAY_MS  # ms delay before starting a httpd thread after threshold
macmechanism = DEFAULT_MACMECHANISM  # mechanism wrt MAC addrs
rulesets = None  # firewall rules
trustedmaclist = []  # list of trusted macs
blockedmaclist = []  # list of blocked macs
allowedmaclist = []  # list of allowed macs
FW_MARK_AUTHENTICATED = DEFAULT_FW_MARK_AUTHENTICATED  # iptables mark for authenticated packets
FW_MARK_BLOCKED = DEFAULT_FW_MARK_BLOCKED  # iptables mark for blocked packets
FW_MARK_TRUSTED = DEFAULT_FW_MARK_TRUSTED  # iptables mark for trusted packets
ip6 = DEFAULT_IP6  # enable IPv6
splashdir = DEFAULT_SPLASH_DIR



conf_name_dict={
    'GatewayInterface':'gw_interface',
    'GatewayAddress':'gw_address',
    'GatewayPort':'gw_port',
    'WebRoot':'webroot',
    'TrustedMACList':'trustedmaclist',
    'BlockedMACList':'blockedmaclist',
    'AllowedMACList':'allowedmaclist',
    'FirewallRuleSet':'rulesets'
}

def is_empty_ruleset(name):
    return (rulesets==None) or (len(rulesets)==0) or (not name in rulesets) or (len(rulesets[name])==0)

#def check_ruleset():

#TODO validate ruleset
#Read json-style configuration file
def config_read(filename):
    jsonfile=open(filename)
    cfgdict=json.load(jsonfile)
    cfgobj=globals()
    #Init for must-have variables
    if not 'GatewayInterface' in cfgdict:
        print('[ERROR]\t\tNo interface specified.')
        exit()
    try:
        for i in cfgdict:
            try:
                cfgobj[conf_name_dict[i]] = cfgdict[i]
            except KeyError as ex_key:
                print("[ERROR]\t\tInvaild key "+str(ex_key))

    except Exception as ex:
        print("[ERROR]\t\tInvaild cfg file")
        traceback.print_exc()
        exit()
    finally:
        jsonfile.close()