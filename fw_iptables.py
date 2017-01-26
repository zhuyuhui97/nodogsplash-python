import util, firewall
import conf
from flags import *
import os

CHAIN_TO_INTERNET = 'ndsNET'
CHAIN_TO_ROUTER = 'ndsRTR'
CHAIN_TRUSTED_TO_ROUTER = 'ndsTRT'
CHAIN_OUTGOING = 'ndsOUT'
CHAIN_INCOMING = 'ndsINC'
CHAIN_AUTHENTICATED = 'ndsAUT'
CHAIN_PREAUTHENTICATED = 'ndsPRE'
CHAIN_BLOCKED = 'ndsBLK'
CHAIN_ALLOWED = 'ndsALW'
CHAIN_TRUSTED = 'ndsTRU'

markop = '--or-mark'


# TODO init marks && check mark masking

# TODO add
def iptables_do_command(fmt, *args):
    cmd = ('iptables ' + fmt).format(*args)
    print('[COMMAND]\t' + cmd)
    return os.system(cmd)


def _iptables_compile(table, chain, rule):
    mode = ''
    rule_opr = rule['operation']
    if rule_opr == 'block':
        mode = 'REJECT'
    elif rule_opr == 'drop':
        mode = 'DROP'
    elif rule_opr == 'allow':
        mode = 'ACCEPT'
    elif rule_opr == 'log':
        mode = 'LOG'
    elif rule_opr == 'ULOG':
        mode = 'ULOG'
    cmd = '-t {} -A {} '.format(table, chain)
    if 'mask' in rule:
        cmd += '-d {} '.format(rule['mask'])
    else:
        cmd += '-d {} '.format('0.0.0.0/0')#TODO Should not be done here??
    if 'protocol' in rule:
        cmd += '-p {} '.format(rule['protocol'])
        if 'port' in rule:
            cmd += '--dport {} '.format(rule['port'])
    cmd += '-j {}'.format(mode)
    return cmd


def _iptables_append_ruleset(table, chain, rulesetname):
    ruleset = conf.rulesets[rulesetname]
    print('[INFO]\t\tLoading ruleset {} into table {}, chain {}'.format(rulesetname, table, chain))
    for rule in ruleset:
        cmd = _iptables_compile(table, chain, rule)
        iptables_do_command(cmd)
    print('[INFO]\t\tRuleset {} loaded into table {}, chain {}'.format(rulesetname, table, chain))




def iptables_block_mac(mac):
    return iptables_do_command('-t mangle -A ' + CHAIN_BLOCKED + ' -m mac --mac-source {} -j MARK {} 0x{:x}', mac,
                               markop,
                               conf.FW_MARK_BLOCKED)


def iptables_unblock_mac(mac):
    return iptables_do_command('-t mangle -D ' + CHAIN_BLOCKED + ' -m mac --mac-source {} -j MARK {} 0x{:x}', mac,
                               markop,
                               conf.FW_MARK_BLOCKED)


def iptables_allow_mac(mac):
    return iptables_do_command('-t mangle -I ' + CHAIN_ALLOWED + ' -m mac --mac-source {} -j RETURN', mac)


def iptables_unallow_mac(mac):
    return iptables_do_command('-t mangle -D ' + CHAIN_ALLOWED + ' -m mac --mac-source {} -j RETURN', mac)


def iptables_trust_mac(mac):
    return iptables_do_command('-t mangle -A ' + CHAIN_TRUSTED + ' -m mac --mac-source {} -j MARK {} 0x{:x}', mac,
                               markop,
                               conf.FW_MARK_TRUSTED)


def iptables_untrust_mac(mac):
    return iptables_do_command('-t mangle -D ' + CHAIN_TRUSTED + ' -m mac --mac-source {} -j MARK {} 0x{:x}', mac,
                               markop,
                               conf.FW_MARK_TRUSTED)


def iptables_fw_init():
    # TODO get config
    ext_interface = ''
    trusted_mac = []
    gw_interface = conf.gw_interface
    gw_address = conf.gw_address
    gw_iprange = conf.gw_iprange
    gw_port = conf.gw_port
    trustedmac = conf.trustedmaclist
    blockedmac = conf.blockedmaclist
    allowedmac = conf.allowedmaclist
    macmechanism = conf.macmechanism
    set_mss = conf.set_mss
    mss_value = conf.mss_value
    traffic_control = conf.traffic_control
    FW_MARK_BLOCKED = conf.FW_MARK_BLOCKED
    FW_MARK_TRUSTED = conf.FW_MARK_TRUSTED
    FW_MARK_AUTHENTICATED = conf.FW_MARK_AUTHENTICATED
    # +mark mask should be checked if it is enabled
    FW_MARK_MASK = FW_MARK_BLOCKED | FW_MARK_TRUSTED | FW_MARK_AUTHENTICATED
    markmask = '/0x{:x}'.format(FW_MARK_MASK)
    markop = '--or-mark'
    # +mark mask should be checked if it is enabled
    # Everything in the MANGLE table
    # create new chains
    iptables_do_command('-t mangle -N ' + CHAIN_TRUSTED)
    iptables_do_command('-t mangle -N ' + CHAIN_BLOCKED)
    iptables_do_command('-t mangle -N ' + CHAIN_INCOMING)
    iptables_do_command('-t mangle -N ' + CHAIN_OUTGOING)
    iptables_do_command('-t mangle -I PREROUTING 1 -i {} -s {} -j ' + CHAIN_OUTGOING, gw_interface, gw_iprange)
    iptables_do_command('-t mangle -I PREROUTING 2 -i {} -s {} -j ' + CHAIN_BLOCKED, gw_interface, gw_iprange)
    iptables_do_command('-t mangle -I PREROUTING 3 -i {} -s {} -j ' + CHAIN_TRUSTED, gw_interface, gw_iprange)
    iptables_do_command('-t mangle -I POSTROUTING 1 -o {} -d {} -j ' + CHAIN_INCOMING, gw_interface, gw_iprange)

    for mac in trustedmac:
        iptables_trust_mac(mac)

    if (conf.MAC_BLOCK == macmechanism):
        for mac in blockedmac:
            iptables_block_mac(mac)
    elif (conf.MAC_ALLOW == macmechanism):
        iptables_do_command('-t mangle -A ' + CHAIN_BLOCKED + ' -j MARK {} 0x{:x}', markop, FW_MARK_BLOCKED)
        for mac in allowedmac:
            iptables_allow_mac(mac)
    else:
        print('[ERROR]\t\tUnknown MAC mechanism: {}', macmechanism)
        # rc=-1

    # TODO traffic control
    iptables_do_command('-t nat -N ' + CHAIN_OUTGOING)
    iptables_do_command('-t nat -I PREROUTING -i {} -s {} -j ' + CHAIN_OUTGOING, gw_interface, gw_iprange)
    iptables_do_command('-t nat -A ' + CHAIN_OUTGOING + ' -m mark --mark 0x{:x}{} -j ACCEPT', FW_MARK_TRUSTED, markmask)
    iptables_do_command('-t nat -A ' + CHAIN_OUTGOING + ' -m mark --mark 0x{:x}{} -j ACCEPT', FW_MARK_AUTHENTICATED,
                        markmask)
    _iptables_append_ruleset('nat',CHAIN_OUTGOING,'preauthenticated-users')
    iptables_do_command('-t nat -A ' + CHAIN_OUTGOING + ' -p tcp --dport 80 -j DNAT --to-destination {}:{}', gw_address,
                        gw_port)
    iptables_do_command('-t nat -A ' + CHAIN_OUTGOING + ' -j ACCEPT')
    iptables_do_command('-t filter -N ' + CHAIN_TO_INTERNET)
    iptables_do_command('-t filter -N ' + CHAIN_TO_ROUTER)
    iptables_do_command('-t filter -N ' + CHAIN_AUTHENTICATED)
    iptables_do_command('-t filter -N ' + CHAIN_TRUSTED)
    iptables_do_command('-t filter -N ' + CHAIN_TRUSTED_TO_ROUTER)
    iptables_do_command('-t filter -I INPUT -i {} -s {} -j ' + CHAIN_TO_ROUTER, gw_interface, gw_iprange)
    iptables_do_command('-t filter -A ' + CHAIN_TO_ROUTER + ' -m mark --mark 0x{:x}{} -j DROP', FW_MARK_BLOCKED,
                        markmask)
    iptables_do_command('-t filter -A ' + CHAIN_TO_ROUTER + ' -m state --state INVALID -j DROP')
    iptables_do_command('-t filter -A ' + CHAIN_TO_ROUTER + ' -m state --state RELATED,ESTABLISHED -j ACCEPT')
    iptables_do_command('-t filter -A ' + CHAIN_TO_ROUTER + ' -p tcp --tcp-flags SYN SYN \\! --tcp-option 2 -j  DROP')
    iptables_do_command('-t filter -A ' + CHAIN_TO_ROUTER + ' -p tcp --dport {} -j ACCEPT', gw_port)  # nds line 484

    if conf.is_empty_ruleset('trusted-users-to-router'):
        iptables_do_command('-t filter -A ' + CHAIN_TO_ROUTER + ' -m mark --mark 0x{:x}{} -j {}', FW_MARK_TRUSTED,
                            markmask, conf.DEFAULT_EMPTY_TRUSTED_USERS_TO_ROUTER_POLICY)
    else:
        iptables_do_command('-t filter -A ' + CHAIN_TO_ROUTER + ' -m mark --mark 0x{:x}{} -j ' + CHAIN_TRUSTED_TO_ROUTER,FW_MARK_TRUSTED, markmask)
        iptables_do_command('-t filter -A '+CHAIN_TRUSTED_TO_ROUTER+' -m state --state RELATED,ESTABLISHED -j ACCEPT')
        _iptables_append_ruleset('filter',CHAIN_TRUSTED_TO_ROUTER,'trusted-users-to-router')
        iptables_do_command('-t filter -A '+CHAIN_TRUSTED_TO_ROUTER+' -j REJECT --reject-with icmp-port-unreachable')

    if conf.is_empty_ruleset('users-to-router'):
        iptables_do_command('-t filter -A ' + CHAIN_TO_ROUTER + ' -j {}', conf.DEFAULT_EMPTY_USERS_TO_ROUTER_POLICY)
    else:
        _iptables_append_ruleset('filter',CHAIN_TO_ROUTER,'users-to-router')
        iptables_do_command('-t filter -A '+CHAIN_TO_ROUTER+' -j REJECT --reject-with icmp-port-unreachable')

    iptables_do_command('-t filter -I FORWARD -i {} -s {} -j ' + CHAIN_TO_INTERNET, gw_interface, gw_iprange)
    iptables_do_command('-t filter -A ' + CHAIN_TO_INTERNET + ' -m mark --mark 0x{:x}{} -j DROP', FW_MARK_BLOCKED,
                        markmask)
    iptables_do_command('-t filter -A ' + CHAIN_TO_INTERNET + ' -m state --state INVALID -j DROP')

    if set_mss:
        if mss_value>0:
            iptables_do_command('-t filter -A '+CHAIN_TO_INTERNET+' -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d', mss_value)
        else:
            iptables_do_command('-t filter -A '+CHAIN_TO_INTERNET+' -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu')

    if conf.is_empty_ruleset('trusted-users'):
        iptables_do_command('-t filter -A ' + CHAIN_TO_INTERNET + ' -m mark --mark 0x{:x}{} -j {}', FW_MARK_TRUSTED,
                            markmask, conf.DEFAULT_EMPTY_TRUSTED_USERS_POLICY)
    else:
        iptables_do_command('-t filter -A '+CHAIN_TO_INTERNET+' -m mark --mark 0x{:x}{} -j '+CHAIN_TRUSTED, FW_MARK_TRUSTED, markmask)
        iptables_do_command('-t filter -A '+CHAIN_TRUSTED+' -m state --state RELATED,ESTABLISHED -j ACCEPT')
        _iptables_append_ruleset('filter',CHAIN_TRUSTED,'trusted_users')
        iptables_do_command('-t filter -A '+CHAIN_TRUSTED+' -j REJECT --reject-with icmp-port-unreachable')

    if conf.is_empty_ruleset('authenticated-users'):
        iptables_do_command('-t filter -A ' + CHAIN_TO_INTERNET + ' -m mark --mark 0x{:x}{} -j {}',
                            FW_MARK_AUTHENTICATED, markmask, conf.DEFAULT_EMPTY_AUTHENTICATED_USERS_POLICY)
    else:
        #print('authenticated-users not empty')
        iptables_do_command('-t filter -A '+CHAIN_TO_INTERNET+' -m mark --mark 0x{:x}{} -j '+CHAIN_AUTHENTICATED, FW_MARK_AUTHENTICATED, markmask)
        iptables_do_command('-t filter -A '+CHAIN_AUTHENTICATED+' -m state --state RELATED,ESTABLISHED -j ACCEPT')
        _iptables_append_ruleset('filter',CHAIN_AUTHENTICATED,'authenticated-users')
        iptables_do_command('-t filter -A '+CHAIN_AUTHENTICATED+' -j REJECT --reject-with icmp-port-unreachable')

    if conf.is_empty_ruleset('preauthenticated-users'):
        iptables_do_command('-t filter -A ' + CHAIN_TO_INTERNET + ' -j {} ',
                            conf.DEFAULT_EMPTY_PREAUTHENTICATED_USERS_POLICY)
    else:
        #print('preauthenticated-users not empty')
        _iptables_append_ruleset('filter',CHAIN_TO_INTERNET,'preauthenticated-users')

    iptables_do_command('-t filter -A ' + CHAIN_TO_INTERNET + ' -j REJECT --reject-with icmp-port-unreachable')
    return 1


def iptables_fw_destroy():
    print('[INFO]\t\tDestroying our iptables entries')
    print('[INFO]\t\tDestroying chains in the MANGLE table')
    iptables_fw_destroy_mention('mangle', 'PREROUTING', CHAIN_TRUSTED)
    iptables_fw_destroy_mention('mangle', 'PREROUTING', CHAIN_BLOCKED)
    iptables_fw_destroy_mention('mangle', 'PREROUTING', CHAIN_ALLOWED)
    iptables_fw_destroy_mention('mangle', 'PREROUTING', CHAIN_OUTGOING)
    iptables_fw_destroy_mention('mangle', 'POSTROUTING', CHAIN_INCOMING)
    iptables_do_command('-t mangle -F ' + CHAIN_TRUSTED)
    iptables_do_command('-t mangle -F ' + CHAIN_BLOCKED)
    iptables_do_command('-t mangle -F ' + CHAIN_ALLOWED)
    iptables_do_command('-t mangle -F ' + CHAIN_OUTGOING)
    iptables_do_command('-t mangle -F ' + CHAIN_INCOMING)
    iptables_do_command('-t mangle -X ' + CHAIN_TRUSTED)
    iptables_do_command('-t mangle -X ' + CHAIN_BLOCKED)
    iptables_do_command('-t mangle -X ' + CHAIN_ALLOWED)
    iptables_do_command('-t mangle -X ' + CHAIN_OUTGOING)
    iptables_do_command('-t mangle -X ' + CHAIN_INCOMING)
    print('[INFO]\t\tDestroying chains in the NAT table')
    iptables_fw_destroy_mention('nat', 'PREROUTING', CHAIN_OUTGOING)
    iptables_do_command('-t nat -F ' + CHAIN_OUTGOING)
    iptables_do_command('-t nat -X ' + CHAIN_OUTGOING)
    print('[INFO]\t\tDestroying chains in the FILTER table')
    iptables_fw_destroy_mention('filter', 'INPUT', CHAIN_TO_ROUTER)
    iptables_fw_destroy_mention('filter', 'FORWARD', CHAIN_TO_INTERNET)
    iptables_do_command('-t filter -F ' + CHAIN_TO_ROUTER)
    iptables_do_command('-t filter -F ' + CHAIN_TO_INTERNET)
    iptables_do_command('-t filter -F ' + CHAIN_AUTHENTICATED)
    iptables_do_command('-t filter -F ' + CHAIN_TRUSTED)
    iptables_do_command('-t filter -F ' + CHAIN_TRUSTED_TO_ROUTER)
    iptables_do_command('-t filter -X ' + CHAIN_TO_ROUTER)
    iptables_do_command('-t filter -X ' + CHAIN_TO_INTERNET)
    iptables_do_command('-t filter -X ' + CHAIN_AUTHENTICATED)
    iptables_do_command('-t filter -X ' + CHAIN_TRUSTED)
    iptables_do_command('-t filter -X ' + CHAIN_TRUSTED_TO_ROUTER)
    return 1


def iptables_fw_destroy_mention(table, chain, mention):
    retval = -1
    print('[INFO]\t\tChecking all mention of {} from {}.{}'.format(mention, table, chain))
    command = 'iptables -t {} -L {} -n --line-numbers -v'.format(table, chain)
    p = os.popen(command)
    p.readline()
    p.readline()
    result = p.readlines()
    p.close()
    for line in result:
        if mention in line:
            print('[INFO]\t\tDeleting rule {} from {}.{} because it mentions {}'.format(line.split()[0], table, chain,
                                                                                        mention))
            iptables_do_command('-t {} -D {} {}', table, chain, line.split()[0])
            retval = 0
            break
    if (retval == 0):
        iptables_fw_destroy_mention(table, chain, mention)
    return retval


def iptables_fw_access(action, client):
    rc = 1
    if action == AUTH_AUTHENTICATED:
        print('Authenticating {} {}'.format(client.ip, client.mac))
        rc |= iptables_do_command(
            '-t mangle -A ' + CHAIN_OUTGOING + ' -s {} -m mac --mac-source {} -j MARK {} 0x{:x}{:x}',
            client.ip, client.mac, markop, client.idx + 10, conf.FW_MARK_AUTHENTICATED)
        rc |= iptables_do_command('-t mangle -A ' + CHAIN_INCOMING + ' -d {} -j MARK {} 0x{:x}{:x}', client.ip, markop,
                                  client.idx + 10, conf.FW_MARK_AUTHENTICATED)
        rc |= iptables_do_command('-t mangle -A ' + CHAIN_INCOMING + ' -d {} -j ACCEPT', client.ip)
    elif action == AUTH_DEAUTHENTICATED:
        print('Deauthenticating {} {}'.format(client.ip, client.mac))
        rc |= iptables_do_command(
            '-t mangle -D ' + CHAIN_OUTGOING + ' -s {} -m mac --mac-source {} -j MARK {} 0x{:x}{:x}',
            client.ip, client.mac, markop, client.idx + 10, conf.FW_MARK_AUTHENTICATED)
        rc |= iptables_do_command('-t mangle -D ' + CHAIN_INCOMING + ' -d {} -j MARK {} 0x{:x}{:x}', client.ip, markop,
                                  client.idx + 10, conf.FW_MARK_AUTHENTICATED)
        rc |= iptables_do_command('-t mangle -D ' + CHAIN_INCOMING + ' -d {} -j ACCEPT', client.ip)
    else:
        rc = 1

    return rc
