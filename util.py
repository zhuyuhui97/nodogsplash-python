import os

def get_ext_iface():
    routetable=open('/proc/net/route', 'r')
    lines=routetable.readlines
    routetable.close()
    for line in lines:
        splitted=line.split()
        device=splitted[0]
        gw=splitted[2]
        if (gw=='00000000'):
            #TODO DEBUG OUTPUT
            return device
    #TODO DEBUG OUTPUT
    return None

def arp_get_mac(ipaddr):
    p = os.popen('arp')
    p.readline()
    result = p.readlines()
    p.close()
    for line in result:
        if ipaddr in line:
            print("[INFO]\t\tFound MAC Address {} for {}".format(line.split()[2], ipaddr))
            return line.split()[2]

def mkdirs(path):
    # 去除首位空格
    path = path.strip()
    # 去除尾部 \ 符号
    path = path.rstrip("\\")
    # 判断路径是否存在
    # 存在     True
    # 不存在   False
    isExists = os.path.exists(path)
    # 判断结果
    if not isExists:
        # 创建目录操作函数
        os.makedirs(path)
        # 如果不存在则创建目录
        # print path + u' 创建成功'
        return True
    else:
        # 如果目录存在则不创建，并提示目录已存在
        # print path + u' 目录已存在'
        return False