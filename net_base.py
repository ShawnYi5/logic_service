import configparser
import copy
import json
import os
import re
import subprocess
import threading
import traceback

import logicService
import net_common
import xlogging

net_lock = threading.Lock()

_logger = xlogging.getLogger('net_base')

# define type info
_NET_TYPE_NAME_BOND = 'bond'
_NET_TYPE_NAME_PHY = 'phy'
_NET_TYPE_NAME_UNKNOWN = 'net name unknown'

# define error info
_NET_ERROR_NO_CFG_FILE = 'no cfg_file'
_NET_ERROR_NAME_UNKNOWN = _NET_TYPE_NAME_UNKNOWN

# 网卡驱动和网卡型号对应字典,驱动作为key
net_cardtype_driver_dict = dict()

reip = re.compile("^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
                  "\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
                  "\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
                  "\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$")
net_cfg_file_pre = "/etc/sysconfig/network-scripts/ifcfg-"
net_cfg_file_dir = "/etc/sysconfig/network-scripts"

net_cfg_file_origin_f = "/etc/aio/origin-net.config"
net_cfg_file_origin_s = "/usr/sbin/aio/logic_service/origin-net.config"
net_dns_cfg_file = "/etc/resolv.conf"
net_default_gateway_cfg_file = "/etc/sysconfig/network"
ifcfg_check_str_dict = {'inet ': 'ip4', 'netmask ': 'netmask', 'broadcast ': 'broadcast', 'inet6 ': 'ip6',
                        'ether ': 'mac', 'txqueuelen ': 'txqueuelen', 'RX packets ': 'rxpk', 'RX errors ': 'rxerr',
                        'TX packets ': 'txpk', 'TX errors ': 'txerr', 'bytes ': ''}
bond_mode_attr = {'adaptive load balancing': '5'}

# 网卡通用数据，默认值为空的字符串
net_card_attr_header = {'name': '', 'cfgfile': '', 'nettype': '', 'cardtype': '', 'state': '', 'link': '', 'ip4': '',
                        'ip6': '', 'netmask': '',
                        'broadcast': '', 'mac': '', 'txqueuelen': '', 'rxpk': '', 'rxbytes': '', 'rxerr': '',
                        'rxdrop': '', 'txpk': '', 'txbytes': '', 'txerr': '', 'txdrop': '', 'dhcp': '', 'gateway': '',
                        'speed': '', 'duplex': '', 'slavestate': '', 'mastername': ''}

net_card_attr_header_only_up = {'name': '', 'nettype': '', 'cardtype': '', 'state': '', 'link': '', 'ip4': '',
                                'netmask': '', 'mac': '',
                                'rxpk': '', 'rxbytes': '', 'txpk': '', 'txbytes': '', 'gateway': '', 'speed': '',
                                'mastername': ''}
# 虚拟网卡都有属性
bond_only_attr_header = {'bondmode': '', 'miistatus': '', 'miiinterval': ''}


# 网络数据类定义，包含网卡信息（嵌套字典，网卡名称作为keys），默认网关（字符串），网络dns（列表），以及一些设置和获取信息的方法定义。
# 其中设置方法仅模块内部调用，获取信息方法可模块外部调用
# 网卡信息字典示例：
# dict = {'card1':net_card_attr_header,'card2':net_card_attr_header},表示有两个网卡，网卡名称分别是card1，card2，网卡类型
# （物理网卡或虚拟网卡）可是用net_type_check方法判断，每个网卡都包含有name，ip4，mac等信息，这些信息定义在net_card_attr_header中
# net_only_attr_header定义了物理网卡独有属性，bond_only_attr_header定义了虚拟网卡独有属性。如果是物理网卡，其属性为net_card_attr_header
# 和net_only_attr_header之和，如果是虚拟网卡，其属性为net_card_attr_header和bond_only_attr_header之和
class NetCard(object):
    def __init__(self):
        self.__net_dict = dict()
        self.__default_gateway = ""
        self.__dns = list()

    # 清空网络数据，谨慎使用
    def init_all(self):
        self.__net_dict = dict()
        self.__default_gateway = ''
        self.__dns.clear()
        return

    # 从网卡名称（in_net_name）获取网卡类型
    # in_net_name：  字符串类型，网卡名称
    # 返回值：其它类型返回0，物理网卡类型返回1，虚拟网卡类型返回2
    def net_type_check(self, in_net_name):
        device_file = '/sys/class/net/' + in_net_name + '/device'
        if in_net_name.startswith('bond') and (':' not in in_net_name):
            return _NET_TYPE_NAME_BOND
        elif os.path.exists(device_file):
            return _NET_TYPE_NAME_PHY
        else:
            return _NET_TYPE_NAME_UNKNOWN

    # 检测网卡（in_net_name）是否已经记录
    # 当网卡已经记录，返回成功，当网卡未记录，如果add_new=‘yes’则新建记录并返回成功，如果add_new='no'则返回失败
    # in_net_name：  字符串类型，网卡名称
    # add_new:      字符串类型，表示是否新增记录
    # 返回值：成功返回0，失败返回负值
    def net_name_check(self, in_net_name, add_new='no'):
        if in_net_name in self.__net_dict:
            return 0, ''
        elif add_new == 'no':
            return -1, ''

        net_type_str = self.net_type_check(in_net_name)
        if net_type_str == _NET_TYPE_NAME_UNKNOWN:
            _logger.error("get a invalid net card {} name invalid".format(in_net_name))
            return -1, _NET_ERROR_NAME_UNKNOWN

        mfile = net_cfg_file_pre + in_net_name
        if os.path.isfile(mfile):
            if net_type_str == _NET_TYPE_NAME_BOND:
                self.__net_dict[in_net_name] = dict(net_card_attr_header, **bond_only_attr_header)
            else:
                self.__net_dict[in_net_name] = dict(net_card_attr_header)
            self.__net_dict[in_net_name]['name'] = in_net_name
            self.__net_dict[in_net_name]['cfgfile'] = mfile
            self.__net_dict[in_net_name]['nettype'] = net_type_str
            _logger.info("get a valid net card {},all is {}".format(in_net_name, len(self.__net_dict)))
        else:
            _logger.error("get a invalid net card {},cfg file {} not exist".format(in_net_name, mfile))
            return -1, _NET_ERROR_NO_CFG_FILE
        return 0, ''

    # 获取指定网卡信息
    # net_name：  字符串类型，网卡名称
    # 返回值：成功返回【0，网卡信息字典】，失败返回【-1，None】
    def net_get_with_name(self, net_name):
        if net_name in self.__net_dict:
            return 0, copy.deepcopy(self.__net_dict[net_name])
        return -1, None

    # 获取所有网络信息
    # 返回值：包含网卡信息字典，默认网关，dns的序列
    def net_get_all(self):
        return copy.deepcopy(self.__net_dict), self.__dns

    # 获取已记录网卡信息数目
    # 返回值：已记录网卡数目
    def net_get_card_num(self):
        return len(self.__net_dict)

    # 获取已记录网卡名称列表
    # 返回值：已记录网卡名称列表
    def net_get_name_list(self):
        return list(self.__net_dict.keys())

    # 获取指定网卡的指定数据项
    # in_net_name：  字符串类型，网卡名称
    # in_item：  字符串类型，网卡数据项名称
    # 返回值：成功返回【0，网卡数据项信息】，失败返回【-1，None】
    def net_get_item(self, in_net_name, in_item):
        if in_net_name not in self.__net_dict:
            _logger.error("do not have card {}".format(in_net_name))
            return -1, None

        if in_item not in self.__net_dict[in_net_name]:
            _logger.error("card {} do not have item {}".format(in_net_name, in_item))
            return -1, None
        return 0, self.__net_dict[in_net_name][in_item]

    # 获取默认网关
    def net_get_default_gateway(self):
        return self.__default_gateway

    # 获取dns信息
    # 返回：dns信息列表
    def net_get_dns(self):
        return self.__dns.copy()

    def net_card_clear_attr(self, in_net_name):
        if in_net_name in self.__net_dict:
            for key in self.__net_dict[in_net_name]:
                if key == 'name' or key == 'cfgfile' or key == 'nettype':
                    continue
                self.__net_dict[in_net_name][key] = ''
        return 0

    def net_set_item(self, in_net_name, in_item, in_value):
        if in_net_name not in self.__net_dict:
            _logger.error("do not have card {}".format(in_net_name))
            return -1

        if in_item not in self.__net_dict[in_net_name]:
            _logger.error("card {} do not have item {}".format(in_net_name, in_item))
            return -1

        self.__net_dict[in_net_name][in_item] = in_value
        _logger.info(
            "set card {} item {} to value {}".format(in_net_name, in_item, self.__net_dict[in_net_name][in_item]))
        return 0

    def net_set_default_gateway(self, in_gateway):
        self.__default_gateway = in_gateway
        return 0

    def net_set_dns(self, in_dns):
        if in_dns not in self.__dns:
            _logger.info("add dns {}".format(in_dns))
            self.__dns.append(in_dns)
        return 0

    def net_print_info_one(self, in_net_name):
        for keys in self.__net_dict[in_net_name]:
            _logger.debug("key {} value {}".format(keys, self.__net_dict[in_net_name][keys]))

    def net_print_info_all(self):
        for name in self.__net_dict:
            self.net_print_info_one(name)
            _logger.debug("\n\n")

        for i in range(len(self.__dns)):
            _logger.debug("dns is {}".format(self.__dns[i]))

        _logger.debug("default gateway is {}".format(self.__default_gateway))


# 网络信息全局变量
net_card_info = NetCard()


def net_get_dns_server():
    dnsdict = {'nameserver': []}
    net_common.get_itemdict_from_file(net_dns_cfg_file, dnsdict)
    keylist = list(dnsdict.keys())
    mlist = dnsdict[keylist[0]]
    mlen = len(mlist)
    if mlen <= 0:
        _logger.info("get dns failed have no ret")
        return -1

    for i in range(mlen):
        _logger.info("get dns return {}".format(mlist[i]))
        net_card_info.net_set_dns(mlist[i])
    return 0


def net_get_dhcp_slave_state_from_name(in_name):
    cfgfile = net_card_info.net_get_item(in_name, "cfgfile")
    if cfgfile[0] != 0:
        return
    in_item = ["BOOTPROTO=", "MASTER=", "SLAVE=", "GATEWAY="]
    set_item = ['dhcp', 'mastername', 'slavestate', 'gateway']
    mdict = dict.fromkeys(in_item)
    net_common.get_itemdict_from_file(cfgfile[1], mdict)

    for i in range(len(mdict)):
        mlist = mdict[in_item[i]]
        if mlist is None:
            _logger.error("get {} failed have no ret".format(set_item[i]))
            continue
        mlen = len(mlist)
        if mlen != 1:
            _logger.error("get {} failed ret list len {}".format(set_item[i], mlen))
        else:
            _logger.info("get {} success ret value {}".format(set_item[i], mlist[0]))
            net_card_info.net_set_item(in_name, set_item[i], mlist[0])

    return


def net_get_dhcp_salve_state_all():
    name_list = net_card_info.net_get_name_list()
    for i in range(len(name_list)):
        net_get_dhcp_slave_state_from_name(name_list[i])
    return


def net_get_speed_one(in_name):
    cmdline = 'ethtool ' + in_name
    retval = net_common.get_info_from_syscmd(cmdline)
    if retval[0] == 0:
        mstr = retval[1]
        mdict = {'Speed:': [], 'Duplex:': []}
        net_common.get_itemdict_from_str(mstr, mdict)
        net_card_info.net_set_item(in_name, 'speed', mdict['Speed:'][0] if len(mdict['Speed:']) else '--')
        net_card_info.net_set_item(in_name, 'duplex', mdict['Duplex:'][0] if len(mdict['Duplex:']) else '--')
    return


def net_get_speed_all():
    name_list = net_card_info.net_get_name_list()
    for i in range(len(name_list)):
        net_get_speed_one(name_list[i])
    return


def net_create_cfg_file(in_net_name):
    cfg_new_file = net_cfg_file_pre + in_net_name
    cfg_origin_file = ''
    file_str = ''
    for fn in os.listdir(net_cfg_file_dir):
        # print("fn is {}".format(fn))
        if os.path.isfile(os.path.join(net_cfg_file_dir, fn)) and fn.startswith('ifcfg-eno'):
            cfg_origin_file = os.path.join(net_cfg_file_dir, fn)
            _logger.debug("get an origin net cfg file {}".format(cfg_origin_file))
            break
    if cfg_origin_file != '':
        retval = net_common.get_info_from_file(cfg_origin_file)
        if retval[0] == 0:
            file_str = retval[1]

    if file_str == '':
        file_str = 'TYPE=Ethernet\n' \
                   'BOOTPROTO=static\n' \
                   'DEFROUTE=yes\n' \
                   'PEERDNS=yes\n' \
                   'PEERROUTES=yes\n' \
                   'IPV4_FAILURE_FATAL=no\n' \
                   'IPV6INIT=yes\n' \
                   'IPV6_AUTOCONF=yes\n' \
                   'IPV6_DEFROUTE=yes\n' \
                   'IPV6_PEERDNS=yes\n' \
                   'IPV6_PEERROUTES=yes\n' \
                   'IPV6_FAILURE_FATAL=no\n' \
                   'ONBOOT=yes\n'
        _logger.debug("set file str as init")
    _logger.debug("get file str \n{}".format(file_str))

    mdict = {'IPADDR': ['d', ''],
             'NETMASK': ['d', ''],
             'GATEWAY': ['d', ''],
             'DNS': ['d', ''],
             'UUID': ['d', ''],
             'MASTER': ['d', ''],
             'SLAVE': ['d', ''],
             'BOOTPROTO': ['ma', '=' + 'static'],
             'ONBOOT': ['ma', '=yes'],
             'NAME': ['ma', '=' + in_net_name],
             'DEVICE': ['ma', '=' + in_net_name],

             }
    retval = net_common.set_itemdict_in_str(file_str, mdict)
    file_str = retval[1]
    _logger.debug("get modify file str \n{}".format(file_str))

    retval = net_common.set_info_to_file(cfg_new_file, file_str, 'w')
    if retval != 0:
        _logger.error("set info to file faild {}".format(cfg_new_file))
        return -1
    _logger.debug("create new net cfg file success {}".format(cfg_new_file))
    return 0


def net_get_card_info_from_line(line_str, in_name_str):
    _logger.debug('line str {}'.format(line_str))
    line_str = line_str.strip()
    line_str = line_str.strip("\n")
    if len(line_str) <= 0:
        return
    rx_or_tx = ''
    if line_str.startswith('RX '):
        rx_or_tx = 'RX'
    elif line_str.startswith('TX '):
        rx_or_tx = 'TX'
    mlist = line_str.split("  ")

    list_len = len(mlist)
    for i in range(list_len):
        _logger.debug("mstr is  {}".format(mlist[i]))
        mstr = mlist[i]
        for check_key in ifcfg_check_str_dict:
            if mstr.startswith(check_key):
                key_len = len(check_key)
                value_str = mstr[key_len:].strip()
                net_item = ''
                if check_key == 'bytes ':
                    if rx_or_tx == 'RX':
                        net_item = 'rxbytes'
                    elif rx_or_tx == 'TX':
                        net_item = 'txbytes'
                else:
                    net_item = ifcfg_check_str_dict[check_key]
                net_card_info.net_set_item(in_name_str, net_item, value_str)
                break
            else:
                pass
    return


def net_get_card_info_from_str(net_str):
    # get net card name
    _logger.debug("net str is {}".format(net_str))
    name_str = ''
    mpos = net_str.find(": flags=")
    if mpos > 0:
        name_str = net_str[:mpos].strip().strip('\n')

    # check name is valid
    retval = net_card_info.net_name_check(name_str, 'yes')
    if retval[0] != 0:
        if retval[1] == _NET_ERROR_NO_CFG_FILE:
            retval = net_create_cfg_file(name_str)
            if retval != 0:
                _logger.error("create net cfg file failed,net name {}".format(name_str))
                return -1
            else:
                net_card_info.net_name_check(name_str, 'yes')
        else:
            _logger.error("get an invalid net card name {}".format(name_str))
            return -1

    net_card_info.net_card_clear_attr(name_str)

    # get net card state (up or down)
    mpos = net_str.find("UP")
    if mpos > 0:
        state_str = "up"
    else:
        state_str = "down"

    net_card_info.net_set_item(name_str, 'state', state_str)

    # get net card link state (ok or fail)
    mpos = net_str.find("RUNNING")
    if mpos > 0:
        state_str = "ok"
    else:
        state_str = "fail"

    net_card_info.net_set_item(name_str, 'link', state_str)

    # then set net card item
    mlist = net_str.split("\n")
    list_len = len(mlist)
    for i in range(list_len):
        net_get_card_info_from_line(mlist.pop(0), name_str)
    return 0


def net_get_card_info_from_list(list_str):
    list_len = len(list_str)
    if list_len <= 0:
        _logger.error("list_str len invalid value is {}".format(list_len))
        return -1
    # list_len = 1
    for i in range(list_len):
        net_get_card_info_from_str(list_str.pop(0))

    return 0


def net_get_cardtype_driver():
    global net_cardtype_driver_dict
    net_cardtype_driver_dict.clear()
    cmdline = 'lspci -v'
    retval = net_common.get_info_from_syscmd(cmdline)
    if retval[0] != 0:
        _logger.error("get_info_from_syscmd failed,cmd {},retval {}".format(cmdline, retval[0]))
        return -1
    card_check_str = 'Ethernet controller: '
    driver_check_str = 'Kernel driver in use: '

    mlist = retval[1].split("\n\n")
    mlist_len = len(mlist)
    for i in range(mlist_len):
        mstr = mlist[i]
        mmlist = mstr.split("\n")
        mmlist_len = len(mmlist)
        cardtype_str = ''
        for j in range(mmlist_len):
            mmstr = mmlist[j]
            if len(cardtype_str) <= 0:
                mindex = mmstr.find(card_check_str)
                if mindex > 0:
                    cardtype_str = mmstr[mindex + len(card_check_str):]
                    _logger.debug('get a cardtype {}'.format(cardtype_str))
            else:
                mindex = mmstr.find(driver_check_str)
                if mindex > 0:
                    driver_str = mmstr[mindex + len(driver_check_str):]
                    _logger.debug('get a driver_str {}'.format(driver_str))
                    if driver_str not in net_cardtype_driver_dict:
                        net_cardtype_driver_dict[driver_str] = cardtype_str

    for key in net_cardtype_driver_dict:
        _logger.debug('cardtype_driver key:{},value:{}'.format(key, net_cardtype_driver_dict[key]))
    return 0


def net_get_cardtype():
    global net_cardtype_driver_dict
    retval = net_get_cardtype_driver()
    if retval != 0:
        _logger.error('net_get_cardtype_driver failed')
        return -1
    name_list = net_card_info.net_get_name_list()
    mlen = len(name_list)
    for i in range(mlen):
        mname = name_list[i]
        if net_card_info.net_type_check(mname) != _NET_TYPE_NAME_PHY:
            continue
        cmdline = 'ethtool -i ' + mname + " | grep driver: | awk '{print$2}'"
        retval = net_common.get_info_from_syscmd(cmdline)
        if retval[0] != 0:
            _logger.error('cmd {} failed'.format(cmdline))
        else:
            driver_name = retval[1].strip(' ').strip('\n')
            if driver_name in net_cardtype_driver_dict:
                net_card_info.net_set_item(mname, 'cardtype', net_cardtype_driver_dict[driver_name])
            else:
                _logger.error('invalid driver_name {}'.format(driver_name))
    return 0


def net_get_default_gateway_info():
    strcmd = "route"
    _logger.info("start get default gateway with cmd '{}'".format(strcmd))
    p = subprocess.Popen(strcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    retval = p.wait()
    _logger.info("subprocess ret value {}".format(retval))

    for line in p.stdout.readlines():
        mstr = line.decode('utf-8')
        if mstr.startswith("default"):
            mlist = mstr.split(" ")
            mlist.pop(0)
            for i in range(len(mlist)):
                if len(mlist[i]) > 4:
                    _logger.info("get defalt gateway {}".format(mlist[i]))
                    net_card_info.net_set_default_gateway(mlist[i])
                    return 0

    return -1


def net_get_bond_only_attr_one(in_name):
    cmd_line = 'cat /proc/net/bonding/' + in_name
    retval = net_common.get_info_from_syscmd(cmd_line)
    if retval[0] != 0:
        _logger.error("get_info_from_syscmd failed,cmd {},retval {}".format(cmd_line, retval[0]))
        return -1
    mstr = retval[1]
    mdict = {'Bonding Mode:': ['bondmode'], 'Currently Active Slave:': ['curslave'],
             'MII Status:': ['miistatus'], 'MII Polling Interval (ms):': ['miiinterval']}
    net_common.get_itemdict_from_str(mstr, mdict)
    for key in mdict:
        mlist = mdict[key]
        mlen = len(mlist)
        if mlist[0] not in bond_only_attr_header:
            continue
        if mlen >= 2:
            if mlist[0] == 'bondmode':
                if mlist[1] in bond_mode_attr:
                    mstr = bond_mode_attr[mlist[1]]
                    mlist[1] = mstr
                else:
                    _logger.error("get inavlid bond mode {}".format(mlist[1]))
                    continue
            net_card_info.net_set_item(in_name, mlist[0], mlist[1])
    return 0


def net_get_bond_only_attr():
    name_list = net_card_info.net_get_name_list()
    for i in range(len(name_list)):
        mstr = name_list[i]
        if mstr.startswith('bond'):
            net_get_bond_only_attr_one(mstr)
    return 0


# 检测网卡绑定驱动是否已安装，如驱动异常则网卡绑定功能不能使用
# 返回值： 正常返回0，异常返回负值
def net_bond_driver_check():
    net_common.get_info_from_syscmd('modprobe bonding')
    strcmd = "lsmod | grep bonding"
    _logger.info("start check bond driver with cmd '{}'".format(strcmd))
    p = subprocess.Popen(strcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    retval = p.wait()
    _logger.info("subprocess ret value {}".format(retval))

    for line in p.stdout.readlines():
        _logger.info("chech bonding driver success,cmd '{}',retval {}".format(strcmd, line))
        return 0

    _logger.error("chech bonding driver failed,with cmd '{}' and no return".format(strcmd))
    return -1


# 重新获取网络信息（以前信息会被全部清除）
# 返回值：成功返回0，失败返回负值
def net_init_info():
    list_str = list()
    strcmd = "ifconfig -a"
    _logger.info("start get net info with cmd '{}'".format(strcmd))
    p = subprocess.Popen(strcmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    retval = p.wait()
    _logger.info("subprocess ret value {}".format(retval))
    # ret_str = p.stdout.read().decode();
    # print(ret_str)

    mstr = ""
    for line in p.stdout.readlines():
        line_len = len(line)
        # print(line_len)
        if line_len <= 2:
            if len(mstr) <= 2:
                continue
            # logger.info("get new net card info {}".format(mstr))
            list_str.append(mstr)
            mstr = ""
        else:
            mstr += line.decode('utf-8')
    if len(list_str) <= 0:
        _logger.error("cmd {} have no valid retrun".format(strcmd))
        return -1
    else:
        net_card_info.init_all()
        retval = net_get_card_info_from_list(list_str)
        if retval != 0:
            _logger.error("list_str have no valid card info,get_net_card_info_from_list failed")
            return -1

        net_get_dhcp_salve_state_all()
        net_get_dns_server()

        net_get_default_gateway_info()
        net_get_speed_all()
        net_get_bond_only_attr()
        net_get_cardtype()
        net_card_info.net_print_info_all()
    return 0


def net_set_cfgfile(in_net_name, in_dict):
    retval = net_card_info.net_name_check(in_net_name, 'no')
    if retval[0] != 0:
        _logger.error("set cfg info failed,name {} invalid".format(in_net_name))
        return -1

    retval = net_card_info.net_get_item(in_net_name, 'cfgfile')
    if retval[0] != 0 or retval[1] is None or len(retval[1]) < 2:
        _logger.error("get {} cfg file failed,ret value {}".format(in_net_name, retval[0]))
        return -1

    file_name = retval[1]
    # file_name = in_net_name

    retval = net_common.set_itemdict_in_file(file_name, in_dict)
    if retval != 0:
        _logger.error("set_itemdict_in_file {} failed,ret value {}".format(in_net_name, retval))
        return -1

    return 0


# 设置指定网卡网络信息（ip，netmask，gateway），调用后会自动将网卡ip获取方式改成静态ip，
# 此方法只修改了系统配置文件，要使配置有效需调用方法net_restart_network，再调用net_init_info
# 更新全局变量net_card_info
# in_net_name：  网卡名称
# in_ip：        字符串类型，ip
# in_net_mask：  字符串类型，net mask
# in_gateway：   字符串类型，gate way
# 返回值：  成功返回0，失败返回负值
def net_set_cfgfile_ipinfo(in_net_name, in_ip, in_net_mask, in_gateway):
    mdict = {'IPADDR': ['ma', '=' + in_ip], 'NETMASK': ['ma', '=' + in_net_mask],
             'GATEWAY': ['ma', '=' + in_gateway], 'BOOTPROTO': ['ma', '=static']}
    retval = net_set_cfgfile(in_net_name, mdict)
    if retval != 0:
        _logger.error("net_set_cfgfile failed,ret value is {}".format(retval))
        return -1
    return 0


# 设置指定网卡ip获取方式
# 此方法只修改了系统配置文件，要使配置有效需调用方法net_restart_network，再调用net_init_info
# 更新全局变量net_card_info
# in_net_name：  字符串类型，网卡名称
# dhcp：         字符串类型，ip获取方式,只能是‘dhcp’，‘static’或‘none’
# 返回值：  成功返回0，失败返回负值
def net_set_cfgfile_dhcp(in_net_name, dhcp):
    if dhcp != 'dhcp' and dhcp != 'none' and dhcp != 'static':
        _logger.error("input dhcp {} invalid".format(dhcp))
        return -1
    mdict = {'BOOTPROTO': ['ma', '=' + dhcp]}
    retval = net_set_cfgfile(in_net_name, mdict)
    if retval != 0:
        _logger.error("net_set_cfgfile failed,ret value is {}".format(retval))
        return -1
    return 0


# 设置物理网卡（in_net_name）加入（或者退出）指定聚合虚拟网卡（master_name），
# 此方法只修改了系统配置文件，要使配置有效需调用方法net_restart_network，再调用net_init_info
# 更新全局变量net_card_info
# in_net_name：  字符串类型，物理网卡名称
# master_name：  字符串类型，虚拟网卡名称，当master_name为空字符串时表示指定物理网卡将退出聚合虚拟网卡
# 返回值：  成功返回0，失败返回负值
def net_set_cfgfile_master(in_net_name, master_name):
    if master_name == '':
        mdict = {'MASTER': ['d', '=' + master_name], 'SLAVE': ['d', '=yes']}
    else:
        retval = net_card_info.net_name_check(master_name)
        if retval[0] != 0:
            _logger.error("master name {} not invalid".format(master_name))
            return -1
        mdict = {'MASTER': ['ma', '=' + master_name], 'SLAVE': ['ma', '=yes']}
    retval = net_set_cfgfile(in_net_name, mdict)
    if retval != 0:
        _logger.error("net_set_cfgfile failed,ret value is {}".format(retval))
        return -1

    return 0


# 设置虚拟网卡模式，
# 此方法只修改了系统配置文件，要使配置有效需调用方法net_restart_network，再调用net_init_info
# 更新全局变量net_card_info
# in_net_name：  字符串类型，网卡名称
# in_opt：   字符串类型，虚拟网卡模式参数，例如：‘mode=6,miimon=100’表示虚拟网卡工作在模式6，链路检测时间为100毫秒，目前只支持这两
#            个参数设置
# 返回值：  成功返回0，失败返回负值
def net_set_cfgfile_bond_opt(in_net_name, in_opt):
    mdict = {'BONDING_OPTS': ['ma', '=' + '"' + 'mode=6 ' + in_opt + '"']}
    retval = net_set_cfgfile(in_net_name, mdict)
    if retval != 0:
        _logger.error("net_set_cfgfile failed,ret value is {}".format(retval))
        return -1
    return 0


# 设置网络dns信息
# 此方法只修改了系统配置文件，要使配置有效需调用方法net_restart_network，再调用net_init_info
# 更新全局变量net_card_info
# dhcp：         字符串类型，ip获取方式,只能是‘dhcp’，‘static’或‘none’
# 返回值：  成功返回0，失败返回负值
def net_set_dns(in_dns_list):
    _logger.info("net start set dns {}".format(in_dns_list))
    list_len = len(in_dns_list)
    if list_len <= 0:
        _logger.warning('dns list is empty, start clean nameserver')
        net_common.get_info_from_syscmd("sed -i /nameserver/d /etc/resolv.conf")
    else:
        mstr = ''
        for i in range(list_len):
            if i > 0:
                mstr += 'nameserver '
            mstr += in_dns_list[i] + '\n'
        mdict = {'nameserver ': ['ca', mstr]}
        retval = net_common.set_itemdict_in_file(net_dns_cfg_file, mdict)
        if retval != 0:
            _logger.error("net set dns failedret value is {}".format(retval))
            return -1
    return 0


# 设置网络默认网关
# 此方法只修改了系统配置文件，要使配置有效需调用方法net_restart_network，再调用net_init_info
# 更新全局变量net_card_info
# in_gateway：   字符串类型，网关数据
# 返回值：  成功返回0，失败返回负值
def net_set_default_gateway(in_gateway):
    mdict = {'GATEWAY ': ['ma', '=' + in_gateway]}
    retval = net_common.set_itemdict_in_file(net_default_gateway_cfg_file, mdict)
    if retval != 0:
        _logger.error("net set deafult gateway failed,ret value is {}".format(retval))
        return -1
    return 0


def net_del_not_exist_cfg_file():
    for fn in os.listdir(net_cfg_file_dir):
        if os.path.isfile(os.path.join(net_cfg_file_dir, fn)) and fn.startswith('ifcfg-eno'):
            for fn_eno in os.listdir('/sys/class/net'):
                if fn == 'ifcfg-' + fn_eno:
                    break
                if fn.split(':')[0] == 'ifcfg-' + fn_eno:
                    break
            else:
                cfg_origin_file = os.path.join(net_cfg_file_dir, fn)
                os.remove(cfg_origin_file)
                _logger.debug("del not exist interface net cfg file {}".format(cfg_origin_file))
    return 0


def net_restart_service():
    try:
        logicService._g.getKtsPrx().refreshNetwork()
    except Exception as e:
        _logger.error("net_restart_service getKtsPrx refreshNetwork failed {}".format(e), exc_info=True)

    try:
        logicService._g.getBoxPrx().refreshNetwork()
    except Exception as e:
        _logger.error("net_restart_service getBoxPrx refreshNetwork failed {}".format(e), exc_info=True)

    return 0


# 重启网络服务，此方法会重启所有网卡，重启后网卡数据可能会改变，需调用net_init_info更新全局变量net_card_info
# 返回值：  成功返回0，失败返回负值
def net_restart_network():
    # ifdown all
    name_list = net_card_info.net_get_name_list()
    cmd_line = ''

    # ifdown phy interface
    _logger.debug("name list {}".format(name_list))
    for i in range(len(name_list)):
        if net_card_info.net_type_check(name_list[i]) == _NET_TYPE_NAME_PHY:
            cmd_line += 'ifdown ' + name_list[i] + ';'
    net_common.get_info_from_syscmd(cmd_line)

    # del not exist phy interface cfg file
    net_del_not_exist_cfg_file()

    # restart net
    cmd_line = '/etc/init.d/network restart'
    retval = net_common.get_info_from_syscmd(cmd_line)
    if retval[0] != 0:
        _logger.error("get info from sys cmd {} failed,ret value {}".format(cmd_line, retval))
        net_common.get_info_from_syscmd('journalctl -xe', 2)
        return -1
    retval = net_restart_service()
    if retval != 0:
        _logger.error("net_restart_service failed ret {}".format(retval))
        return -1
    return 0


# set all net info
# in_net_infos:json str,format like test_list
def net_set_info(in_net_infos):
    # test code
    # test_list = [['interface',['eno16777984'],['172.16.6.165','255.255.248.0','']],
    #              ['interface',['eno33557248','eno50336512','eno67115776'],['172.16.6.167','255.255.248.0','172.16.1.1']],
    #              ['interface',['eno33557248'],['172.16.6.168','255.255.248.0','']],
    #              ['dns',['172.16.1.2','172.16.1.3']]
    #              ]
    # in_net_infos = json.dumps(test_list)
    # test code end
    with net_lock:
        _logger.debug("net_set_info json info {}".format(in_net_infos))
        in_net_list = json.loads(in_net_infos)
        _logger.debug("net set info list {}".format(in_net_list))
        if len(in_net_list[0][2]) != 3 or in_net_list[0][0] != 'interface' or len(in_net_list[0][1]) <= 0:
            xlogging.raise_system_error("net set failed", "net set failed", -1, _logger)
        bond_index_list = list()
        phy_index_list = list()
        dns_list = list()
        cfg_files = list()
        for i in range(len(in_net_list)):
            if in_net_list[i][0] == 'interface':
                if len(in_net_list[i][1]) > 1:
                    bond_index_list.append(i)
                    _logger.debug("interface {},net info {}".format(in_net_list[i][1], in_net_list[i][2]))
                else:
                    phy_index_list.append(i)
                    _logger.debug("phy adapter {},net info {}".format(in_net_list[i][1], in_net_list[i][2]))
            elif in_net_list[i][0] == 'dns':
                dns_list = in_net_list[i][1]
            else:
                _logger.error("invalid flag {}".format(in_net_list[i][0]))

        bond_list_len = len(bond_index_list)
        phy_list_len = len(phy_index_list)
        _logger.debug("in_net_list len {} bond_list_len {} phy_list_len {} dns list {}".format(len(in_net_list),
                                                                                               bond_list_len,
                                                                                               phy_list_len, dns_list))
        # set bond driver info
        cmd_info = 'rmmod bonding;rm -rf /etc/sysconfig/network-scripts/ifcfg-bond*'
        net_common.get_info_from_syscmd(cmd_info)

        net_common.get_info_from_syscmd(cmd_info)
        if bond_list_len > 0:
            cfg_file = '/etc/modprobe.d/bonding.conf'
            cfg_files.append(cfg_file)
            bond_cfg_str = 'alias bond0 bonding\noptions bonding mode=6 miimon=200 max_bonds=' + str(
                bond_list_len) + '\n'
            retval = net_common.set_info_to_file(cfg_file, bond_cfg_str, 'w')
            if retval != 0:
                _logger.error("set cfg file {} failed".format(cfg_file))
                xlogging.raise_system_error("net set failed", "net set failed at set bond driver info", -2, _logger)
            cmd_info = 'modprobe bonding'
            net_common.get_info_from_syscmd(cmd_info)

        for i in range(bond_list_len):
            cfg_file = '/etc/sysconfig/network-scripts/ifcfg-bond' + str(i)
            cfg_files.append(cfg_file)
            file_str = 'ONBOOT=yes\n' \
                       'BOOTPROTO=static\n' \
                       'USERCTL=no\n'
            file_str += 'DEVICE=bond' + str(i) + '\n'
            file_str += 'IPADDR=' + in_net_list[bond_index_list[i]][2][0] + '\n'
            file_str += 'NETMASK=' + in_net_list[bond_index_list[i]][2][1] + '\n'
            file_str += 'GATEWAY=' + in_net_list[bond_index_list[i]][2][2] + '\n'
            retval = net_common.set_info_to_file(cfg_file, file_str, 'w')
            if retval != 0:
                _logger.error("set cfg file {} failed,info is \n{}".format(cfg_file, file_str))
                xlogging.raise_system_error("net set failed", "net set failed at set bond cfg file", -3, _logger)
            # 设置虚拟网卡 设备名 bond0:0 bond0:1 ...
            if len(in_net_list[bond_index_list[i]]) > 3:
                for k in range(len(in_net_list[bond_index_list[i]][3])):
                    cfg_file = '/etc/sysconfig/network-scripts/ifcfg-bond' + str(i) + ':' + str(k)
                    cfg_files.append(cfg_file)
                    ip_and_mask = in_net_list[bond_index_list[i]][3][k].split('/')
                    file_str = 'ONBOOT=yes\n' \
                               'BOOTPROTO=static\n' \
                               'USERCTL=no\n'
                    file_str += 'DEVICE=bond' + str(i) + ':' + str(k) + '\n'
                    file_str += 'IPADDR=' + ip_and_mask[0] + '\n'
                    file_str += 'NETMASK=' + ip_and_mask[1] + '\n'
                    retval = net_common.set_info_to_file(cfg_file, file_str, 'w')
                    if retval != 0:
                        _logger.error("set cfg file {} failed,info is \n{}".format(cfg_file, file_str))
                        xlogging.raise_system_error("net set failed", "net set failed at set bond cfg file", -3,
                                                    _logger)
            for j in range(len(in_net_list[bond_index_list[i]][1])):
                cfg_file = '/etc/sysconfig/network-scripts/ifcfg-' + in_net_list[bond_index_list[i]][1][j]
                cfg_files.append(cfg_file)
                mdict = {'SLAVE': ['ma', '=yes'], 'MASTER': ['ma', '=bond' + str(i)]}
                retval = net_common.set_itemdict_in_file(cfg_file, mdict)
                if retval != 0:
                    _logger.error("set file {} failed,ret value is {}".format(cfg_file, retval))
                    xlogging.raise_system_error("net set failed", "net set failed at set bond phy adapter cfg file", -4,
                                                _logger)

        cmd_info = 'rm -rf /etc/sysconfig/network-scripts/ifcfg-[^bond]*:*'
        net_common.get_info_from_syscmd(cmd_info)

        for i in range(phy_list_len):
            cfg_file = '/etc/sysconfig/network-scripts/ifcfg-' + in_net_list[phy_index_list[i]][1][0]
            cfg_files.append(cfg_file)
            mdict = {'SLAVE': ['d', ''], 'MASTER': ['d', ''], 'BOOTPROTO': ['ma', '=static'], 'ONBOOT': ['ma', '=yes'],
                     'IPADDR': ['ma', '=' + in_net_list[phy_index_list[i]][2][0]],
                     'NETMASK': ['ma', '=' + in_net_list[phy_index_list[i]][2][1]],
                     'GATEWAY': ['ma', '=' + in_net_list[phy_index_list[i]][2][2]]}
            retval = net_common.set_itemdict_in_file(cfg_file, mdict)
            if retval != 0:
                _logger.error("set file {} failed,ret value is {}".format(cfg_file, retval))
                xlogging.raise_system_error("net set failed", "net set failed at set phy adapter cfg file", -5, _logger)
            # 设置虚拟网卡
            if len(in_net_list[phy_index_list[i]]) > 3:
                for k in range(len(in_net_list[phy_index_list[i]][3])):
                    cfg_file = '/etc/sysconfig/network-scripts/ifcfg-' + in_net_list[phy_index_list[i]][1][
                        0] + ':' + str(k)
                    cfg_files.append(cfg_file)
                    ip_and_mask = in_net_list[phy_index_list[i]][3][k].split('/')
                    file_str = 'ONBOOT=yes\n' \
                               'BOOTPROTO=static\n' \
                               'USERCTL=no\n'
                    file_str += 'DEVICE=' + in_net_list[phy_index_list[i]][1][0] + ':' + str(k) + '\n'
                    file_str += 'IPADDR=' + ip_and_mask[0] + '\n'
                    file_str += 'NETMASK=' + ip_and_mask[1] + '\n'
                    retval = net_common.set_info_to_file(cfg_file, file_str, 'w')
                    if retval != 0:
                        _logger.error("set cfg file {} failed,info is \n{}".format(cfg_file, file_str))
                        xlogging.raise_system_error("net set failed", "net set failed at set bond cfg file", -3,
                                                    _logger)

        # clean ifcfg begin
        ifcfg_dir_path = '/etc/sysconfig/network-scripts'
        ifcfg_full_path_prefix = ifcfg_dir_path + '/ifcfg-'
        for file_full_name in os.listdir(ifcfg_dir_path):
            file_full_path = os.path.join(ifcfg_dir_path, file_full_name)
            if (os.path.isfile(file_full_path)) and (file_full_path.startswith(ifcfg_full_path_prefix)) and (
                    file_full_path not in cfg_files):
                _logger.warning(r'will remove unnecessary ifcfg : {}'.format(file_full_path))
                os.remove(file_full_path)
        # clean ifcfg end

        retval = net_set_dns(dns_list)
        if retval != 0:
            _logger.error("set dns str {} failed,ret value is {}".format(dns_list, retval))
            xlogging.raise_system_error("net set failed", "net set failed at set dns cfg file", -6, _logger)

        retval = net_common.get_info_from_syscmd("cat /etc/resolv.conf")
        if retval[0] == 0:
            _logger.info("after set dns is \n{}".format(retval[1]))
        else:
            _logger.error("read dns cfg file failed")

        retval = net_restart_network()
        if retval != 0:
            _logger.error("restart_network failed,ret value is {}".format(retval))
            xlogging.raise_system_error("net set failed", "net set failed at restart network", -7, _logger)
        return 0


# get all net info,return json str
def net_get_info():
    with net_lock:
        net_init_info()
        minfo = net_card_info.net_get_all()
        mdict = minfo[0]
        new_dict = dict.fromkeys(mdict.keys())
        for key1 in new_dict:
            new_dict[key1] = copy.deepcopy(net_card_attr_header_only_up)
            for key2 in new_dict[key1]:
                if key2 in mdict[key1]:
                    new_dict[key1][key2] = mdict[key1][key2]
                else:
                    _logger.error("key1 {} get invalid key2 {}".format(key1, key2))

        mjson = json.dumps((new_dict, minfo[1]))
        mjson = _get_virtual_ip_info_add_to(mjson)
        _logger.debug("net_get_info json info {}".format(mjson))
        return mjson


# 获取虚拟设备 eno1673131:0 ...信息
def _get_virtual_ip_info_add_to(jsonstr):
    jsonobj = json.loads(jsonstr)
    for element in jsonobj:
        if isinstance(element, list):
            continue
        for name, adapter in element.items():
            if (adapter['nettype'] == 'phy' and adapter['mastername'] == '') or (adapter['nettype'] == 'bond'):
                adapter['subipset'] = get_adapter_son_info(name)
    return json.dumps(jsonobj)


def get_adapter_son_info(net_name):
    subipset = list()
    allfile = os.listdir(net_cfg_file_dir)
    net_son = list(filter(lambda x: x.startswith('ifcfg-' + net_name) and ':' in x, allfile))
    for filename in net_son:
        with open(os.path.join(net_cfg_file_dir, filename), 'r') as p:
            content = p.readlines()
            _logger.debug(content)
            ipsetinfo = ''
            for line in content:
                if line.startswith('IPADDR'):
                    ipsetinfo = line.split('=')[1].strip()
                if line.startswith('NETMASK'):
                    ipsetinfo += '/' + line.split('=')[1].strip()
        _logger.debug(ipsetinfo)
        if ipsetinfo and check_ip_info(ipsetinfo):
            subipset.append(ipsetinfo)
    return subipset


def check_ip_info(ipstr):
    ip_and_mask = ipstr.split('/')
    if reip.match(ip_and_mask[0]) and reip.match(ip_and_mask[1]):
        return True
    return False


def net_init():
    retval = net_bond_driver_check()
    if retval != 0:
        _logger.error("net_bond_driver_check failed,ret value {}".format(retval))
        return -1
    net_init_info()
    return 0


def net_origin_init():
    # load bonding driver
    # need run cmd in aio_updata.sh
    # systemctl stop NetworkManager
    # systemctl disable NetworkManager
    # yum install net-tools
    mcfg_file = ''
    if os.path.isfile(net_cfg_file_origin_f):
        mcfg_file = net_cfg_file_origin_f
    elif os.path.isfile(net_cfg_file_origin_s):
        mcfg_file = net_cfg_file_origin_s
    else:
        xlogging.raise_system_error('get orgin net info failed', 'cfg file not exist', '-1', _logger)
    cf = configparser.ConfigParser()
    origin_ip = ''
    origin_netmask = ''
    origin_gateway = ''
    origin_dns = ''
    try:
        cf.read(mcfg_file)
        origin_ip = cf.get('net_infos', 'ip')
        origin_netmask = cf.get('net_infos', 'netmask')
        origin_gateway = cf.get('net_infos', 'gateway')
        origin_dns = cf.get('net_infos', 'dns')
        _logger.info(
            "origin ip {} netmask {} gateway {} dns {}".format(origin_ip, origin_netmask, origin_gateway,
                                                               origin_dns))
        if reip.match(origin_ip) is None:
            xlogging.raise_system_error('get orgin net info failed', 'ip invalid', '-1', _logger)
        if reip.match(origin_netmask) is None:
            xlogging.raise_system_error('get orgin net info failed', 'netmask invalid', '-1', _logger)
        if reip.match(origin_gateway) is None:
            xlogging.raise_system_error('get orgin net info failed', 'gateway invalid', '-1', _logger)
        if reip.match(origin_dns) is None:
            xlogging.raise_system_error('get orgin net info failed', 'dns invalid', '-1', _logger)
    except Exception as e:
        _logger.error("read file {}, {} failed,{}".format(mcfg_file, e, traceback.format_exc()))
        xlogging.raise_system_error('get orgin net info failed', 'get origin net info failed', '-1', _logger)

    cmd_line = 'modprobe bonding'
    retval = net_common.get_info_from_syscmd(cmd_line)
    if retval[0] != 0:
        _logger.error("get info from sys cmd {} failed,ret value {}".format(cmd_line, retval))
        return -1
    net_init()
    name_list = net_card_info.net_get_name_list()
    mlen = len(name_list) - 1
    while mlen >= 0:
        type_str = net_card_info.net_type_check(name_list[mlen])
        if type_str != _NET_TYPE_NAME_PHY:
            _logger.info("index {} delete mstr {}".format(mlen, name_list[mlen]))
            del name_list[mlen]
        mlen -= 1
    _logger.info("phy card is {}".format(name_list))
    if len(name_list) <= 0:
        _logger.error("get phy card name failed num is zero")
        return -1

    test_list = [['interface', name_list, [origin_ip, origin_netmask, origin_gateway]],
                 ['dns', [origin_dns]]
                 ]
    json_info = json.dumps(test_list)
    net_set_info(json_info)

    return 0

# net_set_cfgfile_dhcp('/opt/ifcfg-bond0', 'static')
# net_set_cfgfile_ipinfo('/opt/ifcfg-bond0', '172.16.0.124', '', '')
# net_set_cfgfile_bond_opt('/opt/ifcfg-bond0', 'miimon=100')
# get_info_from_syscmd('ethtool bond0')
# get_info_from_file("/sys/class/net/eno16777984/speed")
# net_init()
# net_init_info()
# net_create_cfg_file('eno33557248')
# net_origin_init()
# net_set_info('test')
# net_get_info()
# hh = net_card_attr()
# set_net_card_item(hh,'name','test')
# if __name__ == "__main__":
# net_get_cardtype_driver()
# net_init_info()
# net_common.get_info_from_syscmd('journalctl -xe',1)
# net_restart_service()
# net_set_dns(['172.16.1.1'])
# net_restart_service()
