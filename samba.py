import copy
import json
import os
import threading
import time
import traceback
import uuid

import psutil

import nbd
import net_common
import xlogging
import db_backup_logic
import remote_helper
import logicService

smb_lock = threading.Lock()
_logger = xlogging.getLogger(__name__)

SambaServerName = ''
# samba user 通用数据，默认值为空的字符串
smb_disk_attr_header = {'name': '', 'cfgfile': '', 'homedir': '', 'disk': '', 'diskdir': '', 'status': '',
                        'thread': None, 'mount': None}

_linux_type_str = 'linux'
_windows_type_str = 'windows'


class NbdThread(threading.Thread):
    def __init__(self, username='', hostname='', diskindex=0, disk_snapshots=''):
        threading.Thread.__init__(self)
        self.username = username
        self.hostname = hostname
        self.diskindex = diskindex
        self.disk_snapshots = disk_snapshots
        self.new_nbd = nbd.nbd_wrapper(nbd.nbd_wrapper_local_device_allocator())
        self.device_path = self.new_nbd.device_path
        _logger.debug('username {} hostname {} diskindex {} disk_snapshots {} nbd start,device_path {}'.
                      format(self.username, self.hostname, self.diskindex, self.disk_snapshots, self.device_path))

    def start(self):
        self.new_nbd.is_thread_alive = True
        try:
            super(NbdThread, self).start()
        except Exception as e:
            _logger.error(r'!!!~~!!! start thread failed {}'.format(e), exc_info=True)
            self.new_nbd.is_thread_alive = False
            raise

    def run(self):
        try:
            while True:
                try:
                    self.new_nbd.mount_with_disk_snapshot(self.disk_snapshots)
                except Exception as e:
                    _logger.error("username {} hostname {} disk {} device path {} nbd except {}".
                                  format(self.username, self.hostname, self.diskindex,
                                         self.device_path, e), exc_info=True)
                break
            _logger.info("username {} hostname {} disk {} device path {} exit".
                         format(self.username, self.hostname, self.diskindex, self.device_path))
        finally:
            self.new_nbd.is_thread_alive = False

    def umount(self):
        self.new_nbd.unmount()
        self.new_nbd = None
        _logger.info("username {} hostname {} disk {} device path {} nbd umount".
                     format(self.username, self.hostname, self.diskindex, self.device_path))


class ManageThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.monitor_dict = dict()
        self.monitor_lock = threading.Lock()

    def run(self):
        while True:
            try:
                with self.monitor_lock:
                    for hostname in self.monitor_dict:
                        hostdict = self.monitor_dict[hostname]
                        for diskdict in hostdict['disklist']:
                            diskdict['status'] = 'ok'
            except Exception as e:
                _logger.error('except {}'.format(traceback.format_exc()))
            time.sleep(1)

    def add_host(self, hostdict):
        try:
            with self.monitor_lock:
                hostname = hostdict['hostname']
                if hostname not in self.monitor_dict:
                    self.monitor_dict[hostname] = hostdict
                    _logger.debug('monitor add_host success,hostdict {} '.format(hostdict))
                    return 0
                else:
                    _logger.error('monitor add_host failed,host {} already have'.format(hostdict))
                    return -1
        except Exception as e:
            _logger.error('except {}'.format(traceback.format_exc()))
            return -1

    def del_host(self, hostname):
        try:
            with self.monitor_lock:
                if hostname in self.monitor_dict:
                    hostdict = self.monitor_dict[hostname]
                    _logger.debug('del del_host {}'.format(hostdict))
                    hostdict['share_logic'].end()
                    del self.monitor_dict[hostname]
                else:
                    _logger.error(
                        'del host not found {} monitor dict keys {}'.format(hostname, self.monitor_dict.keys()))
        except Exception as e:
            _logger.error('except {}'.format(traceback.format_exc()))
        return 0

    def get_host_status(self, hostname):
        try:
            with self.monitor_lock:
                if hostname in self.monitor_dict:
                    hostdict = self.monitor_dict[hostname]
                    statusstr = ''
                    for diskdict in hostdict['disklist']:
                        if statusstr != '':
                            statusstr += ';'
                        statusstr += diskdict['diskname'] + ':' + diskdict['status']
                    return 0, statusstr
                else:
                    _logger.error('get host failed {} monitor dict keys {}'.format(hostname, self.monitor_dict.keys()))
                    return -1, 'unknown host'
        except Exception as e:
            _logger.error('except {}'.format(traceback.format_exc()))
            return -1, 'except'


managerthread = ManageThread()


def smb_get_cfgfile_name(user_name):
    return '/etc/samba/{}.smb.conf'.format(user_name)


def smb_get_userpath(user_name):
    return os.path.join('/home/', user_name, user_name)


def smb_get_hostpath(user_name, host_name):
    return os.path.join(smb_get_userpath(user_name), host_name)


def smb_get_diskpath(user_name, host_name, disk_name):
    return os.path.join(smb_get_hostpath(user_name, host_name), disk_name)


def smb_umount_path(hostpath):
    if not os.path.isdir(hostpath):
        _logger.error('umount host path not exist {}'.format(hostpath))
        return 0, 'success'
    mountlist = psutil.disk_partitions()
    umountlist = list()
    for diskpart in mountlist:
        mountpoint = diskpart.mountpoint
        if mountpoint.startswith(hostpath):
            umountlist.append(mountpoint)
    if len(umountlist) > 0:
        sortlist = sorted(umountlist, key=(lambda x: len(x)), reverse=True)
        _logger.debug('umount sort list {}'.format(sortlist))
        for mountpoint in sortlist:
            _logger.debug('umount path {}'.format(mountpoint))
            cmdline = 'fuser -k "{mountpoint}";fuser -k "{mountpoint}";fuser -k "{mountpoint}";umount "{mountpoint}"'.format(
                mountpoint=mountpoint)
            net_common.get_info_from_syscmd(cmdline)


def smb_del_cfg(user_name):
    # cfgfile = smb_get_cfgfile_name(in_name)
    cfgfile = '/etc/samba/user.smb.conf'
    if not os.path.isfile(cfgfile):
        return 0
    phase_name = '[' + user_name + ']'
    new_cfg_str = ''
    retval = net_common.get_info_from_file(cfgfile)
    if retval[0] != 0:
        _logger.error("del user {} get cfg info from {} failed".format(user_name, cfgfile))
        return -1
    strlist = retval[1].split('\n\n')
    update_flag = 0
    for i in range(len(strlist)):
        mstr = strlist[i].strip('\n').strip(' ')
        if len(mstr) <= 2:
            continue
        if mstr.startswith(phase_name):
            _logger.debug('del user {} cfg info {} at str success'.format(user_name, mstr))
            update_flag = 1
            continue
        else:
            new_cfg_str += mstr + '\n\n'
    if update_flag == 1:
        retval = net_common.set_info_to_file(cfgfile, new_cfg_str, 'w')
        if retval != 0:
            _logger.error("del user {} update cfg to file {} failed".format(user_name, cfgfile))
            return -1
        else:
            _logger.debug("del user {} update cfg to file {} success".format(user_name, cfgfile))
    return 0


def smb_add_cfg(user_name, read_only):
    cfgfile = '/etc/samba/user.smb.conf'
    phase_name = '[' + user_name + ']'
    # add_cfg_str = '[' + user_name + ']\n' + 'comment = This is ' + user_name + '\n' + 'path = ' + smb_get_userpath(
    #     user_name) + '\n' + 'read only = yes\n' + 'valid users = ' + user_name + '\n\n'
    add_cfg_str = '[{user_name}]\n' \
                  'path = {path}\n' \
                  'comment = My shared folder\n' \
                  'force group = root\n' \
                  'force user = root\n' \
                  'valid users = {user_name}\n'.format(user_name=user_name, path=smb_get_userpath(user_name))
    if read_only:
        add_cfg_str += 'read only = yes\n\n'
    else:
        add_cfg_str += 'readonly = no\n'
        add_cfg_str += 'writable = yes\n\n'
    new_cfg_str = ''
    if os.path.isfile(cfgfile):
        retval = net_common.get_info_from_file(cfgfile)
        if retval[0] != 0:
            _logger.error("add user {} get cfg info from {} failed".format(user_name, cfgfile))
            return -1
        if retval[1].find(phase_name) < 0:
            new_cfg_str = retval[1] + add_cfg_str
    else:
        new_cfg_str = add_cfg_str

    if new_cfg_str != '':
        retval = net_common.set_info_to_file(cfgfile, new_cfg_str, 'w')
        if retval != 0:
            _logger.error("add user {} add cfg to file {} failed".format(user_name, cfgfile))
            return -1
        else:
            _logger.debug("add user {} add cfg to file {} success".format(user_name, cfgfile))
    return 0


def smb_get_user_list():
    userlist = list()
    cmd_line = 'pdbedit -L'
    retval = net_common.get_info_from_syscmd(cmd_line)
    if retval[0] != 0:
        _logger.error("get info from cmd {} failed".format(cmd_line))
    else:
        mlist = retval[1].strip().split('\n')
        for i in range(len(mlist)):
            mstr = mlist[i]
            mindex = mstr.find(':')
            if mindex > 0:
                muser_name = mstr[:mindex]
                userlist.append(muser_name)
    return userlist


# 如果检测到当前用户没有主机共享则删除用户
def smb_del_userpath(user_name):
    # del sys usr
    userpath = smb_get_userpath(user_name)
    have_host = 0
    if os.path.isdir(userpath):
        for hostname in os.listdir(userpath):
            hostpath = os.path.join(userpath, hostname)
            if os.path.isdir(hostpath):
                have_host += 1
                break
    if have_host == 0:
        # del sys user
        cmd_line = 'userdel -r -f "{}"'.format(user_name)
        _logger.debug("start del sys user {},cmd {}".format(user_name, cmd_line))
        net_common.get_info_from_syscmd(cmd_line)
        # del smb user
        smb_del_cfg(user_name)
        cmd_line = 'pdbedit -x {}'.format(user_name)
        _logger.debug("start del smb user {},cmd {}".format(user_name, cmd_line))
        net_common.get_info_from_syscmd(cmd_line)
        cmdline = 'rm -rf "{userpath}"'.format(
            userpath=userpath)
        _logger.debug("start user path,cmd {}".format(cmd_line))
        net_common.get_info_from_syscmd(cmdline)
    else:
        _logger.error('already have {} host,can not del userpath {}'.format(have_host, userpath))
        return -1, "failed"

    return 0, 'success'


# 添加用户同时生成用户目录,如果已有用户目录则直接返回成功
def smb_add_userpath(username, userpwd, read_only):
    userpath = smb_get_userpath(username)

    cmd_line = 'useradd {username}; chmod 755 {userpath_dir}; ' \
               'mkdir -p -m 755 "{userpath}";chown {username}:{username} "{userpath}"'.format(
        username=username, userpath=userpath, userpath_dir=os.path.dirname(userpath))
    net_common.get_info_from_syscmd(cmd_line)
    cmd_line = '(echo "{}";echo "{}")|smbpasswd -a "{}"'.format(userpwd, userpwd, username)
    net_common.get_info_from_syscmd(cmd_line)
    retval = smb_add_cfg(username, read_only)
    if retval != 0:
        _logger.error("smb user {} create cfg file failed".format(username))
        smb_del_userpath(username)
        return -1, 'create smb cfg file failed,user {}'.format(username)
    userinfo = net_common.get_info_from_syscmd('pdbedit -L')
    if userinfo[0] != 0:
        return -1, 'create smb cfg file failed,user {}'.format(username)
    if username not in userinfo[1]:
        return -1, 'create smb cfg file failed,user {}'.format(username)
    _logger.debug('smb_create_smbuser user {} pwd {} success'.format(username, userpwd))
    return 0, 'success'


# 删除主机共享目录,同步清除所有mount信息,外部的主机监控信息和mount信息需为额外清除
# 同时会尝试删除用户信息
def smb_del_hostpath(username, hostname):
    hostpath = smb_get_hostpath(username, hostname)
    _logger.debug('del host path: user {} host {} host path {}'.format(username, hostname, hostpath))
    if os.path.isdir(hostpath):
        cmdline = 'rm -rf "{hostpath}"'.format(hostpath=hostpath)
        net_common.get_info_from_syscmd(cmdline)
    smb_del_userpath(username)
    return 0, 'success'


# 添加主机共享目录，如已有主机目录则返回失败
def smb_add_hostpath(user_name, hostname):
    hostpath = smb_get_hostpath(user_name, hostname)
    if os.path.exists(hostpath):
        _logger.error('smb_add_hostpath host {} already exist'.format(hostpath))
        return -1, ''
    cmdline = 'mkdir -p -m 755 "{hostpath}"'.format(hostpath=hostpath)
    ret = net_common.get_info_from_syscmd(cmdline)
    if ret[0] != 0:
        _logger.debug('add hostpath failed {}'.format(ret))
        return -1, 'failed'
    return 0, 'success'


# 删除用户信息,用户主机共享信息,外部的主机监控信息和mount信息需额外清除
def smb_del_user(user_name):
    # del sys usr
    _logger.debug('del user {}'.format(user_name))
    userpath = smb_get_userpath(user_name)
    if os.path.isdir(userpath):  # sambauser name
        for hostname in os.listdir(userpath):
            hostpath = os.path.join(userpath, hostname)
            if os.path.isdir(hostpath):  # host snapshot path
                smb_del_hostpath(user_name, hostname)
    smb_del_userpath(user_name)
    return 0, 'success'


# 添加用户,同smb_add_userpath
def smb_add_user(user_name, userpwd, read_only):
    return smb_add_userpath(user_name, userpwd, read_only)


# 同smb_del_hostpath
def smb_del_host(username, hostname):
    smb_del_hostpath(username, hostname)
    return 0


# 删除主机共享,同步清除监控信息和mount信息
def smb_del_host_share(hostinfo):
    global smb_lock
    _logger.debug('del host {}'.format(hostinfo))
    username = hostinfo[0]
    hostname = hostinfo[1]
    with smb_lock:
        managerthread.del_host(hostname)
        smb_del_host(username, hostname)
        return 0, username, hostname


# 获取主机所有硬盘监控信息
def smb_get_host_share_status(hostname):
    global smb_lock
    with smb_lock:
        return managerthread.get_host_status(hostname)


# 从include_ranges 筛选出制定磁盘的 partitions info
def get_partitions_info(disk_index, include_ranges):
    rs = list()
    for ranges in include_ranges:
        if int(disk_index) == ranges['diskIndex']:
            rs = ranges['ranges']
            break
    return rs


def _pause_in_debug_mod(msg, logger):
    if not os.path.exists('/dev/shm/debug_share'):
        return
    file_name = '/tmp/pause_share_{}'.format(time.time())
    with open(file_name, 'w'):
        pass
    while os.path.exists(file_name):
        logger.warning('{} pause until {} removed!'.format(msg, file_name))
        time.sleep(5)


# 添加主机共享,同步生成用户信息,监控信息和mount信息
def smb_add_host_share(cmdinfo):
    samba_params = {
        'username': cmdinfo['username'],
        'hostname': cmdinfo['hostname'],
        'userpwd': cmdinfo['userpwd'],
        'read_only': True
    }
    kvm_used_params = {  # 启动kvm使用的参数
        'logic': 'linux',
        'disk_ctl_type': 'scsi-hd',
        'aio_server_ip': '172.29.16.2',
        'ip_prefix': '172.29.100',
        'memory_mbytes': 128,
        'tap_name_prefix': 'sharetap',
        'disksnapshots': list(),
        'qcow_files': [
            {
                'base': '/home/kvm_rpc/Clerware-7-x86_64-1611.mini.loader.qcow2',
                'new': '/tmp/tmp_qcow/share{}.qcow2'.format(uuid.uuid4().hex),
                'qcow_type': 'with_base'
            }
        ]
    }
    mount_file_system_params = {
        'read_only': True,
        'linux_storage': cmdinfo['linux_storage'],
        'include_ranges': cmdinfo['include_ranges'],
        'windows_volumes': cmdinfo['windows_volumes'],
        'ostype': cmdinfo['ostype'],
        'disklist': list()
    }
    for disk_info in cmdinfo['disklist']:
        if 'nbd_uuid' not in disk_info:
            nbd_uuid = uuid.uuid4().hex
        else:
            nbd_uuid = disk_info['nbd_uuid']
        kvm_used_params['disksnapshots'].append({
            'images': disk_info['disksnapshots'],
            'nbd_type': 'gznbd',
            'scsi_id': nbd_uuid
        })
        mount_file_system_params['disklist'].append(
            {
                'diskid': disk_info['diskid'],
                'nbd_uuid': nbd_uuid
            }
        )
    share_logic = AddShareLogic(kvm_used_params, mount_file_system_params, samba_params)
    try:
        share_logic.share()
        AddShareLogic.add_monitor(cmdinfo['hostname'], share_logic)
    except Exception:
        _pause_in_debug_mod('文件浏览失败', _logger)
        share_logic.end()
        raise
    else:
        retstr = r'{}\{}\{}'.format(SambaServerName, samba_params['username'], samba_params['hostname'])
        retstr = retstr.replace('/', '\\')
        return 0, retstr


smb_cmd_ctrl_dict = {'add_share': smb_add_host_share,
                     'get_host_status': smb_get_host_share_status,
                     'del_host': smb_del_host_share}

ice_cmd_ctrl_header = {'cmdtype': '', 'contype': '', 'cmdinfo': None}


def ice_cmd_ctrl_init(cmdtype, contype, cmdinfo):
    mdict = copy.copy(ice_cmd_ctrl_header)
    mdict['cmdtype'] = cmdtype
    mdict['contype'] = contype
    mdict['cmdinfo'] = cmdinfo
    return mdict


def ice_cmd_get_cmdtype(in_cmd):
    try:
        return 0, in_cmd['cmdtype']
    except Exception as e:
        _logger.error('invalid cmdtype {}'.format(traceback.format_exc()))
        return -1, 'cmdtype invalid'


def ice_cmd_get_contype(in_cmd):
    try:
        return 0, in_cmd['contype']
    except Exception as e:
        _logger.error('invalid contype,{}'.format(traceback.format_exc()))
        return -1, 'contype invalid'


def ice_cmd_get_cmdinfo(in_cmd):
    try:
        return 0, in_cmd['cmdinfo']
    except Exception as e:
        _logger.error('invalid cmdinfo,{}'.format(traceback.format_exc()))
        return -1, 'cmdinfo invalid'


def ice_cmd_get_all(in_cmd):
    retval = ice_cmd_get_cmdtype(in_cmd)
    if retval[0] != 0:
        return -1, retval[1]
    cmdtype = retval[1]

    retval = ice_cmd_get_contype(in_cmd)
    if retval[0] != 0:
        return -1, retval[1]
    contype = retval[1]

    retval = ice_cmd_get_cmdinfo(in_cmd)
    if retval[0] != 0:
        return -1, retval[1]
    cmdinfo = retval[1]
    return 0, cmdtype, contype, cmdinfo


def ice_cmd_ctrl(cmd_str):
    global smb_cmd_ctrl_dict
    mstr = json.loads(cmd_str)
    _logger.debug('get new cmd_str {}'.format(mstr))
    retlist = list()
    for i in range(len(mstr)):
        retval = ice_cmd_get_all(mstr[i])
        if retval[0] != 0:
            _logger.debug('ice_cmd_get_all failed,ret {}'.format(retval[1]))
            retlist.append([-1, retval[1]])
            continue
        cmdtype = retval[1]
        contype = retval[2]
        cmdinfo = retval[3]

        _logger.debug('get new cmd type {},contype {},info {}'.format(cmdtype, contype, cmdinfo))
        if cmdtype not in smb_cmd_ctrl_dict:
            _logger.error('unknown cmd type {}'.format(cmdtype))
            retlist.append([-1, 'unknown cmd type {}'.format(cmdtype)])
            if contype != 'continue':
                break
        try:
            retval = smb_cmd_ctrl_dict[cmdtype](cmdinfo)
            _logger.debug('run cmd type {} success,ret is {}'.format(cmdtype, retval))
            retlist.append([0, retval])
        except Exception as e:
            mstr = traceback.format_exc()
            _logger.error('run cmdtype {} failed,except {}'.format(cmdtype, mstr))
            retlist.append([-1, 'except {}'.format(mstr)])
        if contype != 'continue':
            _logger.debug('at cmd type {} break'.format(cmdtype))
            break
    _logger.debug('ret list is {}'.format(retlist))
    mjson = json.dumps(retlist)
    _logger.debug('return mjson {}'.format(mjson))
    return mjson


def smb_clear_all():
    # 清理残留的共享目录
    while True:
        rev = net_common.get_info_from_syscmd('grep -qs cifs /proc/mounts', timeout=5)
        if rev[0] != 0:
            break
        net_common.get_info_from_syscmd('umount -a -t cifs -l', timeout=5)
        time.sleep(2)

    userlist = smb_get_user_list()
    _logger.debug('get user list {}'.format(userlist))
    for i in range(len(userlist)):
        name = userlist[i]
        smb_del_user(name)
    for k, _ in psutil.net_if_addrs().items():
        if k.startswith('sharetap'):
            net_common.get_info_from_syscmd('ip tuntap del {} mode tap'.format(k))


def smb_init():
    try:
        global SambaServerName
        managerthread.setDaemon(True)
        managerthread.start()
        SambaServerName = 'SambaServer'
        _logger.debug('SambaServerName is {}'.format(SambaServerName))
        smb_clear_all()
    except Exception as e:
        _logger.error('smb_init failed,except {}'.format(traceback.format_exc()))


class SAMBAMountHandle(object):

    def __init__(self, key_info, mount_point):
        self._key_info = key_info
        self.mount_point = mount_point

    def set_ip(self, server_ip):
        self._server_ip = server_ip

    def mount(self, readonly=True):
        """
        mount -t cifs //172.29.100.100/wuo/W2003R2PAR_1_2018-08-01T20-30-38.350867
         /mnt/smb/ -o username="wuo",password="843207",iocharset=utf8
        :return:
        """
        assert self._server_ip
        check_readonly = 'ro'
        if not readonly:
            check_readonly = 'rw'
        cmd = r'mount -t cifs "//{samba_server}/{samba_user}/{host_name}/" "{dst_point}"' \
              r' -o username="{samba_user}",password="{samba_password}",iocharset=utf8,{readonly},nomapposix'.format(
            samba_server=self._server_ip, samba_user=self._key_info['username'],
            host_name=self._key_info['hostname'], samba_password=self._key_info['userpwd'],
            dst_point=self.mount_point, readonly=check_readonly)
        _logger.info('mount cmd info:{}'.format(cmd))
        rev = net_common.get_info_from_syscmd(cmd, timeout=5)
        return rev[0] == 0

    def unmount(self):
        _cmd_u = 'umount -f -l "{}"'.format(self.mount_point)
        _fuser_k = 'fuser -k "{}"'.format(self.mount_point)
        while True:
            code, _, stderr = net_common.get_info_from_syscmd(_cmd_u, timeout=5)
            if code == 0 or 'not mounted' in stderr:
                break
            net_common.get_info_from_syscmd(_fuser_k)
            time.sleep(2)
        _logger.info('unmount {} successful'.format(self.mount_point))


class SambaShareUser(object):

    def __init__(self, key_info):
        self.user = key_info['username']
        self.password = key_info['userpwd']
        self.host_name = key_info['hostname']
        self.read_only = key_info.get('read_only', True)
        self.host_path = smb_get_hostpath(self.user, self.host_name)
        self.add_user = False
        self.add_host = False

    def share(self):
        ret = smb_add_user(self.user, self.password, self.read_only)
        if ret[0] != 0:
            xlogging.raise_system_error('SambaShareUser add user fail', 'SambaShareUser add user fail', 131)
        self.add_user = True

        ret = smb_add_hostpath(self.user, self.host_path)
        if ret[0] != 0:
            xlogging.raise_system_error('SambaShareUser add host path fail', 'SambaShareUser add host path fail', 132)
        self.add_host = True

    def del_share(self):
        if self.add_host:
            smb_del_hostpath(self.user, self.host_path)
        if self.add_user:
            smb_del_userpath(self.user)

    @staticmethod
    def restart_samba():
        net_common.get_info_from_syscmd('systemctl restart smb;systemctl restart nmb')


class AddShareLogic(object):

    def __init__(self, kvm_used_params, mount_file_system_params, samba_params, check_fun=None, logger=None):
        self.kvm = None
        self.gust_proxy = None
        self._kvm_used_params = kvm_used_params
        self._samba_params = samba_params
        self._mount_file_system_params = mount_file_system_params

        self._samba_user_handle = None
        self._samba_mount_handle = None

        self._guest_ip = None
        self._guest_mac = None
        self.logger = logger if logger else _logger

        def check_fun_local():
            pass

        self._check_fun = check_fun if check_fun else check_fun_local

    def share(self, local_share=True, mount_point=None):
        try:
            self.kvm = db_backup_logic.KvmDBBackup(self._kvm_used_params)
            self.kvm.start()
            self._guest_ip, self._guest_mac = self.kvm.get_ip_and_mac()
            self.logger.info('remote host ip :{}'.format(self._guest_ip))
            self._wait_host_online(self._guest_ip)
            self._mount_file_system_remote()  # 远端mount
            if local_share:  # 本地需要samba共享
                self._samba_user_handle = SambaShareUser(self._samba_params)
                self._samba_user_handle.share()
                mount_point = self._samba_user_handle.host_path
            self._mount_file_system_to_local(mount_point)  # mount 到本地
            if local_share:
                self._samba_user_handle.restart_samba()
        except Exception as e:
            _logger.error('AddShardLogic e:{}'.format(e), exc_info=True)
            raise

    def get_ip_and_mac(self):
        return self._guest_ip, self._guest_mac

    def get_proxy(self):
        return self.gust_proxy

    def _wait_host_online(self, _guest_ip):
        self.logger.info('_wait_host_online begin')
        remote_proxy_ins = remote_helper.RemoteProxy(_guest_ip, logicService.get_communicator(), self.logger,
                                                     self._check_fun)
        remote_proxy_ins.set_python_path(r'/home/python3.6/bin/python3.6')
        self.gust_proxy = remote_proxy_ins.create()
        self.logger.info('_wait_host_online end')

    def _mount_file_system_remote(self):
        self.logger.info('begin _mount_file_system_remote')
        # 添加共享
        _samba_ins = remote_helper.ModuleMapper('add_share', 'SambaShareUser', self.gust_proxy,
                                                self.logger, self._samba_params)
        share_path, _ = _samba_ins.execute('share')
        self.logger.info('_mount_file_system_to_local get remote share path :{}'.format(share_path))
        self._mount_file_system_params['mount_root'] = share_path
        # 远端mount
        _mount_ins = remote_helper.ModuleMapper('add_share', 'MountFileSystem', self.gust_proxy,
                                                self.logger, self._mount_file_system_params)
        _mount_ins.execute('mount')
        _samba_ins.execute('restart_samba')
        self.logger.info('end  _mount_file_system_remote')

    def _mount_file_system_to_local(self, mount_point):
        self.logger.info('begin _mount_file_system_to_local')
        self._samba_mount_handle = SAMBAMountHandle(self._samba_params, mount_point)
        self._samba_mount_handle.set_ip(self._guest_ip)
        if not self._samba_mount_handle.mount(self._samba_params['read_only']):
            xlogging.raise_system_error('挂载文件系统失败', 'mount fail', 753)
        self.logger.info('end _mount_file_system_to_local ')

    def nbd_alive(self):
        return self.kvm.nbd_alive()

    def kvm_alive(self):
        return self.kvm.kvm_alive()

    def end(self):
        if self._samba_mount_handle:
            self._samba_mount_handle.unmount()
            self._samba_mount_handle = None
        if self._samba_user_handle:
            self._samba_user_handle.del_share()
            self._samba_user_handle = None
        if self.kvm:
            self.kvm.kill()
            self.kvm.join()
            self.kvm = None

    def is_active(self):
        if self.kvm:
            return self.kvm.is_active()
        return False

    def join(self):
        return self.kvm.join()

    @staticmethod
    def add_monitor(hostname, end_handle):
        monitor_dict = {'hostname': hostname, 'share_logic': end_handle, 'disklist': []}
        return managerthread.add_host(monitor_dict)


if __name__ == "__main__":
    nbd.init(128)
    smb_init()
    key_info = {
        'username': 'wuo',
        'hostname': 'W2003R2PAR_1_2018-08-01T20-30-38.350867',
        'linux_storage': '',
        'userpwd': '843207',
        'disklist': [{
            'disksnapshots': [{
                'ident': '49ec3adb58bb4696a6ac3ec865547077',
                'path': '/home/mnt/nodes/68067f4b8a3e4eb59b3ae9fc5a851a9f/images/ff5cc0c6541446d685156e4efe34a911/ac5505da0a014ce6b2638a0b9e5e8c6b.qcow'
            }],
            'diskdir': 'disk0',
            'diskid': 0
        }],
        'ostype': 'windows',
        'include_ranges': [{
            'diskIdent': '5dc17c02a28047379d1b16fec3e0a24e',
            'diskSnapshot': '49ec3adb58bb4696a6ac3ec865547077',
            'diskIndex': 0,
            'ranges': [{
                'VolumeName': '\\\\?\\Volume{1a5a6be4-d257-11e6-852f-806e6f6e6963}\\',
                'VolumeSize': '16096837632',
                'PartitionSize': '16096840704',
                'FileSystem': 'NTFS',
                'VolumeLabel': 'W2003R2',
                'PartitionOffset': '32256',
                'FreeSize': '8875925504',
                'Letter': 'C',
                'Style': 'mbr',
                'Index': '1'
            }],
            'diskNativeGUID': '{76017601-0000-0000-0000-000000000000}'
        }]
    }
