# 调用 Enum 之后返回的数据结构体如下。
#
# ['内：外', '172.16.6.74', '3260', 'iqn.1991-05.com.microsoft:win-3r1rf354uo3-wolf-target', 'lun-0', '/dev/sdd','磁盘大小',
# ‘硬盘设备信息字符串’，‘有分区，无分区’，'卷名'，'公司名','产品GUID', '磁盘分区1GUID', ‘是否被mount’,'mount 路径']
# [[True, None, None, None, None, '/dev/mapper/centos-home_aio', '974GB', 'Linux device-mapper (linear) (dm)', True,
#  '/dev/mapper/centos-home_aio', 'FC48', '39DF4A7962384de195A33082FF193AB2', '256ef9d1-b4d1-4d58-9d0e-7ded2ba2def7', True, '/home/aio'],
# 内：可用：默认分区，已mount
#
# [True, 'None', 'None', 'None', 'None', '/dev/sdb', '17.2GB', 'VMware Virtual disk (scsi)', False, None, None, None, None, None],
# 内：不可用：没有分区
#
# [True, 'None', 'None', 'None', 'None', '/dev/sdc', '17.2GB', 'VMware Virtual disk (scsi)', True, '/dev/sdc1', '1111',
#  '11111111111111111111111111111111', 'd82fcb7e-7ed3-4054-88ca-e7a850237f1d', False, None],
# 内：不可用：分区guid不对。未mount
#
# [False, '172.16.6.74', '3260', 'iqn.1991-05.com.microsoft:win-3r1rf354uo3-wolf-target', 'lun-0', '/dev/sdd', '1049MB',
# 'MSFT Virtual HD (scsi)', True, '/dev/sdd1', 'M-fM', '-^VM-0M-eM-^JM- M-eM-^MM-7', '4ABC8020BC8008A1', False, None],
# 外：不可用：分区guid不对。未mount
#
# [False, '172.16.6.74', '3260', 'iqn.1991-05.com.microsoft:win-3r1rf354uo3-wolf-target', 'lun-1', '/dev/sde', '524MB', '
# MSFT Virtual HD (scsi)', True, '/dev/sde1', 'dp1', None, '3934cafb-aec5-45f9-8a92-e3d83296f039', True, '/mnt']]
# 外：不可用：分区guid不对。已mount
#

import configparser
import os
import re
import sys
import time
import subprocess
import traceback

try:
    import xlogging
except ImportError:
    import logging as xlogging

# =========================================================================================
g_store_ini_path = '/etc/aio/store_manage.cfg'
_logger = xlogging.getLogger('storage_r')


# =========================================================================================

def cur_file_dir():
    try:
        # 获取脚本路径
        path = sys.path[0]
        # 判断为脚本文件还是py2exe编译后的文件，如果是脚本文件，则返回的是脚本的目录，如果是py2exe编译后的文件，则返回的是编译后的文件路径
        if os.path.isdir(path):
            _logger.debug("cur_file_dir = %s" % (path))
            return path
        elif os.path.isfile(path):
            _logger.debug("cur_file_dir = %s" % (os.path.dirname(path)))
            return os.path.dirname(path)
    except:
        _logger.error(traceback.format_exc())


def show_and_exe_cmd_line_and_get_ret(in_cmd_line, chk_err_str='', bPrint=True):
    try:
        cmd_line = in_cmd_line + ' 2>&1'
        if bPrint:
            _logger.debug(cmd_line)
        with os.popen(cmd_line) as out_put:
            out_put_lines = out_put.readlines()
            if '' == chk_err_str:
                if bPrint:
                    _logger.debug('0'), _logger.debug(out_put_lines)
                return 0, out_put_lines
            for one_line in out_put_lines:
                if -1 != one_line.find(chk_err_str):
                    if bPrint:
                        _logger.debug('-1'), _logger.debug(out_put_lines)
                    return -1, out_put_lines
        if bPrint:
            _logger.debug('0'), _logger.debug(out_put_lines)
        return 0, out_put_lines
    except:
        _logger.error(traceback.format_exc())
        _logger.debug('-1'), _logger.debug(out_put_lines)
        return -1, out_put_lines


def ret_sub_str_start_and_end_by_name(will_search_str, start_str, end_str, bIsCleanName=True):
    try:
        # ==================================================================================
        # 分两次查找。
        # 第一次查找获取后的位置有可能包含头尾空格
        re1 = ''
        ret_start = 0
        ret_end = 0
        len_start = 0
        len_end = 0
        re2 = ''
        # _logger.debug("will_search_str = {}".format(will_search_str))

        if start_str is not None:
            if bIsCleanName:
                re1 += r'(\s|\A)'
            re1 += start_str
            re2 += start_str
            len_start = len(start_str)

        if end_str is not None:
            re1 += '.*?' + end_str
            re2 += '.*?' + end_str
            if bIsCleanName:
                re1 += r'(\s|\Z)'
            len_end = len(end_str)
        else:
            re1 += '.*'
            re2 += '.*'

        # _logger.debug("re1 = {},re2 = {}".format(re1,re2))

        com1 = re.compile(re1)
        ret1 = com1.search(will_search_str)
        # _logger.debug(ret1)
        if ret1 is not None:
            # ==================================================================================
            # 第二次查找。
            com2 = re.compile(re2)
            ret2 = com2.search(will_search_str, ret1.start(), ret1.end())
            # _logger.debug(ret2)
            if ret2 is not None:
                ret_start = ret2.start() + len_start
                ret_end = ret2.end() - len_end

        # _logger.debug("ret_start = {},ret_end={}".format(ret_start, ret_end))
        if ret_start == ret_end:
            return None, None
        return ret_start, ret_end
    except:
        _logger.error(traceback.format_exc())
        return None, None


# bIsCleanName：是否干净的名字：比如要查找的名字是 LABEL ,那么 PARTLABEL 就不是干净的名字。
# 某些情况下需要不干净的名字：比如。ip-172.16.6.74:3260-iscsi-iqn.1991-05.com.microsoft:win-3r1rf354uo3-wolf-target-lun-0 -> ../../sdd
def get_sub_str_by_name(will_search_str, start_str, end_str, bIsCleanName=True):
    try:
        (start, end) = ret_sub_str_start_and_end_by_name(will_search_str, start_str, end_str, bIsCleanName)
        # _logger.debug("get_sub_str_by_name start=%d,end=%d,will_search_str=%s" % (start, end,will_search_str))
        if start is None: return None
        ret_str = will_search_str[start:end]
        # _logger.debug("get_sub_str_by_name ret_str= {}".format(ret_str))
        return ret_str
    except:
        _logger.error(traceback.format_exc())
        return None


def get_sub_str_by_name_r(will_search_str, start_str, end_str, bIsCleanName=True):
    try:
        (start, end) = ret_sub_str_start_and_end_by_name(will_search_str, start_str, end_str, bIsCleanName)
        # _logger.debug("get_sub_str_by_name_r start=%d,end=%d,will_search_str=%s" % (start, end, will_search_str))
        if start is None: return None
        ret_str = will_search_str[end:]
        # _logger.debug("get_sub_str_by_name_r ret_str= {}".format(ret_str))
        return ret_str
    except:
        _logger.error(traceback.format_exc())
        return None


def get_sub_str_by_name_l(will_search_str, start_str, end_str, bIsCleanName=True):
    try:
        (start, end) = ret_sub_str_start_and_end_by_name(will_search_str, start_str, end_str, bIsCleanName)
        # _logger.debug("get_sub_str_by_name_l start=%d,end=%d,will_search_str=%s" % (start, end, will_search_str))
        if start is None: return None
        return will_search_str[:start]
    except:
        _logger.error(traceback.format_exc())
        return None


class CPartition:
    def set_partiton(self, partition_str):
        self.partition_str = partition_str

    def format_xfs(self):
        ret, lines = show_and_exe_cmd_line_and_get_ret("mkfs.xfs -f " + self.partition_str, 'No such file or directory')
        for one_line in lines:
            if -1 != one_line.find('busy'):
                _logger.debug('format_xfs device is busy = {}'.format(one_line))
                return -1
        return ret


class CDisk:
    def set_disk(self, disk_str):
        self.disk_str = disk_str
        self.partiton_1 = CPartition()
        self.partiton_1.set_partiton(disk_str + '1')

    def ReInitDisk_by_one_partiton(self, co_guid, product_guid):
        # 洗白引导扇区
        show_and_exe_cmd_line_and_get_ret('dd if=/dev/zero  of=' + self.disk_str + ' bs=512 count=1')
        # 执行建立磁盘分区的脚本
        show_and_exe_cmd_line_and_get_ret(
            'sh ./create_disk_partiton.sh ' + self.disk_str + ' ' + co_guid + product_guid)
        for i in range(60):
            if 0 == self.partiton_1.format_xfs():
                break;
            time.sleep(1)

    def ReInitDisk_by_no_partiton(self):
        return show_and_exe_cmd_line_and_get_ret("mkfs.xfs -f " + self.disk_str, 'No such file or directory')


class CExternStore:
    def __init__(self):
        try:
            pass
        except:
            _logger.error(traceback.format_exc())

    # 可将显示连接获取的一行字符串提取iqn ,iqn 结束后必须有空格否则出错。
    def str_to_iqn(self, one_line, remote_port):
        try:
            iqn_start_num = one_line.find('iqn')
            if -1 == iqn_start_num:
                return None
            tmp = one_line[0:iqn_start_num]
            # _logger.debug('one_line = {} , tmp1 = {}'.format(one_line,tmp))
            remote_port_start_num = tmp.find(str(remote_port))
            if -1 == remote_port_start_num:
                return None
            tmp = one_line[iqn_start_num:len(one_line) - 1]
            # _logger.debug('one_line = {} , tmp2 = {}'.format(one_line,tmp))
            iqn_end_num = tmp.find(' ')
            if -1 != iqn_end_num:
                tmp = tmp[0:iqn_end_num]
            return tmp
        except:
            _logger.error(traceback.format_exc())
            return None

    # 连接，连接成功之后，系统会自动记录，开机会重连
    def iscsi_con(self, remote_ip, remote_port, bUseCHAP, user_name, password):
        try:
            cmd_line = 'iscsiadm -m discovery -t sendtargets -p ' + remote_ip + ":" + str(remote_port)
            _logger.debug(cmd_line)
            with os.popen(cmd_line) as out_put:
                # output_str_once_read = out_put.read()
                # if 0 == len(output_str_once_read): return -1
                output_str_lines = out_put.readlines()
                bFindServID = False
                for one_line in output_str_lines:
                    _logger.debug(one_line)
                    iqn_str = self.str_to_iqn(one_line, remote_port)
                    if iqn_str is None: continue
                    bFindServID = True
                    break
            if bFindServID == False:
                _logger.debug('not find iqn')
                return -1, None
            _logger.debug(iqn_str)
            if bUseCHAP:
                cmd_line = 'iscsiadm -m node -T ' + iqn_str + " -o update --name node.session.auth.authmethod --value=CHAP"
                _logger.debug(cmd_line)
                os.system(cmd_line)
                cmd_line = 'iscsiadm -m node -T ' + iqn_str + " -o update --name node.session.auth.username --value=" + user_name
                _logger.debug(cmd_line)
                os.system(cmd_line)
                cmd_line = 'iscsiadm -m node -T ' + iqn_str + " -o update --name node.session.auth.password --value=" + password
                _logger.debug(cmd_line)
                os.system(cmd_line)
            # cmd_line = 'iscsiadm -m node -T '+ iqn_str + " -p " + remote_ip + ":" + str(remote_port)+"  -l"
            cmd_line = 'iscsiadm -m node -T ' + iqn_str + " -l"
            with os.popen(cmd_line) as out_put:
                _logger.debug(cmd_line)
                output_str_lines = out_put.readlines()
                for one_line in output_str_lines:
                    _logger.debug(one_line)
                    if -1 != one_line.find('successful'):
                        return 0, iqn_str
            return -1, iqn_str
        except:
            _logger.error(traceback.format_exc())
            return -1, None

    # 显示连接信息多行字符串
    def iscsi_show(self):
        try:
            cmd_line = 'iscsiadm -m session'
            _logger.debug(cmd_line)
            with os.popen(cmd_line) as out_put:
                out_put_all_line = out_put.readlines()
                if len(out_put_all_line) == 0:
                    _logger.debug("no iscsi connect info")
                    return -1, None
            # _logger.debug(out_put_all_line)
            return 0, out_put_all_line
        except:
            _logger.error(traceback.format_exc())
            return -1, None

    # 使用iqn登出
    def iscsi_log_out_by_iqn(self, iqn):
        try:
            cmd_line = 'iscsiadm -m node -T ' + iqn + ' -u'
            _logger.debug(cmd_line)
            with os.popen(cmd_line) as out_put:
                output_str = out_put.read()
                if 0 == len(output_str):
                    return -1
            return 0
        except:
            _logger.error(traceback.format_exc())
            return -1

    # 使用连接信息一行字符串登出
    def iscsi_log_out_by_show_one_line(self, one_line):
        try:
            _logger.debug("iscsi_log_out_by_one_line begin")
            iqn_str = self.str_to_iqn(one_line)
            if iqn_str == None:
                _logger.debug("iscsi_log_out_by_one_line one_line = %s : not find iqn" % (one_line))
                return -1
            return self.iscsi_log_out_by_iqn(iqn_str)
        except:
            _logger.error(traceback.format_exc())
            return -1

    # 登录成功后的节点如果不删除，重启系统后会自动连接。
    # 使用iqn删除节点，删除节点必须要断开当前会话。
    def del_node_by_iqn(self, iqn):
        try:
            self.iscsi_log_out_by_iqn(iqn)  # 有可能没有连接
            cmd_line = 'iscsiadm -m node --op delete --targetname ' + iqn + " 2>&1"
            _logger.debug(cmd_line)
            with os.popen(cmd_line) as out_put:
                output_str = out_put.read()
                _logger.debug("ret str = %s" % (output_str))
                if -1 != output_str.find('No records found'):
                    return -1
            return 0
        except:
            _logger.error(traceback.format_exc())
            return -1

    # 登录成功后的节点如果不删除，重启系统后会自动连接。
    # 使用连接信息，一行删除节点，删除节点必须要断开当前会话。
    def del_node_by_show_one_line(self, one_line):
        try:
            _logger.debug("del_node_by_show_one_line begin")
            iqn_str = self.str_to_iqn(one_line)
            if iqn_str is None:
                _logger.debug("del_node_by_show_one_line one_line = %s : not find iqn" % (one_line))
                return -1
            return self.del_node_by_iqn(iqn_str)
        except:
            _logger.error(traceback.format_exc())
            return -1


class CMultipath():
    def __init__(self):
        try:
            self.bHaveMultiPath = self.is_multipath_exist()
        except:
            _logger.error(traceback.format_exc())
            self.bHaveMultiPath = False

    def execute_command(self, cmd, cwd=None):
        try:
            # _logger.info('[execute_command] cmd={0} cwd={1}'.format(cmd, cwd))

            std_out = []
            std_err = []
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True, shell=True, cwd=cwd,
                                 stderr=subprocess.PIPE)
            p.wait()

            for line in p.stdout:
                std_out.append(line.rstrip())

            for line in p.stderr:
                std_err.append(line.rstrip())

            return p.returncode, std_out, std_err
        except:
            _logger.error(traceback.format_exc())
            return -1, std_out, std_err

    def get_multipath_dir(self):
        path = os.path.join("/dev", "mpath")
        if os.path.exists(path):
            return path
        path = os.path.join("/dev", "mapper")

        return path

    def exec_multipath_cmd(self, cmd):
        full = "/usr/sbin/multipath {0}".format(cmd)
        retval, outmsg, errmsg = self.execute_command(full)
        if retval != 0:
            _logger.info("[exec_multipath_cmd] retval={0} out={1} err={2}".format(retval, outmsg, errmsg))

        return retval, outmsg, errmsg

    def is_multipath_exist(self):
        cmd = "-h"
        retval, out, err = self.exec_multipath_cmd(cmd)
        if retval == 0:
            return True

        cmd = "lsmod|grep dm_multipath"
        retval, out, err = self.execute_command(cmd)
        if retval != 0:
            return False

        for i in out:
            if i.find("dm_multipath") >= 0:
                return True

        return False

    def get_multipath_list(self):
        try:
            if self.bHaveMultiPath is not True:
                return list()

            multipath_list = list()
            path = self.get_multipath_dir()
            files = os.listdir(path)
            for f in files:
                cmd = "-l {0}".format(f) + " |grep running|sed \"s/|//\"|awk  {'print $3'} "
                retval, out, err = self.exec_multipath_cmd(cmd)
                if retval != 0:
                    _logger.info("[get_multipath_list] not mpath device {}".format(f))
                    continue
                bFindNorDisk = False
                for one in out:
                    nor_disk_path = '/dev/' + one
                    if os.path.exists(nor_disk_path):
                        bFindNorDisk = True
                        break
                if bFindNorDisk:
                    one_multipath = os.path.join(path, f)
                    multipath_list.append(one_multipath)
            return multipath_list
        except:
            _logger.error(traceback.format_exc())
            return list()

    def get_nor_disk_list_by_multipath(self, multipath_full_path):
        try:
            if self.bHaveMultiPath is not True:
                return list()
            cmd = "-l {0}".format(multipath_full_path) + " |grep running|sed \"s/|//\"|awk  {'print $3'} "
            retval, out, err = self.exec_multipath_cmd(cmd)
            if retval != 0:
                _logger.info("[get_nor_disk_list_by_multipath] not mpath device {}".format(f))
                return list()
            nor_disk_list = list()
            for one in out:
                nor_disk_path = '/dev/' + one
                if os.path.exists(nor_disk_path):
                    nor_disk_list.append(nor_disk_path)
            return nor_disk_list
        except:
            _logger.error(traceback.format_exc())
            return list()


class CStoreManage:
    def __init__(self):
        try:
            # 初始化变量

            # 读取配置文件。
            config = configparser.ConfigParser()
            config.read(g_store_ini_path)
            self.co_guid = config['main']['CO_GUID']
            _logger.debug(self.co_guid)
            self.product_guid = config['main']['Product_GUID']
            _logger.debug(self.product_guid)

            # 包含分区列表。
            self.include_partition_num = config['include_partiton']['num']
            self.include_partition_list = list()
            for i in range(int(self.include_partition_num)):
                self.include_partition_list.append(config['include_partiton']['vol_uuid_' + str(i)])
            _logger.debug(self.include_partition_list)

            # 排除磁盘列表。
            self.exclude_disk_num = config['exclude_disk']['num']
            self.exclude_disk_list = list()
            for i in range(int(self.exclude_disk_num)):
                self.exclude_disk_list.append(config['exclude_disk']['disk_uuid_' + str(i)])
            _logger.debug(self.exclude_disk_list)

            self.extern_store = CExternStore()
        except:
            _logger.error(traceback.format_exc())

    # return 0:是磁盘。
    # return num:是分区num号
    # return < 0:错误
    def __chk_is_iscsi_disk_or_partiton(self, str):
        try:
            _logger.debug("str=%s:len(str)=%d" % (str, len(str)))
            if 's' != str[0]: return -1
            if 'd' != str[1]: return -1
            if str[2] < 'a': return -1
            if str[2] > 'z': return -1
            if 3 == len(str): return 0
            return int(str[3:])
        except:
            _logger.error(traceback.format_exc())
            return -1

    def __get_vol_or_disk_size(self, vol_or_disk_str):
        try:
            (ret, lines) = show_and_exe_cmd_line_and_get_ret(
                in_cmd_line='parted -a optimal "' + vol_or_disk_str + '" print | grep "' + vol_or_disk_str + '"',
                chk_err_str='', bPrint=False)
            if ret == -1: return None
            for i in lines:
                if -1 != i.find('Disk'):
                    size = get_sub_str_by_name(i, ': ', None, False)
                    if size is not None:
                        return size.strip('\n')
                    return None
            return None
        except:
            _logger.error(traceback.format_exc())
            return None

    def __get_vol_or_disk_model(self, vol_or_disk_str):
        try:
            (ret, lines) = show_and_exe_cmd_line_and_get_ret(
                in_cmd_line='parted -a optimal "' + vol_or_disk_str + '" print | grep Model', chk_err_str='',
                bPrint=False)
            if ret == -1: return None
            for i in lines:
                if -1 != i.find('Model'):
                    size = get_sub_str_by_name(i, ': ', None, False)
                    if size is not None:
                        return size.strip('\n')
                    return None
            return None
        except:
            _logger.error(traceback.format_exc())
            return None

    def __get_vol_mount_path(self, vol_str):
        try:
            (ret, lines) = show_and_exe_cmd_line_and_get_ret('mount|grep "' + vol_str + '"')
            if ret == -1: return None
            for i in lines:
                return get_sub_str_by_name(i, 'on ', ' ', False)
            return None
        except:
            _logger.error(traceback.format_exc())
            return None

    def __get_disk_first_partition_info_in_2list(self, search_disk, ll_list, blk_list):
        try:
            # 查找第一个分区。
            first_partiton_str = search_disk + '1'
            ll_one = None
            blk_one = None
            for i in ll_list:
                if i[5] == first_partiton_str:
                    ll_one = i
            for i in blk_list:
                if i[0] == first_partiton_str:
                    blk_one = i
            return first_partiton_str, ll_one, blk_one
        except:
            _logger.error(traceback.format_exc())
            return None, None, None

    def __get_co_product_guid_by_label(self, label):
        try:
            co_guid = None
            product_guid = None
            if label is None:
                return co_guid, product_guid
            label_len = len(label)
            if label_len <= 4:
                co_guid = label
                product_guid = None
                return co_guid, product_guid
            co_guid = label[:4]
            product_guid = label[4:]
            return co_guid, product_guid
        except:
            _logger.error(traceback.format_exc())
            return None, None

    def check_partiton_or_disk_is_real_exist(self, partiton_str):
        try:
            if partiton_str is None:
                return False
            ret, lines = show_and_exe_cmd_line_and_get_ret(
                in_cmd_line='dd if=' + partiton_str + ' of=/dev/null bs=1 count=1', bPrint=False)
            if ret < 0:
                return False
            for one_line in lines:
                if -1 != one_line.find('0 bytes (0 B) copied'):
                    return False
                elif -1 != one_line.find('No such file or directory'):
                    return False
                elif -1 != one_line.find('No such device or address'):
                    return False
            return True
        except:
            _logger.error(traceback.format_exc())
            return False

    def enable_sys_scan_scsi(self):
        try:
            host_list = os.listdir(r'/sys/class/scsi_host')
            for one_host in host_list:
                cmd = 'echo "- - -" > /sys/class/scsi_host/' + one_host + '/scan'
                # _logger.info(cmd)
                os.system(cmd)
        except:
            _logger.error(traceback.format_exc())

    def link_two_list_by_dev(self, search_disk, ll_list, blk_list, enum_list, bIsXen):
        if bIsXen:
            # _logger.debug('xen search_disk = {}'.format(search_disk))
            for j in blk_list:
                if j[0] is not None:
                    if -1 != j[0].lower().find(search_disk):
                        bHaveInsertOneDisk = False
                        for one_have_insert in enum_list:
                            if one_have_insert[5] == search_disk:
                                bHaveInsertOneDisk = True
                                break
                        if bHaveInsertOneDisk:
                            continue
                        enum_one = list()
                        enum_one.append(True)
                        enum_one.append(None)
                        enum_one.append(None)
                        enum_one.append(None)
                        enum_one.append(None)
                        enum_one.append(search_disk)
                        enum_one.append(self.__get_vol_or_disk_size(search_disk))
                        enum_one.append(self.__get_vol_or_disk_model(search_disk))
                        (first_partiton_str, ll_one, blk_one) = self.__get_disk_first_partition_info_in_2list(
                            search_disk, ll_list, blk_list)
                        _logger.debug("ll_one is {}".format(ll_one))
                        _logger.debug("blk_one is {}".format(blk_one))
                        if blk_one is not None:
                            enum_one.append(True)
                            enum_one.append(blk_one[0])
                            (co_guid, product_guid) = self.__get_co_product_guid_by_label(blk_one[1])
                            enum_one.append(co_guid)
                            enum_one.append(product_guid)
                            enum_one.append(blk_one[2])
                            mount_path = self.__get_vol_mount_path(blk_one[0])
                            if mount_path is not None:
                                enum_one.append(True)
                            else:
                                enum_one.append(False)
                            enum_one.append(mount_path)
                        else:
                            enum_one.append(False)
                            enum_one.append(None)
                            enum_one.append(None)
                            enum_one.append(None)
                            enum_one.append(None)
                            enum_one.append(False)
                            enum_one.append(None)
                        _logger.debug('xen will link 2 list append enum_one = {}'.format(enum_one))
                        enum_list.append(enum_one)
        else:
            # _logger.debug('search_disk = {}'.format(search_disk))
            for j in ll_list:
                if search_disk == j[5]:
                    enum_one = list()
                    if 'pci' == j[0]:
                        enum_one.append(True)
                    else:
                        enum_one.append(False)
                    enum_one.append(j[1])
                    enum_one.append(j[2])
                    enum_one.append(j[3])
                    enum_one.append(j[4])
                    enum_one.append(j[5])
                    enum_one.append(self.__get_vol_or_disk_size(j[5]))
                    enum_one.append(self.__get_vol_or_disk_model(j[5]))
                    (first_partiton_str, ll_one, blk_one) = self.__get_disk_first_partition_info_in_2list(
                        search_disk, ll_list, blk_list)
                    # _logger.debug("ll_one is {}".format(ll_one))
                    # _logger.debug("blk_one is {}".format(blk_one))
                    if ll_one is not None and blk_one is not None:
                        enum_one.append(True)
                        enum_one.append(blk_one[0])
                        (co_guid, product_guid) = self.__get_co_product_guid_by_label(blk_one[1])
                        enum_one.append(co_guid)
                        enum_one.append(product_guid)
                        enum_one.append(blk_one[2])
                        mount_path = self.__get_vol_mount_path(blk_one[0])
                        if mount_path is not None:
                            enum_one.append(True)
                        else:
                            enum_one.append(False)
                        enum_one.append(mount_path)
                    else:
                        enum_one.append(False)
                        enum_one.append(None)
                        enum_one.append(None)
                        enum_one.append(None)
                        enum_one.append(None)
                        enum_one.append(False)
                        enum_one.append(None)
                    _logger.debug('will link 2 list append enum_one = {}'.format(enum_one))
                    enum_list.append(enum_one)

    def gen_one_enum_info_by_2_list_and_dev_path(self, bIsLocal, ip, port, iqn, lun, dev_path, ll_list, blk_list):
        bRet = self.check_partiton_or_disk_is_real_exist(dev_path)
        if bRet is not True:
            _logger.debug('{} is not real disk'.format(dev_path))
            return False, list()

        enum_one = list()
        enum_one.append(bIsLocal)
        enum_one.append(ip)
        enum_one.append(port)
        enum_one.append(iqn)
        enum_one.append(lun)
        enum_one.append(dev_path)
        enum_one.append(self.__get_vol_or_disk_size(dev_path))
        enum_one.append(self.__get_vol_or_disk_model(dev_path))
        (first_partiton_str, ll_one, blk_one) = self.__get_disk_first_partition_info_in_2list(
            dev_path, ll_list, blk_list)
        if blk_one is not None:
            enum_one.append(True)
            enum_one.append(blk_one[0])
            (co_guid, product_guid) = self.__get_co_product_guid_by_label(blk_one[1])
            enum_one.append(co_guid)
            enum_one.append(product_guid)
            enum_one.append(blk_one[2])
            mount_path = self.__get_vol_mount_path(blk_one[0])
            if mount_path is not None:
                enum_one.append(True)
            else:
                enum_one.append(False)
            enum_one.append(mount_path)
        else:
            enum_one.append(False)
            enum_one.append(None)
            enum_one.append(None)
            enum_one.append(None)
            enum_one.append(None)
            enum_one.append(False)
            enum_one.append(None)
        _logger.debug('will add one_info to enum_list = {}'.format(enum_one))
        return True, enum_one

    def Enum(self):
        try:
            allow_disk_name_list = ['sd', 'vd', 'xvd']
            self.enable_sys_scan_scsi()
            bIsXen = False
            # 先通过blkid获取所有分区。
            (ret, lines) = show_and_exe_cmd_line_and_get_ret("blkid")
            if ret < 0: return -1
            blk_list = list()
            for i in lines:
                # _logger.debug(i)
                blk_one = list()
                blk_one.append(get_sub_str_by_name(i, None, ':'))
                if blk_one[0] is not None:
                    if -1 != blk_one[0].lower().find('/dev/xvd'):
                        bIsXen = True
                uuid = get_sub_str_by_name(i, 'UUID="', '"')
                # _logger.debug("uuid = %s" % (uuid))
                partuuid = get_sub_str_by_name(i, 'PARTUUID="', '"')
                # _logger.debug("partuuid = %s" % (partuuid))
                label = get_sub_str_by_name(i, 'LABEL="', '"')
                # _logger.debug("label = %s" % (label))
                partlabel = get_sub_str_by_name(i, 'PARTLABEL="', '"')
                # _logger.debug("partlabel = %s" % (partlabel))
                type = get_sub_str_by_name(i, 'TYPE="', '"')
                # _logger.debug("type = %s" % (type))
                parttype = get_sub_str_by_name(i, 'PTTYPE="', '"')
                # _logger.debug("parttype = %s" % (parttype))
                if partlabel is not None:
                    blk_one.append(partlabel)
                else:
                    blk_one.append(label)
                if partuuid is not None:
                    blk_one.append(partuuid)
                else:
                    blk_one.append(uuid)
                if parttype is not None:
                    blk_one.append(parttype)
                else:
                    blk_one.append(type)

                bRet = self.check_partiton_or_disk_is_real_exist(blk_one[0])
                if bRet:
                    # _logger.debug(blk_one)
                    blk_list.append(blk_one)
                else:
                    _logger.debug('check partiton is not exist')
                    _logger.debug(blk_one)

            ll_list = list()
            if bIsXen is not True:
                # 通过 ll /dev/disk/by-path/ 获取
                (ret, lines) = show_and_exe_cmd_line_and_get_ret("ls -l /dev/disk/by-path/ | awk '{print $9,$11}'")
                if ret < 0: return -1
                for i in lines:
                    # _logger.debug("len(i)=%d:one_line=%s" % (len(i), i))
                    if len(i) < 3: continue
                    ll_one = list()
                    will_search = i

                    tmp = get_sub_str_by_name(will_search, None, '-', False)
                    if 'ip' == tmp:
                        ll_one.append(tmp)
                        will_search = get_sub_str_by_name_r(will_search, None, '-', False)
                        tmp = get_sub_str_by_name(will_search, '-', ':', False)
                        ll_one.append(tmp)

                        will_search = get_sub_str_by_name_r(will_search, '-', ':', False)
                        tmp = get_sub_str_by_name(will_search, ':', '-', False)
                        ll_one.append(tmp)

                        will_search = get_sub_str_by_name_r(will_search, ':', '-', False)
                        tmp = get_sub_str_by_name(will_search, '-iscsi-', '-lun', False)
                        ll_one.append(tmp)

                        will_search = get_sub_str_by_name_r(will_search, '-iscsi-', '-lun', False)
                        tmp = get_sub_str_by_name(will_search, '-', ' ', False)
                        ll_one.append(tmp)

                        will_search = get_sub_str_by_name_r(will_search, '-', ' ', False)
                        tmp = os.path.basename(will_search)
                        ll_one.append('/dev/' + tmp.strip('\n'))

                        bRet = self.check_partiton_or_disk_is_real_exist(ll_one[5])
                        if bRet:
                            _logger.debug('tmp = ip,ll_one = {}'.format(ll_one))
                            ll_list.append(ll_one)
                        else:
                            _logger.debug('tmp = ip,check partiton os disk is not exist,ll_one = {}'.format(ll_one))
                    elif 'pci' == tmp:
                        ll_one.append(tmp)
                        ll_one.append('None')
                        ll_one.append('None')
                        ll_one.append('None')
                        ll_one.append('None')
                        will_search = get_sub_str_by_name_r(will_search, None, ' ', False)
                        tmp = os.path.basename(will_search)
                        ll_one.append('/dev/' + tmp.strip('\n'))

                        bRet = self.check_partiton_or_disk_is_real_exist(ll_one[5])
                        if bRet:
                            _logger.debug('tmp = pci,ll_one = {}'.format(ll_one))
                            ll_list.append(ll_one)
                        else:
                            _logger.debug('tmp = pci,check partiton os disk is not exist,ll_one = {}'.format(ll_one))
                    elif 'virtio' == tmp:
                        ll_one.append('pci')  # 修正输出名字，对应外部要用pci，避免显示出错。
                        ll_one.append('None')
                        ll_one.append('None')
                        ll_one.append('None')
                        ll_one.append('None')
                        will_search = get_sub_str_by_name_r(will_search, None, ' ', False)
                        tmp = os.path.basename(will_search)
                        ll_one.append('/dev/' + tmp.strip('\n'))

                        bRet = self.check_partiton_or_disk_is_real_exist(ll_one[5])
                        if bRet:
                            _logger.debug('tmp = virtio,ll_one = {}'.format(ll_one))
                            ll_list.append(ll_one)
                        else:
                            _logger.debug('tmp = virtio,check partiton os disk is not exist,ll_one = {}'.format(ll_one))

            # 此list 未能去重。
            enum_list = list()

            # 添加系统默认卷
            for i in self.include_partition_list:
                for j in blk_list:
                    # _logger.debug('i=%s:j[2]=%s' % (i, j[2]))
                    if i == j[2]:
                        enum_one = list()
                        # 根据GUID 找到 卷名，填写结构体。
                        enum_one.append(True)
                        enum_one.append(None)
                        enum_one.append(None)
                        enum_one.append(None)
                        enum_one.append(None)
                        enum_one.append(j[0])
                        enum_one.append(self.__get_vol_or_disk_size(j[0]))
                        enum_one.append(self.__get_vol_or_disk_model(j[0]))
                        enum_one.append(True)
                        enum_one.append(j[0])
                        enum_one.append(self.co_guid)
                        enum_one.append(self.product_guid)
                        enum_one.append(j[2])
                        mount_path = self.__get_vol_mount_path(j[0])
                        if mount_path is not None:
                            enum_one.append(True)
                        else:
                            enum_one.append(False)
                        enum_one.append(mount_path)
                        _logger.debug('will add one_info to enum_list = {}'.format(enum_one))
                        enum_list.append(enum_one)
            # 将两个列表联系在一起。
            for one_allow_disk_name in allow_disk_name_list:
                for i in range(26):
                    search_disk = '/dev/' + one_allow_disk_name
                    search_disk += chr(i + ord('a'))
                    # _logger.debug('will search_disk = %s' % (search_disk))
                    self.link_two_list_by_dev(search_disk, ll_list, blk_list, enum_list, bIsXen)

            # 插入 lsblk 查找到，但是 enum_list 没有找到的磁盘分区
            (ret, lines) = show_and_exe_cmd_line_and_get_ret("lsblk|grep disk|awk {'print $1'}")
            if ret < 0: return -1
            for one_line in lines:
                disk_name = one_line.strip()
                bSearchDisk = False
                for one_allow_disk_name in allow_disk_name_list:
                    if 0 == disk_name.lower().find(one_allow_disk_name):
                        bSearchDisk = True
                        break
                if bSearchDisk is not True:
                    _logger.debug('lsblk name not allow,disk_name = {}'.format(disk_name))
                    continue
                will_proc_disk = '/dev/' + disk_name
                bSearchDisk = False
                for one_enum in enum_list:
                    if -1 != one_enum[5].upper().find(will_proc_disk.upper()):
                        bSearchDisk = True
                        break
                if bSearchDisk:
                    _logger.debug('lsblk find enum_list have same disk = {}'.format(will_proc_disk))
                    continue
                _logger.debug('can not find lsblk in enum_list = {}'.format(will_proc_disk))
                ret, new_enum_one = self.gen_one_enum_info_by_2_list_and_dev_path(True, None, None, None, None,
                                                                                  will_proc_disk, ll_list, blk_list)
                if ret:
                    enum_list.append(new_enum_one)

            # ls -l /dev/disk/by-path/
            # ci-0000:00:04.0-scsi-0:0:1:0 -> ../../sda
            # virtio-pci-0000:00:04.0-scsi-0:0:1:0 -> ../../sda
            # 以上导致磁盘重复。需要删除相同的磁盘分区硬盘。
            ret_list = list()
            for enum_one in enum_list:
                bFind = False
                for one_ret in ret_list:
                    if enum_one[5] == one_ret[5]:
                        _logger.debug('enum_list find same disk = {}'.format(enum_one))
                        bFind = True
                        break
                if not bFind:
                    ret_list.append(enum_one)

            # 必须在上面删除重复磁盘后处理，否则以下清除磁盘代码，如果有重复会无效。
            # 从以上列表中删除多路径对应的普通磁盘，再加入多路径磁盘信息。
            multi_path = CMultipath()
            multipath_list = multi_path.get_multipath_list()
            _logger.debug('enum_list get_multipath_list = {}'.format(multipath_list))
            for one_multipath in multipath_list:
                nor_disk_list = multi_path.get_nor_disk_list_by_multipath(one_multipath)
                _logger.debug('enum_list get_nor_disk_list_by_multipath = {}'.format(nor_disk_list))
                # 找到多路径对应的普通磁盘列表项，删除。
                for i in nor_disk_list:
                    for j in range(len(ret_list)):
                        # _logger.debug('i={},enum_list[j][12]={}'.format(i, enum_list[j][12]))
                        if i == ret_list[j][5]:
                            _logger.debug('multipath will del enum_list[{}]'.format(i))
                            del ret_list[j]
                            break
                # 将多路径加入到找到的列表中。
                ret, new_enum_one = self.gen_one_enum_info_by_2_list_and_dev_path(True, None, None, None, None,
                                                                                  one_multipath, ll_list, blk_list)
                if ret:
                    ret_list.append(new_enum_one)

            # 删除需要排除的硬盘。
            for i in self.exclude_disk_list:
                for j in range(len(ret_list)):
                    # _logger.debug('i={},enum_list[j][12]={}'.format(i, enum_list[j][12]))
                    if i == ret_list[j][12]:
                        _logger.debug('will del enum_list[{}]'.format(i))
                        del ret_list[j]
                        break
            # 因为blkid枚举加密磁盘/dev/sda1会造成偶尔失败，导致没有排除/dev/sda，进而初始化/dev/sda导致数据丢失。
            # 因此在这里强制排除/dev/sda
            # for j in range(len(enum_list)):
            #     if '/dev/sda' == enum_list[j][5]:
            #         del enum_list[j]
            #         break
            # _logger.debug(enum_list)
            # _logger.debug('enum_list = {}'.format(enum_list))

            # 查看枚举出来的结果，  cat logic_service.log |grep enum_storage
            return ret_list
        except:
            _logger.error(traceback.format_exc())
            return None

    # 需要返回。连接是成功，还是失败。
    def __login_one(self, one_req):
        try:
            _logger.debug('__login_one')
            if one_req is None:
                return -1
            if one_req[0] == True:
                return -1, None

            return self.extern_store.iscsi_con(one_req[1], one_req[2], one_req[3], one_req[4], one_req[5])
        except:
            _logger.error(traceback.format_exc())
            return -1, None

    def __unlogin_one(self, one_enum):
        try:
            _logger.debug('__unlogin_one')
            if one_enum is None:
                return -1
            if one_enum[0] == True:
                return -1
            self.extern_store.del_node_by_iqn(one_enum[3])
        except:
            _logger.error(traceback.format_exc())
            return -1

    def __get_one_enum_dev_by_GUID(self, enum_list, guid):
        try:
            for i in enum_list:
                if guid == i[12]:
                    return i
            return None
        except:
            _logger.error(traceback.format_exc())
            return None

    def __get_one_req_by_GUID(self, req_list, guid):
        try:
            for i in req_list:
                if guid == i[8]:
                    return i
            return None
        except:
            _logger.error(traceback.format_exc())
            return None

    def __check_have_same_ip_and_port_by_enum_list(self, ip, port, enum_list):
        try:
            for i in enum_list:
                _logger.debug(i)
                if ip == i[1] and port == i[2]:
                    return True
            return False
        except:
            _logger.error(traceback.format_exc())
            return False

    def __check_have_same_ip_and_port_by_req_list(self, ip, port, req_list):
        try:
            for i in req_list:
                _logger.debug(i)
                if ip == i[1] and port == i[2]:
                    return True
            return False
        except:
            _logger.error(traceback.format_exc())
            return False

    def __loop_wait_iscsi_disk_dev_ready(self, ip, port):
        try:
            while True:
                _logger.debug('__loop_wait_iscsi_disk_dev_ready loop wait iscsi dev ready!')
                time.sleep(1)
                (ret, lines) = show_and_exe_cmd_line_and_get_ret('ls -l /dev/disk/by-path/')
                for i in lines:
                    if -1 != i.find(ip):
                        _logger.debug('__loop_wait_iscsi_disk_dev_ready loop wait find iscsi dev ok!')
                        return
        except:
            _logger.error(traceback.format_exc())
            return False

    # ========================================================================================================
    # 1：如果请求多于枚举，这个时候是要进行连接。
    # 1.1：如果是本地。
    # 1.1.1：查找枚举出来的设备，有设备，mount.
    # 1.1.2：查找枚举出来的设备，没有设备不处理。
    #
    # 1.2：如果是ip.
    # 1.2.1：查找枚举出来的设备，有设备，mount.
    # 1.2.2：查找枚举出来的设备，没有设备
    # 1.2.2.1：已有相同IP，端口的设备存在。那么不予理会
    # 1.2.2.2：没有相同IP，端口的设备存在。那么，开始连接。连接成功后，再次枚举设备，如果找到设备mount.否则不处理。
    #
    # ========================================================================================================
    # 2：如果请求设备少于枚举。
    # 2.1：如果是本地。
    # 2.1.1：查找出来的设备，有设备，unmount.
    # 2.1.2：如果没有设备，不处理。
    #
    # 2.2：如果是ip
    # 2.2.1：查找枚举出来的设备。如果有设备，unmount
    # 2.2.2:如果没有设备不处理。
    #
    # 2.2.3：查找是否还有其他相同IP,端口，有不处理。
    # 2.2.4：如果没有，断开连接。
    # ========================================================================================================
    # one_req2 = [False, '172.16.6.74', '3260', True, 'aaa', 'aaaaaaaaaaaa',
    #             'iqn.1991-05.com.microsoft:win-3r1rf354uo3-wolf-target', 'lun-0', '4ABC8020BC8008A1', '/mnt/sdd1']
    # 内外，IP,port,char,username,password,iqn,lun,分区guid,分区号。
    # 1:
    def Refresh_Status(self, req_list):
        try:
            ret_list = list()
            enum_list = self.Enum()
            for one_req in req_list:
                one_enum = self.__get_one_enum_dev_by_GUID(enum_list, one_req[8])
                if one_enum is not None:  # 从一个请求中查找是否有一个枚举设备。
                    # 从一个请求中查找是否有一个枚举设备。有枚举设备
                    # _logger.debug('Refresh_Status one_enum is not None,one_req = ')
                    # _logger.debug(one_req)
                    # _logger.debug(one_enum)
                    # 无论是本地设备，还是远程设备。
                    if one_enum[14] is not None:
                        # 已经被mount,不处理。
                        _logger.debug('have mount')
                        pass
                    else:
                        # 未被mount，开始mount
                        show_and_exe_cmd_line_and_get_ret('mount ' + one_enum[9] + ' ' + one_req[9])
                else:
                    # 从一个请求中查找是否有一个枚举设备。没有枚举设备
                    _logger.debug('Refresh_Status one_enum is None,one_req = ')
                    _logger.debug(one_req)
                    if one_req[0] is True:
                        # 本地设备，查不到。不处理。
                        pass
                    else:
                        # 远程设备
                        # 检查是否有其他IP,端口设备存在，如果有，这种错误不处理。否则开始连接。
                        if self.__check_have_same_ip_and_port_by_enum_list(one_req[1], one_req[2], enum_list):
                            _logger.debug('have same ip ')
                        else:
                            _logger.debug('no same ip ')
                            if 0 == self.__login_one(one_req):
                                # 连接成功后，重新枚举，再检查出来的设备，是否有相同GUID。
                                _logger.debug('connect success !re enum !')
                                self.__loop_wait_iscsi_disk_dev_ready(one_req[1], one_req[2])
                                enum_list_2 = self.Enum()
                                one_enum = self.__get_one_enum_dev_by_GUID(enum_list_2, one_req[8])
                                if one_enum is not None:
                                    _logger.debug("find same guid device")
                                    # 无论是本地设备，还是远程设备。
                                    if one_enum[14] is not None:
                                        # 已经被mount,不处理。
                                        _logger.debug('have mount ')
                                    else:
                                        # 未被mount，开始mount
                                        show_and_exe_cmd_line_and_get_ret('mount ' + one_enum[9] + ' ' + one_req[9])
                                else:
                                    # 重新连接了，都没有设备，不管了。
                                    _logger.debug("can not find same guid device!")
                            else:
                                # 连接失败，不管了。
                                _logger.debug("connect failed!")
            for one_enum in enum_list:
                _logger.debug('one_enum = ')
                _logger.debug(one_enum)
                one_req = self.__get_one_req_by_GUID(req_list, one_enum[12])
                if one_req is not None:
                    # 有请求不处理，因为两边都有的话，上面已经处理。
                    _logger.debug("req and enum have same guid=%s" % (one_enum[12]))
                    pass
                else:
                    _logger.debug("only enum have guid=%s" % (one_enum[12]))
                    if one_enum[0] is True:
                        # 本地设备，需要umount.
                        _logger.debug('local dev need umount one_enum[14] = %s' % (one_enum[14]))
                        if one_enum[14] != None:
                            show_and_exe_cmd_line_and_get_ret(r'fuser -k "{}"'.format(one_enum[9]))
                            show_and_exe_cmd_line_and_get_ret(r'fuser -k "{}"'.format(one_enum[9]))
                            show_and_exe_cmd_line_and_get_ret(r'fuser -k "{}"'.format(one_enum[9]))
                            show_and_exe_cmd_line_and_get_ret('umount ' + one_enum[9])
                    else:
                        # 检查是否有其他IP,端口设备存在，如果有，这种错误不处理。否则开始连接。
                        if self.__check_have_same_ip_and_port_by_req_list(one_enum[1], one_enum[2], req_list):
                            # 已经有相同ip,port设备存在。不处理。
                            _logger.debug('have same ip = %s,port = %s' % (one_enum[1], one_enum[2]))
                            pass
                        else:
                            # 断开连接。
                            _logger.debug('no same ip = %s,port = %s' % (one_enum[1], one_enum[2]))
                            self.__unlogin_one(one_enum)
        except:
            _logger.error(traceback.format_exc())
            return None

    def InitDisk(self, disk_str):
        try:
            disk_class = CDisk()
            disk_class.set_disk(disk_str)
            disk_class.ReInitDisk_by_one_partiton(self.co_guid, self.product_guid)
        except:
            _logger.error(traceback.format_exc())

    # 成功 0
    # 失败 -1
    def mount(self, dev_str, dir_str):
        try:
            now_mount = self.__get_vol_mount_path(dev_str)
            if now_mount is not None:
                if now_mount == dir_str:
                    return 0
            # show_and_exe_cmd_line_and_get_ret('xfs_repair -L ' + dev_str)
            # show_and_exe_cmd_line_and_get_ret('xfs_repair ' + dev_str)
            ret, lines = show_and_exe_cmd_line_and_get_ret(
                'mount -o defaults,noatime,nodiratime ' + dev_str + ' ' + dir_str, 'mount')
            if ret != 0:
                _logger.debug('can not mount,xfs_repair -L ' + dev_str)
                show_and_exe_cmd_line_and_get_ret('xfs_repair -L ' + dev_str)

            return ret
        except:
            _logger.error(traceback.format_exc())
            return -1

    # 成功 0
    # 失败 -1
    def umount(self, dev_str, async=False):
        try:
            retry_times = 60
            ret = 0
            while (self.__get_vol_mount_path(dev_str) is not None) and retry_times > 0:
                show_and_exe_cmd_line_and_get_ret(r'fuser -k "{}"'.format(dev_str))
                show_and_exe_cmd_line_and_get_ret(r'fuser -k "{}"'.format(dev_str))
                show_and_exe_cmd_line_and_get_ret(r'fuser -k "{}"'.format(dev_str))
                ret, lines = show_and_exe_cmd_line_and_get_ret('umount ' + dev_str, 'umount')
                if ret == -1:
                    ret, lines = show_and_exe_cmd_line_and_get_ret('umount -f ' + dev_str, 'umount')
                if ret == -1 and async:
                    ret, lines = show_and_exe_cmd_line_and_get_ret('umount -r ' + dev_str, 'umount')
                    return ret
                else:
                    time.sleep(1)
                    retry_times -= 1
            return ret
        except:
            _logger.error(traceback.format_exc())

    # 成功 iqn
    # 失败 None
    def get_local_iqn(self):
        try:
            ret, lines = show_and_exe_cmd_line_and_get_ret('cat /etc/iscsi/initiatorname.iscsi | grep InitiatorName')
            if ret != 0: return None
            for one_line in lines:
                if -1 != one_line.find('InitiatorName'):
                    ret_str = get_sub_str_by_name(one_line.strip('\n'), 'InitiatorName=', None)
                    _logger.debug('get_local_iqn = {}'.format(ret_str))
                    return ret_str
            return None
        except:
            _logger.error(traceback.format_exc())
            return None

    # return 0
    # return -1:
    # return -2:iqn 字符串不是以 “iqn.” 开头 注意是4个字符
    def set_local_iqn(self, iqn):
        try:
            if iqn is None: return -1
            if len(iqn) < 5: return -1
            if 'iqn.' != iqn[:4]:
                return -2
            with open('/etc/iscsi/initiatorname.iscsi', 'r') as file_handle:
                lines = file_handle.readlines()

            with open('/etc/iscsi/initiatorname.iscsi', 'w') as file_handle:
                for one_line in lines:
                    if -1 != one_line.find('InitiatorName='):
                        file_handle.writelines('InitiatorName=' + iqn + '\n')
                    else:
                        file_handle.writelines(one_line)
                show_and_exe_cmd_line_and_get_ret('systemctl restart iscsid.service')
                show_and_exe_cmd_line_and_get_ret(' systemctl restart iscsi.service')
                return 0
        except:
            _logger.error(traceback.format_exc())
            return -1

    # return 0,iqn
    # return -1,None
    def login_one(self, remote_ip, remote_port, bUseCHAP, user_name, password):
        return self.extern_store.iscsi_con(remote_ip, remote_port, bUseCHAP, user_name, password)

    # 输入：如果用户名，密码有任何一项为None 会清除配置文件。
    # return 0
    # return -1:
    def set_global_double_chap(self, user_name_in, password_in):
        try:
            with open('/etc/iscsi/iscsid.conf', 'r') as file_handle:
                lines = file_handle.readlines()
            with open('/etc/iscsi/iscsid.conf', 'w') as file_handle:
                if user_name_in is None or password_in is None or 0 == len(user_name_in) or 0 == len(password_in):
                    for one_line in lines:
                        if -1 != one_line.find('node.session.auth.username_in'):
                            file_handle.writelines('#node.session.auth.username_in = username_in\n')
                        elif -1 != one_line.find('node.session.auth.password_in'):
                            file_handle.writelines('#node.session.auth.password_in = password_in\n')
                        else:
                            file_handle.writelines(one_line)
                    show_and_exe_cmd_line_and_get_ret('systemctl restart iscsid.service')
                    show_and_exe_cmd_line_and_get_ret(' systemctl restart iscsi.service')
                    return 0

                bFindUserNameIn = False
                bFindPasswordIn = False
                for one_line in lines:
                    if -1 != one_line.find('node.session.auth.username_in'):
                        bFindUserNameIn = True
                        file_handle.writelines('node.session.auth.username_in = ' + user_name_in + '\n')
                    elif -1 != one_line.find('node.session.auth.password_in'):
                        bFindPasswordIn = True
                        file_handle.writelines('node.session.auth.password_in = ' + password_in + '\n')
                    else:
                        file_handle.writelines(one_line)
                if bFindUserNameIn is not True:
                    file_handle.writelines('node.session.auth.username_in = ' + user_name_in + '\n')
                if bFindPasswordIn is not True:
                    file_handle.writelines('node.session.auth.password_in = ' + password_in + '\n')
                show_and_exe_cmd_line_and_get_ret('systemctl restart iscsid.service')
                show_and_exe_cmd_line_and_get_ret(' systemctl restart iscsi.service')
                return 0
            return -1
        except:
            _logger.error(traceback.format_exc())
            return -1

    def get_global_double_chap(self):
        username_in = None
        password_in = None
        try:
            ret, lines = show_and_exe_cmd_line_and_get_ret(
                "cat /etc/iscsi/iscsid.conf |grep node.session.auth.username_in|awk {'print $3'}")
            if ret == 0:
                for one_line in lines:
                    _logger.debug(one_line)
                    if len(one_line) > 1:
                        username_in = one_line.strip('\n')
                        _logger.debug('1:username_in = {}'.format(username_in))
                        if username_in == 'username_in':
                            username_in = None
                            _logger.debug('2:username_in = {}'.format(username_in))
                        break

            ret, lines = show_and_exe_cmd_line_and_get_ret(
                "cat /etc/iscsi/iscsid.conf |grep node.session.auth.password_in|awk {'print $3'}")
            if ret == 0:
                for one_line in lines:
                    if len(one_line) > 1:
                        _logger.debug(one_line)
                        password_in = one_line.strip('\n')
                        _logger.debug('1:password_in = {}'.format(password_in))
                        if password_in == 'password_in':
                            password_in = None
                            _logger.debug('2:password_in = {}'.format(password_in))
                        break
            _logger.debug('end:username_in = {},password_in = {}'.format(username_in, password_in))
            return username_in, password_in
        except:
            _logger.error(traceback.format_exc())
            return username_in, password_in

    def rescan_all(self):
        try:
            show_and_exe_cmd_line_and_get_ret(' iscsiadm -m session --rescan')
        except:
            _logger.error(traceback.format_exc())

    def rescan_one(self, iqn):
        try:
            ret, lines = show_and_exe_cmd_line_and_get_ret("iscsiadm -m session | grep " + iqn + " |awk {'print $2'}")
            for one_line in lines:
                num = one_line.strip('[')
                num = num.strip(']\n')
                show_and_exe_cmd_line_and_get_ret('iscsiadm -m session --sid=' + num + ' --rescan')
        except:
            _logger.error(traceback.format_exc())


if __name__ == "__main__":
    xlogging.basicConfig(stream=sys.stdout, level=xlogging.DEBUG)
    cur_file_dir_str = cur_file_dir()
    os.chdir(cur_file_dir_str)
    # =========================================================================================
    # extern_class = CExternStore()
    # _logger.debug(
    #     extern_class.iscsi_con('172.16.2.104', 3261, True, "iqn.1994-05.com.redhat:7e2268c57fd", "abc1234567890"))
    # _logger.debug(extern_class.iscsi_show())
    # time.sleep(5)
    # for one_line in all_line:
    #      _logger.debug(extern_class.del_node_by_show_one_line(one_line))
    # =========================================================================================
    #     disk = CDisk()
    #     disk.set_disk('/dev/sdb')
    #     disk.ReInitDisk()
    # =========================================================================================
    store_manage = CStoreManage()
    store_manage.Enum()
    # one_req1 = [True, None, None, None, None, None, None, None,
    #             'd82fcb7e-7ed3-4054-88ca-e7a850237f1d', '/mnt/sdc']
    # reqs = [one_req1]
    # store_manage.Refresh_Status(reqs)
    #
    # one_req1 = [True, None, None, None, None, None, None, None,
    #             'd82fcb7e-7ed3-4054-88ca-e7a850237f1d', '/mnt/sdc']
    # one_req2 = [False, '172.16.6.74', '3260', True, 'aaa', 'aaaaaaaaaaaa',
    #             'iqn.1991-05.com.microsoft:win-3r1rf354uo3-wolf-target', 'lun-0', '4ABC8020BC8008A1', '/mnt/sdd1']
    # reqs = [one_req1, one_req2]
    # store_manage.Refresh_Status(reqs)
    # store_manage.InitDisk('/dev/sdc')
    # _logger.debug(store_manage.set_local_iqn('iqn.abcedfg'))
    # store_manage.set_global_double_chap('bbb', 'bbbbbbbbbbbb')
    # store_manage.rescan_one('iqn.1991-05.com.microsoft:win-3r1rf354uo3-wolf-target')
    # _logger.debug(store_manage.check_partiton_or_disk_is_real_exist('/dev/sda1'))
    # _logger.debug(store_manage.check_partiton_or_disk_is_real_exist('/dev/sdb1'))
    # _logger.debug(store_manage.check_partiton_or_disk_is_real_exist('/dev/sdc1'))
    # _logger.debug(store_manage.check_partiton_or_disk_is_real_exist('/dev/sdd1'))
    # _logger.debug(store_manage.check_partiton_or_disk_is_real_exist('/dev/sde1'))
    # store_manage.set_global_double_chap(None, 'aaaaaaaaaaaa')
    # _logger.debug(store_manage.get_global_double_chap())
    # =========================================================================================
