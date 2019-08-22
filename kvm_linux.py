import base64
import datetime
import hashlib
import json
import os
import random
import re
import shlex
import shutil
import subprocess
import time
import traceback
import uuid
from collections import OrderedDict
from copy import deepcopy

import Ice

import Initramfs
import kvm
import linux_devices
import loadIce
import mod_firmware
import modget
import mount_nbd_linux
import net_common
import save_clrd_initrd
import xdefine
import xlogging
from disk_read_ahead.disk_read_ahead import force_read_ESP_and_MSR_partition_range, read_head_tail_to_2m
from kvm_shell import KVMShell
from linux_config import ModifyConfig
from nbd import nbd_wrapper, nbd_direct_images, nbd_wrapper_local_device_allocator
from qemu_helper import GetQcowFileAlterInfo
from samba import SAMBAMountHandle

_logger = xlogging.getLogger(__name__)

force_install_sbd_driver = os.path.join(loadIce.current_dir, r'disksbd_linux.ko')
force_config_params = os.path.join(loadIce.current_dir, r'kvm_linux.params')
force_config_params_disksbd_linux = r'disksbd_linux.ko'
force_config_params_ip_set = r'ip-set'
over_kvm_flag = '/opt/over_kvm_flag.temp'


@xlogging.convert_exception_to_value('')
def get_force_config_params(key, default_value):
    if not os.path.isfile(force_config_params):
        return default_value
    with open(force_config_params) as f:
        params = json.load(f)
        return params.get(key, default_value)


python_support_so = [
    'lib/libpthread.so.0',
    'lib64/libpthread.so.0',
    'lib/libdl.so.2',
    'lib64/libdl.so.2',
    'lib/libutil.so.1',
    'lib64/libutil.so.1',
    'lib/libc.so.6',
    'lib64/libc.so.6',
    'usr/lib/libz.so.1',
    'usr/lib64/libz.so.1',
    'usr/lib/libbz2.so.1',
    'usr/lib64/libbz2.so.1',
    'lib/libm.so.6',
    'lib64/libm.so.6',
]

key_files = [
    {'path': 'etc/', 'type': 'dir_all'},
    {'path': 'lib/systemd/', 'type': 'dir_all'},
    {'path': 'lib64/systemd/', 'type': 'dir_all'},
    {'path': 'lib/', 'type': 'dir_cur'},
    {'path': 'lib64/', 'type': 'dir_cur'},
    {'path': 'bin/sh', 'type': 'file'},
    {'path': 'bin/bash', 'type': 'file'},
    {'path': 'sbin/init', 'type': 'file'},
    {'path': 'sbin/login', 'type': 'file'},
    {'path': 'lib/firmware', 'type': 'dir_all'},
]


def get_bad_index(content, bad_index, index):
    for i in content:
        if i != 0:
            return bad_index
    bad_index.extend([index, index + 1, index + 2])
    return bad_index


def get_agent_config(bin_path, name):
    config_path = os.path.join(bin_path, "AgentService.config")

    _logger.info("get_agent_config config_path={}".format(config_path))

    if not os.path.exists(config_path):
        _logger.info("get_agent_config config_path={} not exist".format(config_path))
        return None

    initData = Ice.InitializationData()
    initData.properties = Ice.createProperties()
    initData.properties.load(config_path)

    value = initData.properties.getPropertyWithDefault(name, None)

    _logger.info("get_agent_config name={} value={}".format(name, value))

    return value


def get_agent_path(bin_path, root_path, name):
    _logger.info("get_agent_path bin_path={} root_path={}".format(bin_path, root_path))
    path = get_agent_config(bin_path, name)
    if not path:
        return None

    _logger.info("get_agent_path path={}".format(path))

    index = path.find("/")
    if index < 0:
        _logger.info("get_agent_path invalid path={}".format(path))
        return None

    full = os.path.join(root_path, path[index + 1:])

    _logger.info("get_agent_path full={}".format(full))

    return full


def get_clwmeta_path(bin_path, root_path):
    path = get_agent_path(bin_path, root_path, "Agent.ClwMetaPath")
    if not path:
        return None

    clwmeta = os.path.join(path, "ClerWareMeta")

    return clwmeta


def get_bmffile_path(bin_path, root_path):
    return get_agent_path(bin_path, root_path, "Agent.BmfFilePath")


def serch_bmf_file(bmf_dir):
    bmf_file_names = list(filter(lambda x: x.endswith(".bmf") and x.startswith("sbd_"), os.listdir(bmf_dir)))
    if len(bmf_file_names) != 0:
        bmf_file_path_array = [os.path.join(bmf_dir, file_name) for file_name in bmf_file_names]
        return bmf_dir, bmf_file_path_array

    return None, None


def find_bmf_file_imp(bmf_dir_boot, bmf_dir_bin, root_path):
    config_path = get_bmffile_path(bmf_dir_bin, root_path)
    if config_path:
        return serch_bmf_file(config_path)

    path, file = serch_bmf_file(bmf_dir_bin)
    if path:
        return path, file

    path, file = serch_bmf_file(bmf_dir_boot)
    if path:
        return path, file

    xlogging.raise_system_error(r'备份快照中的关键位图区域无效',
                                r'find_bmf_file failed : {},{}'.format(bmf_dir_boot, bmf_dir_bin), 198)


def find_bmf_file(bmf_dir_boot, bmf_dir_bin, root_path):
    """
    :param bmf_dir_boot: boot目录
    :param bmf_dir_bin: bin目录
    :return: bmf_dir_boot or bmf_dir_bin
    """
    path, file = find_bmf_file_imp(bmf_dir_boot, bmf_dir_bin, root_path)
    if path:
        _logger.info(r'find_bmf_file path={}'.format(path))

    return path, file


class kvm_linux(object):
    def __init__(self, pe_ident, boot_disk_token, boot_disk_bytes, boot_device_normal_snapshot_ident, boot_nbd_object,
                 data_nbd_objects, linux_disk_index_info, linux_storage, root_path, linux_info, link_path,
                 restore_config, floppy_path, ipconfigs, kvm_virtual_devices, start_kvm_flag_file, to_hyper_v_one,
                 to_xen, takeover_params, htb_key_data_dir, open_kvm_params):
        """

        :param pe_ident:
        :param boot_disk_token:
        :param boot_disk_bytes:
        :param boot_device_normal_snapshot_ident:
        :param boot_nbd_object:
        :param data_nbd_objects:
        :param linux_disk_index_info:
        :param linux_storage:
        :param root_path:
        :param linux_info:
        :param link_path:
        :param restore_config:
        :param floppy_path:
        :param ipconfigs:
        :param kvm_virtual_devices:
        :param start_kvm_flag_file:
        :param to_hyper_v_one:
        :param to_xen:
        :param takeover_params:
        :param htb_key_data_dir:
        :param open_kvm_params:
        :var self.org_init_ram_fs_path: 源系统的 raminitfs 的路径（在一体机中被挂载的路径）
        :var self.root_path: 源系统的 根 的路径（在一体机中被挂载的路径）
        """
        self.pe_ident = pe_ident
        self.boot_disk_token = boot_disk_token
        self.boot_disk_bytes = boot_disk_bytes
        self.boot_device_normal_snapshot_ident = boot_device_normal_snapshot_ident
        self.boot_nbd_object = boot_nbd_object
        self.data_nbd_objects = data_nbd_objects
        self.linux_disk_index_info = linux_disk_index_info
        self.linux_storage = linux_storage
        self.root_path = root_path  # 快照中的文件系统根的路径
        self.linux_info = linux_info
        self.link_path = link_path
        self.restore_config = restore_config
        self.floppy_path = floppy_path
        self.ipconfigs = ipconfigs
        self.kvm_virtual_devices = kvm_virtual_devices
        self.some_error = None
        self.running = False
        self.mount_wrapper = None
        self.start_kvm_flag_file = start_kvm_flag_file
        self.to_hyper_v_one = to_hyper_v_one
        self.to_xen = to_xen
        self.takeover_params = takeover_params
        self.clw_meta_file = None
        self._samba_mount = None
        self.kvmshell = None
        self.open_kvm_params = open_kvm_params
        self.kvm_pid = None
        self.init_ram_fs_path = os.path.join(self.link_path, 'init_ram_fs')
        # TODO远程启动kvm
        self.remote_kvm_host_object = None
        os.makedirs(self.init_ram_fs_path, exist_ok=True)

        self.htb_key_data_dir = htb_key_data_dir
        if self.htb_key_data_dir:
            os.makedirs(self.htb_key_data_dir, exist_ok=True)

        self.org_init_ram_fs_path = None
        self.initramfs = None

        self.src_disk_alias = linux_storage.get('disk_alias', [])
        self.open_kvm_params['install_path'] = self.linux_info['install_path']

    def get_path_from_key_files(self, file_type):
        items = list(filter(lambda key_file: key_file['type'] == file_type, key_files))
        path_existed = list()
        for item in items:
            item_path = os.path.join(self.root_path, item['path'])
            if os.path.exists(item_path):
                path_existed.append(item_path)
        return path_existed

    def get_reg_file_path_imp(self):

        path = self._get_agent_app_path()
        meta_path = get_clwmeta_path(path, self.root_path)
        if meta_path:
            self.clw_meta_file = meta_path
            return meta_path

        _logger.info(r'get_reg_file_path_imp config path is not exist')

        meta_path = os.path.join(path, 'ClerWareMeta')
        if os.path.exists(meta_path):
            self.clw_meta_file = meta_path
            return meta_path

        _logger.info(r'get_reg_file_path_imp bin path is not exist')

        meta_path = os.path.join(self.root_path, 'boot', 'ClerWareMeta')
        if os.path.exists(meta_path):
            self.clw_meta_file = meta_path
            return meta_path

        xlogging.raise_system_error(r'无法访问备份快照中的关键数据区域',
                                    r'get_reg_file_path_imp failed : {}'.format(meta_path), 1)
        return None

    def _get_reg_file_path(self):

        if self.clw_meta_file:
            return self.clw_meta_file

        meta_path = self.get_reg_file_path_imp()

        _logger.info(r'_get_reg_file_path meta_path={}'.format(meta_path))

        return meta_path

    # 注册表配置文件读一遍
    @staticmethod
    def _read_one_file(file_path):
        meta_path = file_path
        try:
            max_buffer_bytes = 8 * 1024 * 1024
            with open(meta_path, 'rb') as file_handle:
                while True:
                    read_bytes = len(file_handle.read(max_buffer_bytes))
                    _logger.info("file_path = {},read len = {}".format(meta_path, read_bytes))
                    if read_bytes < max_buffer_bytes:
                        break
        except Exception as e:
            _logger.error(r'_read_one_file {} failed. {}'.format(meta_path, e), exc_info=True)

    def _read_all_folder(self):
        cmd = "python /sbin/aio/logic_service/enum_dirs.py -root {} {}".format(self.root_path,
                                                                               self._get_ex_dirs_str(
                                                                               ))
        net_common.get_info_from_syscmd(cmd, 60 * 5)

    # 排除非系统的卷
    def _get_ex_dirs_str(self):
        ex_mount_point = self._samba_mount.mount_point[1:] if self._samba_mount.mount_point and len(
            self._samba_mount.mount_point) > 1 else list()

        return ' '.join(['--ex_dir {}'.format(item) for item in ex_mount_point])

    """
        #起kvm的流程，这部分代码挪到了linux_iso中读取
        def _read_key_files_in_system(self):
        # 预读单个文件
        single_files = self.get_path_from_key_files(file_type='file')
        for file in single_files:
            cmd = r'cat {0} > /dev/null'.format(file)
            net_common.get_info_from_syscmd(cmd, 60 * 5)
        # 预读目录当层文件
        folders = self.get_path_from_key_files(file_type='dir_cur')
        for folder in folders:
            cmd = r'find {0} -maxdepth 1 -type f | tar -cf - -T - | cat > /dev/null'.format(folder)
            net_common.get_info_from_syscmd(cmd, 60 * 5)
        # 预读文件夹内所有(子)文件(<5MB)
        folders = self.get_path_from_key_files(file_type='dir_all')
        for folder in folders:
            cmd = r'find {0} -type f -size -5M | tar -cf - -T - | cat > /dev/null'.format(folder)
            net_common.get_info_from_syscmd(cmd, 60 * 5)
    """

    def _wait_all_nbd_read_ok(self):
        nbd_wrapper.wait_nbd_read_ok(self.boot_nbd_object)

        for data_nbd_object in self.data_nbd_objects:
            nbd_wrapper.wait_nbd_read_ok(data_nbd_object['nbd_object'])

    def _read_clw_boot_redirct_gpt_disk(self):
        for data_nbd_object in self.data_nbd_objects:
            if data_nbd_object['data_device']['normal_snapshot_ident'] == xdefine.CLW_BOOT_REDIRECT_GPT_LINUX_UUID:
                break
        else:
            return False
        _logger.info('_read_clw_boot_redirct_gpt_disk find clwbootdisk data_nbd_object:{}'.format(data_nbd_object, ))
        with open('/sbin/aio/logic_service/clwbdisk_linux_gpt.bin', 'rb') as fsrc:
            with open(data_nbd_object['nbd_object'].device_path, 'rb+') as fdst:
                buf = xlogging.DataHolder()
                while buf.set(fsrc.read(64 * 1024)):
                    if not all(v == 0 for v in buf.get()):
                        fdst.write(buf.get())
                    else:
                        fdst.seek(len(buf.get()), os.SEEK_CUR)
        return True

    def _read_clw_boot_redirct_mbr_disk(self):
        kvm.kvm_wrapper.read_clw_boot_redirct_mbr_disk(self.data_nbd_objects, self.boot_nbd_object)

    def _is_stop_kvm(self):
        if not os.path.exists(self.start_kvm_flag_file):
            self.close_kvm((r'用户取消任务', 'user cancel task'))
            raise xlogging.raise_system_error('用户取消任务', 'start_kvm_flag_file not exists', 1)

    @staticmethod
    def _read_disk_tail_to2m(device_path):
        common_cmd = '/sys/block'
        nbd_path_size = os.path.join(common_cmd, device_path.split('/')[-1], 'size')
        _, disk_setor, _ = net_common.get_info_from_syscmd('cat ' + nbd_path_size)
        _logger.info('_calc_nbd_size:{}'.format(disk_setor))
        read_setor = 4096
        disk_setor = int(disk_setor)
        if disk_setor > 10240:
            with open(device_path, 'rb') as open_partition:
                open_partition.read(read_setor * 512)
            with open(device_path, 'rb') as open_partition:
                offset = disk_setor - read_setor
                open_partition.seek(offset * 512)
                open_partition.read(read_setor * 512)
        else:
            with open(device_path, 'rb') as open_partition:
                open_partition.read(disk_setor * 512)

    # 每个磁盘、每个分区的头尾2M读一次
    def _read_partition_head_tail_to2m_and_disk_tail_to2m(self):
        read_head_tail_to_2m(self.boot_nbd_object.device_path)
        self._read_disk_tail_to2m(self.boot_nbd_object.device_path)
        for data_nbd_object in self.data_nbd_objects:
            _logger.info('data_nbd_object_data:{}'.format(data_nbd_object['nbd_object'].device_path))
            read_head_tail_to_2m(data_nbd_object['nbd_object'].device_path)
            self._read_disk_tail_to2m(data_nbd_object['nbd_object'].device_path)

    # opt目录下ClwDRClient开头文件夹下的文件读一遍
    def _read_opt_clwdrclient(self):
        opt_path = os.path.join(self.root_path, 'opt')
        clwdrclient_dirs = [clwdrclient_dir for clwdrclient_dir in os.listdir(opt_path) if
                            'ClwDRClient' in clwdrclient_dir and os.path.isdir(os.path.join(opt_path, clwdrclient_dir))]
        for clwdrclient_dir in clwdrclient_dirs:
            clwdrclient_dir_path = os.path.join(opt_path, clwdrclient_dir)
            for root, dirs, files in os.walk(clwdrclient_dir_path):
                for file in files:
                    abs_path = os.path.join(root, file)  # file的绝对路径
                    if os.path.isfile(abs_path) and not os.path.islink(abs_path):
                        self._read_one_file(abs_path)

    @xlogging.convert_exception_to_value(None)
    def remove_start_kvm_flag_file(self):
        if os.path.exists(self.start_kvm_flag_file):
            os.remove(self.start_kvm_flag_file)

    def run(self, kvm_flag):
        if self.takeover_params:
            return self.run_for_takeover(kvm_flag)
        return self.run_for_restore(kvm_flag)

    @xlogging.LockDecorator(mount_nbd_linux.lock_all_mount)
    @xlogging.LockDecorator(mount_nbd_linux.lock_writable_mount)
    def run_for_restore(self, kvm_flag):
        try:
            self.running = True
            _logger.info('disk read:{},vnc_address:{}'.format(self.boot_nbd_object.device_path,
                                                              self.boot_nbd_object.vnc_address))
            self.disk_match_nbd(self.boot_nbd_object, 'b')
            params_vnc = self.open_kvm_params.get("vnc", None)
            if params_vnc is None:
                self.open_kvm_params['vnc'] = self.boot_nbd_object.vnc_address.split(':')[1]
            boot_nbd_thread = kvm.nbd_thread(
                self.pe_ident, self.boot_disk_token, self.boot_disk_bytes, self, self.boot_nbd_object,
                r'nbd ({}) boot disk'.format(self.boot_nbd_object.device_path))
            boot_nbd_thread.start()

            data_index = 0
            for data_nbd_object in self.data_nbd_objects:
                _logger.info('data_nbd_object:{}'.format(data_nbd_object['data_device']['disk_ident']))
                data_index += 1
                data_device = data_nbd_object['data_device']
                self.disk_match_nbd(data_nbd_object['nbd_object'], 'd', data_nbd_object['data_device']['disk_ident'])
                data_nbd_thread = kvm.nbd_thread(
                    self.pe_ident, data_device['token'], data_device['disk_bytes'], self, data_nbd_object['nbd_object'],
                    r'nbd ({}) data disk {}'.format(data_nbd_object['nbd_object'].device_path, data_index))
                data_nbd_thread.start()
            self._is_stop_kvm()
            self._wait_all_nbd_read_ok()
            _logger.info('disk_match_nbd open_kvm_params info:{}'.format(self.open_kvm_params))
            if not self._read_clw_boot_redirct_gpt_disk():
                self._read_clw_boot_redirct_mbr_disk()

            self._is_stop_kvm()
            self._mount_nbds(kvm_flag)

            self._is_stop_kvm()
            self._restore_logic(kvm_flag)

            self._is_stop_kvm()
            self._read_key_sectors_in_first_interspace()

            self._is_stop_kvm()
            self._read_key_sectors_in_data_device()

            self._is_stop_kvm()
            self._read_all_files_in_boot_partition((kvm_flag & 8) == 8)

            # self._is_stop_kvm()
            # self._read_key_files_in_system()

            self._is_stop_kvm()
            self._read_all_folder()

            self._read_one_file(self._get_reg_file_path())
            self._read_partition_head_tail_to2m_and_disk_tail_to2m()
            self._read_opt_clwdrclient()

            force_read_ESP_and_MSR_partition_range(self.boot_nbd_object.device_path)
        except Exception as e:
            if (kvm_flag & 2) == 2:
                _logger.warning(r'kvm_linux run failed : {}'.format(e), exc_info=True)
                self._pause_kvm()
                kvm_flag &= (~1)
            raise e
        finally:
            if (kvm_flag & 1) == 1:
                self._pause_kvm()
            self.running = False
            if self._samba_mount is not None:
                self._samba_mount.unmount()
            if self.kvmshell:
                self.kvmshell.over_kvm()
            self.boot_nbd_object.wait_no_mounting()
            self.boot_nbd_object.set_no_longer_used()
            self.boot_nbd_object = None
            for data_nbd_object in self.data_nbd_objects:
                data_nbd_object['nbd_object'].wait_no_mounting()
                data_nbd_object['nbd_object'].set_no_longer_used()
                data_nbd_object['nbd_object'] = None
            self._remove_params()
            self.remove_start_kvm_flag_file()

    def disk_match_nbd(self, nbd_obj, disk_type, disk_ident=None):
        """
        用来匹配还原阶段产生的nbd
        :param nbd_obj: nbd对象
        :param disk_type: boot盘还是data盘
        :return:
        """
        if disk_type == 'b':
            for disk in self.open_kvm_params['disk_devices']:
                if disk['boot_device'] is True:
                    nbd_info = disk['device_profile']['nbd']
                    nbd_info['vnc_address'] = nbd_obj.vnc_address
                    nbd_info['device_path'] = nbd_obj.device_path
                    nbd_info['device_name'] = nbd_obj.device_name
                    nbd_info['device_index'] = nbd_obj.device_index
                    nbd_info['serial_address'] = None
        if disk_type == 'd':
            for disk in self.open_kvm_params['disk_devices']:
                if (disk['boot_device'] is False) and (disk['disk_ident'] == disk_ident):
                    nbd_info = disk['device_profile']['nbd']
                    nbd_info['vnc_address'] = nbd_obj.vnc_address
                    nbd_info['device_path'] = nbd_obj.device_path
                    nbd_info['device_name'] = nbd_obj.device_name
                    nbd_info['device_index'] = nbd_obj.device_index
                    nbd_info['serial_address'] = None

    def _gen_qemu_nbd(self):
        boot_device = self.takeover_params['disk_snapshots']['boot_devices'][0]['device_profile']
        device_path = boot_device['qcow2path']
        boot_device['qemu_nbd'] = nbd_wrapper(nbd_wrapper_local_device_allocator(), use_qemu_nbd=True)

        name = r'qemu_nbd ({}) boot disk'.format(boot_device['qemu_nbd'].device_path)
        boot_nbd_thread = nbd_direct_images(name, boot_device['qemu_nbd'], [{"path": device_path}])
        boot_nbd_thread.start()
        nbd_wrapper.wait_nbd_read_ok(boot_device['qemu_nbd'])

        for data_nbd_object in self.data_nbd_objects:
            device_profile = data_nbd_object['data_device']['device_profile']
            device_path = device_profile['qcow2path']
            device_profile['qemu_nbd'] = nbd_wrapper(nbd_wrapper_local_device_allocator(), use_qemu_nbd=True)
            name = r'qemu_nbd ({}) data disk'.format(device_profile['qemu_nbd'].device_path)
            boot_nbd_thread = nbd_direct_images(name, device_profile['qemu_nbd'], [{"path": device_path}])
            boot_nbd_thread.start()
            nbd_wrapper.wait_nbd_read_ok(device_profile['qemu_nbd'])

    def _wait_qemu_nbd_no_mounting(self):
        boot_device = self.takeover_params['disk_snapshots']['boot_devices'][0]['device_profile']
        boot_device['qemu_nbd'].unmount()
        boot_device['qemu_nbd'].wait_no_mounting()
        boot_device['qemu_nbd'].set_no_longer_used()
        boot_device['qemu_nbd'] = None
        for data_nbd_object in self.data_nbd_objects:
            device_profile = data_nbd_object['data_device']['device_profile']
            device_profile['qemu_nbd'].unmount()
            device_profile['qemu_nbd'].wait_no_mounting()
            device_profile['qemu_nbd'].set_no_longer_used()
            device_profile['qemu_nbd'] = None

    def _save_kvm_run_info(self, kvm_key, kvm_value):
        flag_file = self.start_kvm_flag_file
        try:
            with open(flag_file, 'r+') as fout:
                info = json.loads(fout.read())
                info[kvm_key] = kvm_value
                fout.seek(0)
                fout.truncate()
                info_str = json.dumps(info, ensure_ascii=False)
                _logger.info('kvm_linux.py _save_kvm_run_info info_str={}'.format(info_str))
                fout.write(info_str)
        except Exception as e:
            _logger.info('_save_kvm_run_info r Failed.e={}'.format(e))

    def _GetFileMd5(self, filename):
        if not os.path.isfile(filename):
            return 'none'
        myhash = hashlib.md5()
        with open(filename, 'rb') as fout:
            while True:
                b = fout.read(8096)
                if not b:
                    break
                myhash.update(b)
        return myhash.hexdigest()

    def _save_qcow2_file_md5(self, qcow2path):
        filemd5path = qcow2path + '.md5'
        if qcow2path and os.path.isfile(qcow2path):
            filemd5 = self._GetFileMd5(qcow2path)
            with open(filemd5path, 'w') as file_object:
                file_object.write(str(filemd5))

    @xlogging.LockDecorator(mount_nbd_linux.lock_all_mount)
    @xlogging.LockDecorator(mount_nbd_linux.lock_writable_mount)
    def run_for_takeover(self, kvm_flag):
        is_exception = False
        device_path_list = list()

        try:
            self._is_stop_kvm()
            self.running = True
            self._save_kvm_run_info('msg', '正在为第一次启动作准备（1/10）')
            disk_snapshots = self.takeover_params['disk_snapshots']
            name = r'nbd ({}) boot disk'.format(self.boot_nbd_object.device_path)
            self._save_kvm_run_info('debug', name)
            boot_nbd_thread = nbd_direct_images(name, self.boot_nbd_object,
                                                disk_snapshots['boot_devices'][0]['disk_snapshots'])
            boot_nbd_thread.start()

            self._save_kvm_run_info('msg', '正在为第一次启动作准备（2/10）')

            data_index = 0
            for data_nbd_object in self.data_nbd_objects:
                data_index += 1
                name = r'nbd ({}) data disk {}'.format(data_nbd_object['nbd_object'].device_path, data_index)
                self._save_kvm_run_info('debug', name)
                disk_snapshots = data_nbd_object['data_device']['disk_snapshots']
                data_nbd_thread = nbd_direct_images(name, data_nbd_object['nbd_object'], disk_snapshots)
                data_nbd_thread.start()

            self._is_stop_kvm()
            self._wait_all_nbd_read_ok()

            self._save_kvm_run_info('msg', '正在为第一次启动作准备（3/10）')

            boot_device = self.takeover_params['disk_snapshots']['boot_devices'][0]['device_profile']
            device_path = boot_device['qcow2path']
            user_data_max_size = boot_device['DiskSize']

            qemu_img_cmd = 'qemu-img create -b {} -f qcow2 {} {}'.format(self.boot_nbd_object.device_path,
                                                                         device_path, user_data_max_size)
            device_path_list.append(device_path)

            _logger.info(r'kvm_linux.run_for_restore qemu_img_cmd={}'.format(qemu_img_cmd))
            self._save_kvm_run_info('debug', qemu_img_cmd)
            split_qemu_img_cmd = shlex.split(qemu_img_cmd)
            with subprocess.Popen(split_qemu_img_cmd, stderr=subprocess.PIPE, universal_newlines=True) as p:
                stdoutdata, stderrdata = p.communicate()
                if stdoutdata:
                    _logger.info(r'kvm_linux.run_for_restore stdoutdata={}'.format(stdoutdata))
                if stderrdata:
                    _logger.info(r'kvm_linux.run_for_restore stderrdata={}'.format(stderrdata))
            _logger.info("kvm_linux.run_for_restore qemu_img_cmd returncode={}".format(p.returncode))

            self._save_kvm_run_info('msg', '正在为第一次启动作准备（4/10）')

            for data_nbd_object in self.data_nbd_objects:

                device_profile = data_nbd_object['data_device']['device_profile']
                device_path = device_profile['qcow2path']
                user_data_max_size = device_profile['DiskSize']

                if not device_path:
                    xlogging.raise_system_error('参数错误，无用户数据硬盘', 'data_device={}'.format(device_profile), 0, _logger)

                qemu_img_cmd = 'qemu-img create -b {} -f qcow2 {} {}'.format(data_nbd_object['nbd_object'].device_path,
                                                                             device_path, user_data_max_size)
                device_path_list.append(device_path)

                _logger.info(r'kvm_linux.run_for_restore qemu_img_cmd={}'.format(qemu_img_cmd))
                self._save_kvm_run_info('debug', qemu_img_cmd)

                split_qemu_img_cmd = shlex.split(qemu_img_cmd)
                with subprocess.Popen(split_qemu_img_cmd, stderr=subprocess.PIPE, universal_newlines=True) as p:
                    self.kvm_pid = p.pid
                    stdoutdata, stderrdata = p.communicate()
                    if stdoutdata:
                        _logger.info(r'kvm_linux.run_for_restore stdoutdata={}'.format(stdoutdata))
                    if stderrdata:
                        _logger.info(r'kvm_linux.run_for_restore stderrdata={}'.format(stderrdata))
                _logger.info("kvm_linux.run_for_restore qemu_img_cmd returncode={}".format(p.returncode))

            self._save_kvm_run_info('msg', '正在为第一次启动作准备（5/10）')

            self._gen_qemu_nbd()

            self._save_kvm_run_info('msg', '正在为第一次启动作准备（6/10）')

            self._is_stop_kvm()
            self._mount_nbds_for_takeover(kvm_flag)

            self._save_kvm_run_info('msg', '正在为第一次启动作准备（7/10）')

            self._is_stop_kvm()
            self._restore_logic(kvm_flag)

            self._save_kvm_run_info('msg', '正在为第一次启动作准备（8/10）')

        except Exception as e:
            is_exception = True
            tb = traceback.format_exc()
            _logger.error(r'run_for_takeover failed . {} - {}'.format(e, tb))
            self._save_kvm_run_info('msg', '启动虚拟机异常')
            self._save_kvm_run_info('debug', r'kvm run failed . {} - {}'.format(e, tb))
            if (kvm_flag & 2) == 2:
                _logger.warning(r'kvm_linux run failed : {}'.format(e), exc_info=True)
                self._pause_kvm()
                kvm_flag &= (~1)
            raise e
        finally:
            if (kvm_flag & 1) == 1:
                self._pause_kvm()
            self.running = False

            if self._samba_mount is not None:
                self._samba_mount.unmount()
            if self.kvmshell:
                self.kvmshell.over_kvm()

            if self.takeover_params['kvm_type'] == 'forever_kvm':
                flp_path = self.takeover_params.get('floppy_path', None)
                qcow2data = list()
                for device_path in device_path_list:
                    if flp_path:
                        disk_ident = self._get_disk_id(self.takeover_params['disk_snapshots'], device_path)
                        if not os.path.isfile(device_path):
                            continue
                        info = GetQcowFileAlterInfo.get(device_path)
                        qcow2data.append({"disk_ident": disk_ident, "data": info})

                if flp_path:
                    flag_string = r'7294847cc045474882a93ec99090797b'
                    flag_raw_content = [ord(letter) for letter in flag_string]
                    qcow2data_str = json.dumps(qcow2data, ensure_ascii=False)
                    raw_content = [ord(letter) for letter in qcow2data_str]
                    with open(flp_path, 'wb') as file_object:
                        file_bytes = 1024 * 1024 * 20  # 20MB
                        file_object.truncate(file_bytes)
                        file_object.seek(1024 * 1024 * 10)
                        file_object.write(bytearray(flag_raw_content))
                        file_object.write(bytearray(raw_content))

            self.boot_nbd_object.unmount()
            for data_nbd_object in self.data_nbd_objects:
                data_nbd_object['nbd_object'].unmount()
            self.boot_nbd_object.wait_no_mounting()
            self.boot_nbd_object.set_no_longer_used()
            self.boot_nbd_object = None
            self._save_kvm_run_info('msg', '正在为第一次启动作准备（9/10）')
            for data_nbd_object in self.data_nbd_objects:
                data_nbd_object['nbd_object'].wait_no_mounting()
                data_nbd_object['nbd_object'].set_no_longer_used()
                data_nbd_object['nbd_object'] = None
            self._wait_qemu_nbd_no_mounting()
            self._save_kvm_run_info('msg', '正在为第一次启动作准备（10/10）')
            if is_exception:
                for device_path in device_path_list:
                    if os.path.isfile(device_path):
                        os.remove(device_path)
            else:
                for device_path in device_path_list:
                    self._save_qcow2_file_md5(device_path)
            self._remove_params()

    @staticmethod
    def _get_disk_id(disk_snapshots, qcow2path):
        boot_devices = disk_snapshots['boot_devices']
        for device in boot_devices:
            if qcow2path == device['device_profile']['qcow2path']:
                return device['disk_ident']
        data_devices = disk_snapshots['data_devices']
        for device in data_devices:
            if qcow2path == device['device_profile']['qcow2path']:
                return device['disk_ident']
        return None

    @staticmethod
    def _pause_kvm():
        flag_path = '/tmp/LinuxKvmPause'
        os.makedirs(flag_path, exist_ok=True)
        loop_times = 0
        while os.path.exists(flag_path):
            if (loop_times % 6) == 0:
                _logger.warning(r'~~~~ !!!! need remove [{}] to wake up LinuxKvm !!!! ~~~~'.format(flag_path))
            time.sleep(10)
            loop_times += 1

    def kill_kvm(self, kill_param):
        if self.remote_kvm_host_object:
            self._kill_remote_kvm(kill_param)
        else:
            self._kill_local_kvm(kill_param)
        return datetime.datetime.now()

    def _kill_remote_kvm(self, kill_param):
        kill_cmd = r'kill -{} {}'.format(kill_param, self.kvm_pid)
        # kvm_host.kvm_host_exec_helper(self.remote_kvm_host_object, kill_cmd, 'kill', _logger)

    def _kill_local_kvm(self, kill_param):
        _logger.info(r'close_kvm will kill {} by {}'.format(self.kvm_pid, kill_param))
        os.kill(self.kvm_pid, kill_param)
        _logger.info(r'close_kvm killed {}'.format(self.kvm_pid))

    def close_kvm(self, some_error):
        if not self.running:
            _logger.info(r'kvm_linux close_kvm do nothing')
            return

        # 可能掩盖真实错误
        if not self.some_error:
            self.some_error = some_error

        if self.kvm_pid is None:
            _logger.info(r'kvm_linux close_kvm kvm_pid is None do nothing')
            return

        try:
            last_kill_15_datetime = self.kill_kvm(15)
            last_kill_9_datetime = None
            while True:
                if not self.running:
                    break
                time.sleep(0.3)
                t_15 = datetime.datetime.now() - last_kill_15_datetime
                if t_15 > datetime.timedelta(seconds=300):
                    self.kill_kvm(11)
                    break
                elif t_15 > datetime.timedelta(seconds=30) and (last_kill_9_datetime is None):
                    last_kill_9_datetime = self.kill_kvm(9)
        except Exception as e:
            tb = traceback.format_exc()
            _logger.error(r'kvm_linux close kvm failed . {} - {}'.format(e, tb))

    def _remove_params(self):
        params_file_path = self.open_kvm_params['write_new']['src_path']
        if os.path.isfile(params_file_path):
            os.remove(params_file_path)
        else:
            pass

    def change_chmod_only_read(self):
        net_common.get_info_from_syscmd(r'chmod -R a-wx,a+rX "{}"'.format(self.root_path), 60 * 15)

    def _mount_nbds(self, kvm_flag):
        linux_storage = self.linux_storage
        linux_disk_index_info = self.linux_disk_index_info
        for data_nbd_object in self.data_nbd_objects:
            if data_nbd_object['data_device']['disk_ident'] == xdefine.CLW_BOOT_REDIRECT_GPT_LINUX_UUID:
                snapshot_disk_index = xdefine.CLW_BOOT_REDIRECT_GPT_LINUX_INDEX
                linux_storage = deepcopy(self.linux_storage)
                linux_disk_index_info = deepcopy(self.linux_disk_index_info)
                linux_storage['disks'].append({
                    "partitions": [
                        {
                            "mountOpts": "rw,relatime",
                            "fileSystem": "ext4",
                            "mountPoint": xdefine.CLW_BOOT_REDIRECT_GPT_LINUX_MOUNT_PATH,
                            "index": 1,
                            "device": "not_exists"
                        }
                    ],
                    "style": "mbr",
                    "index": xdefine.CLW_BOOT_REDIRECT_GPT_LINUX_INDEX,
                    "device": "fake"
                })
                linux_disk_index_info.append({'disk_ident': xdefine.CLW_BOOT_REDIRECT_GPT_LINUX_UUID,
                                              'snapshot_disk_index': snapshot_disk_index})
        self.start_kvm_mount_nbd(linux_storage, linux_disk_index_info)
        if (kvm_flag & 16) == 16:
            _logger.info('_mount_nbds kvm_flag={}, guest_ip={}'.format(kvm_flag, self.kvmshell.guest_ip))
            self._pause_kvm()

    def _guest_ip_is_none(self):
        timeouts_timestamp = datetime.datetime.now() + datetime.timedelta(seconds=120)
        while not self.kvmshell.guest_ip:
            if datetime.datetime.now() > timeouts_timestamp:
                xlogging.raise_system_error('获取guest_ip失败', '_guest_ip_is_none, timeout', 101)
            time.sleep(3)

    def start_kvm_mount_nbd(self, linux_storage, linux_disk_index_info):
        _logger.info(
            'start_kvm_mount_nbd linux_storage {} linux_disk_index_info{}'.format(linux_storage, linux_disk_index_info))
        self.kvmshell = KVMShell(self.open_kvm_params, linux_storage, linux_disk_index_info)
        self.kvmshell.setDaemon(True)
        self.kvmshell.start()
        if not self.kvmshell.create_params:
            time.sleep(10)
        params_file_path = self.open_kvm_params['write_new']['src_path']
        self._guest_ip_is_none()
        _logger.info('kvmshell_guest_ip:{}'.format(self.kvmshell.guest_ip))
        with open(params_file_path, 'r') as f:
            key_info = json.loads(f.read())
        self.change_chmod_only_read()
        _logger.info('root_path SAMBAMountHandle:{}'.format(self.root_path))
        self._samba_mount = SAMBAMountHandle(key_info, self.root_path)
        self._samba_mount.set_ip(self.kvmshell.guest_ip)
        self._mount_until_ok()
        self._fix_swapv2()

    def _fix_swapv2(self):
        if self.takeover_params:
            boot_device = self.takeover_params['disk_snapshots']['boot_devices'][0]['device_profile']
            nbds = [{'snapshot_disk_index': boot_device['snapshot_disk_index'],
                     'device_path': boot_device['qemu_nbd'].device_path}, ]
            for data_nbd_object in self.data_nbd_objects:
                device_profile = data_nbd_object['data_device']['device_profile']
                nbds.append({
                    'snapshot_disk_index': device_profile['snapshot_disk_index'],
                    'device_path': device_profile['qemu_nbd'].device_path})
        else:
            nbds = [{'snapshot_disk_index': self.get_snapshot_disk_index(self.boot_device_normal_snapshot_ident),
                     'device_path': self.boot_nbd_object.device_path}]
            for data_nbd_object in self.data_nbd_objects:
                if data_nbd_object['data_device']['disk_ident'].startswith('clwbootdisk'):
                    continue
                snapshot_disk_index = self.get_snapshot_disk_index(data_nbd_object['data_device']['disk_ident'])
                nbds.append({
                    'snapshot_disk_index': snapshot_disk_index,
                    'device_path': data_nbd_object['nbd_object'].device_path})

        self.mount_wrapper = mount_nbd_linux.MountNbdLinux(nbds, self.linux_storage, None, False, list())
        self.mount_wrapper.fix_swapv2()

    def _mount_until_ok(self):
        st = time.time()
        start_time = time.time()
        while True:
            if (time.time() - start_time) > 30 * 60:  # 当一体机IO性能很差时候，很容易超时
                xlogging.raise_system_error('挂载文件失败', 'mount fail, timeout', 138)
            if self._samba_mount.mount(False):
                break
            else:
                time.sleep(5)
        _logger.info('_mount_until_ok mount ok, cost time {:.1f}s'.format(time.time() - st))

    def start_kvm_mount_nbd_for_takeover(self):
        _logger.info('start_kvm_mount_nbd_for_takeover open_kvm_params={}'.format(self.open_kvm_params))
        self.kvmshell = KVMShell(self.open_kvm_params, self.linux_storage, self.linux_disk_index_info)
        self.kvmshell.setDaemon(True)
        self.kvmshell.start()
        if not self.kvmshell.create_params:
            time.sleep(10)
        params_file_path = self.open_kvm_params['write_new']['src_path']
        self._guest_ip_is_none()
        _logger.info('kvmshell_guest_ip:{}'.format(self.kvmshell.guest_ip))
        with open(params_file_path, 'r') as f:
            key_info = json.loads(f.read())
        self.change_chmod_only_read()
        _logger.info('root_path SAMBAMountHandle:{}'.format(self.root_path))
        self._samba_mount = SAMBAMountHandle(key_info, self.root_path)
        self._samba_mount.set_ip(self.kvmshell.guest_ip)
        self._mount_until_ok()
        self._fix_swapv2()

    def _mount_nbds_for_takeover(self, kvm_flag):
        from collections import namedtuple
        boot_device = self.takeover_params['disk_snapshots']['boot_devices'][0]['device_profile']
        self.open_kvm_params['vnc'] = boot_device['nbd']['vnc_address'].split(':')[1]
        nbd_obj = namedtuple('nbd_obj', ['vnc_address', 'device_path', 'device_name', 'device_index'])
        nbd_obj.vnc_address = boot_device['nbd']['vnc_address']
        nbd_obj.device_path = boot_device['qcow2path']
        nbd_obj.device_name = boot_device['nbd']['device_name']
        nbd_obj.device_index = boot_device['nbd']['device_index']
        self.disk_match_nbd(nbd_obj, 'b')

        data_devices = self.takeover_params['disk_snapshots']['data_devices']
        for data_device in data_devices:
            nbd_obj.vnc_address = data_device['device_profile']['nbd']['vnc_address']
            nbd_obj.device_path = data_device['device_profile']['qcow2path']
            nbd_obj.device_name = data_device['device_profile']['nbd']['device_name']
            nbd_obj.device_index = data_device['device_profile']['nbd']['device_index']
            self.disk_match_nbd(nbd_obj, 'd', data_device['disk_ident'])

        self.start_kvm_mount_nbd_for_takeover()

        if (kvm_flag & 16) == 16:
            _logger.info('_mount_nbds_for_takeover kvm_flag={}, guest_ip={}'.format(kvm_flag, self.kvmshell.guest_ip))
            self._pause_kvm()

    def get_snapshot_disk_index(self, disk_ident):
        for info in self.linux_disk_index_info:
            if disk_ident == info['disk_ident']:
                return info['snapshot_disk_index']
        xlogging.raise_system_error(
            r'内部异常，代码3110',
            'get_snapshot_disk_index failed {} not in {}'.format(disk_ident, self.linux_disk_index_info), 1)

    def _deal_files_for_htb(self):
        actions = list()

        # 备份raminitfs
        actions.extend(self._generate_actions_for_htb(self.org_init_ram_fs_path, self.linux_info['initrdfs_path']))
        # 备份fstab
        actions.extend(self._generate_actions_for_htb(os.path.join(self.root_path, 'etc', 'fstab'), '/etc/fstab'))

        _logger.info(r'_deal_files_for_htb : {}'.format(actions))

        with open(os.path.join(self.htb_key_data_dir, 'actions.json'), 'w') as f:
            json.dump(actions, f, ensure_ascii=False)

    def _generate_actions_for_htb(self, local_path, remote_path):
        """
        针对热备会覆盖一些特殊文件，需要备份下来，后续推送到客户端进行覆盖
        :param local_path: 需要备份的路径
        :param remote_path: 恢复后目标路径
        :return: actions
        """
        actions = list()
        tmp_file_name = 'htb_file_' + uuid.uuid4().hex
        local_tmp_path = os.path.join(self.htb_key_data_dir, tmp_file_name)
        remote_tmp_path = (r'current', tmp_file_name,)
        shutil.copyfile(local_path, local_tmp_path)
        actions.append({
            'action': 'push_file',
            'src_path': local_tmp_path,
            'dst_dir': remote_tmp_path[0],
            'dst_path': remote_tmp_path[1],
        })
        actions.append({
            'action': 'exc_command',
            'exc_dict': {
                'AppName': r'cp',
                'param': r'-f {} "{}"'.format(tmp_file_name, remote_path),
                'workdir': r'|current|',
            },
        })
        actions.append({
            'action': 'exc_command',
            'exc_dict': {
                'AppName': r'rm',
                'param': r'-f {}'.format(tmp_file_name),
                'workdir': r'|current|',
            },
        })
        return actions

    def _read_all_files_in_boot_partition(self, save_last):
        _logger.info(r'_read_boot_key_partition begin {}'.format(self.root_path))
        if self.htb_key_data_dir:
            # 热备推送数据阶段会导致部分数据被覆盖
            cmd = r'tar -cPf - "{}/boot" --exclude "{}" | cat > /dev/null'.format(
                self.root_path, self.org_init_ram_fs_path)
            self._deal_files_for_htb()
        else:
            cmd = r'tar -cPf - "{}/boot" | cat > /dev/null'.format(self.root_path)

        if save_last:
            cmd = r'tar -cPf /home/aio/last_restore_root.tar "{}/boot"'.format(self.root_path)
        net_common.get_info_from_syscmd(cmd, 60 * 60)
        _logger.info(r'_read_boot_key_partition end {}'.format(self.root_path))

    def _read_key_sectors_in_first_interspace(self):
        need_bytes = None
        for disk_index_info in self.linux_disk_index_info:
            if 'first_partition_bytes_offset' in disk_index_info.keys():
                need_bytes = int(disk_index_info['first_partition_bytes_offset'])
        _logger.info('_read_key_sectors_in_first_interspace:{}-{}'.format(self.boot_nbd_object.device_path, need_bytes))
        if need_bytes is None:
            return

        need_bytes = need_bytes if need_bytes < (16 * 1024 * 1024) else (16 * 1024 * 1024)  # 最多只预读前16MB
        read_block_bytes = 64 * 1024  # 64KBytes
        read_blocks = int((need_bytes + read_block_bytes - 1) / read_block_bytes)
        cmd = r'dd if={} of=/dev/null bs={} count={}'.format(
            self.boot_nbd_object.device_path, read_block_bytes, read_blocks)
        net_common.get_info_from_syscmd(cmd)
        _logger.info('_read_key_sectors_in_first_interspace end : {}'.format(self.boot_nbd_object.device_path))

    def _read_key_sectors_in_data_device(self):
        for data_nbd_object in self.data_nbd_objects:
            cmd = r'dd if={} of=/dev/null bs=65536 count=32'.format(data_nbd_object['nbd_object'].device_path)
            net_common.get_info_from_syscmd(cmd)

    def _search_driver_from_aio(self, devices, driver_files, kvm_flag):
        driver_file_names = [os.path.basename(_) for _ in driver_files]
        for device in devices:
            try:
                pci_value_list = modget.convert_pci_str_2_pci_value_list(device)
                if modget.is_pci_value_valid(pci_value_list) and len(pci_value_list) >= 5 \
                        and pci_value_list[4][0] == '0' and pci_value_list[4][1] == '6':
                    _logger.warning(r'ignore bridge device : {}'.format(device))
                    continue

                files = linux_devices.get_device_files(self.linux_info['kernel_ver'], self.linux_info['platform'],
                                                       self.linux_info['bit_opt'], device)
                if files is None:
                    xlogging.raise_system_error(r'未找到匹配的驱动：{}'.format(device),
                                                r'_search_driver_from_aio failed : {} {} {} {}'.format(
                                                    self.linux_info['kernel_ver'], self.linux_info['platform'],
                                                    self.linux_info['bit_opt'], device), 0)
                for file in files:
                    if (file not in driver_files) and (os.path.basename(file) not in driver_file_names):
                        driver_files.append(file)
                    else:
                        _logger.info(r'exist driver file : {}'.format(file))
            except Exception as e:
                if (kvm_flag & 64) == 64:
                    pass
                else:
                    raise e

    def _patch_virtio_drivers(self, driver_files, kvm_flag, pci_devices):
        for pci_device in pci_devices:
            pci_value_list = modget.convert_pci_str_2_pci_value_list(pci_device)
            if modget.is_pci_value_valid(pci_value_list) \
                    and ((pci_value_list[0] == '1AF4' and pci_value_list[1] == '1004')
                         or (pci_value_list[0] == '1AF4' and pci_value_list[1] == '1048')):
                _logger.info(r'find virtio scsi device, need check drivers ...')
                break
        else:
            _logger.info(r'NOT find virtio scsi device')
            return

        driver_file_names = [os.path.basename(_) for _ in driver_files]
        is_virtio, is_virtio_scsi = False, False
        for val in driver_file_names:
            if val.find('virtio.ko') >= 0:
                is_virtio = True
            if val.find('virtio_scsi.ko') >= 0:
                is_virtio_scsi = True
        if is_virtio and not is_virtio_scsi:
            _logger.info(r'_patch_virtio_drivers search virtio driver file')
            self._search_driver_from_aio(['VEN_1AF4&DEV_1004&SUBSYS_1AF40008&REV_00&CLASS_010000'], driver_files,
                                         kvm_flag)

    @staticmethod
    def _force_patch_virtio_drivers_from_kernel_folder(lib_modules_path, driver_files):
        def __is_virio_drivers_not_in_kernel_folder(_driver_path):
            _driver_rel_path_with_version_folder = os.path.relpath(_driver_path, lib_modules_path)
            if not _driver_rel_path_with_version_folder.startswith('updates'):
                return False
            return 'virtio' in os.path.basename(_driver_rel_path_with_version_folder)

        def __try_alter_to_same_file_name_in_kernel_folder(_driver_path):
            _file_name = os.path.basename(_driver_path)
            _dir_path = os.path.join(lib_modules_path, 'kernel')

            for root, _, files in os.walk(_dir_path, topdown=False):
                for name in files:
                    _temp_path = os.path.join(root, name)
                    if _file_name == os.path.basename(_temp_path):
                        return _temp_path

            return _driver_path

        for index in range(len(driver_files)):
            if not __is_virio_drivers_not_in_kernel_folder(driver_files[index]):
                continue
            _logger.warning(r'_force_patch_virtio_drivers_from_kernel_folder before : {}'.format(driver_files[index]))
            driver_files[index] = __try_alter_to_same_file_name_in_kernel_folder(driver_files[index])
            _logger.warning(r'_force_patch_virtio_drivers_from_kernel_folder after : {}'.format(driver_files[index]))

    @staticmethod
    def _get_xen_driver_name(lib_modules_path):
        xen_drivers = [r'xen-netfront.ko',
                       r'xen-blkfront.ko',
                       r'VEN_10EC&DEV_8139&SUBSYS_11001AF4&REV_20&CLASS_020000',
                       r'VEN_8086&DEV_7010&SUBSYS_11001AF4&REV_00&CLASS_010180',
                       ]
        _, not_found_devices = kvm_linux._search_driver_from_snapshot(lib_modules_path, xen_drivers)
        result = list()
        for driver in xen_drivers:
            if driver not in not_found_devices:
                result.append(driver)
        _logger.info(r'_get_xen_driver_name : {} in {}'.format(result, lib_modules_path))
        return result

    @staticmethod
    def _copy_file_with_retry(scr, dest, times=5, wait_secs=1):
        for attempt in range(times):
            time.sleep(wait_secs)
            try:
                shutil.copy(scr, dest)
            except Exception as e:
                _logger.warning('cp {} to {} failed. {}. will retry ...'.format(scr, dest, e))
            else:
                break
        else:
            xlogging.raise_system_error('拷贝文件错误', 'cp file occur error, src:{} dst:{}'.format(scr, dest), 0, _logger)

    def _get_special_alias_by_type(self, alias_type):
        for alias in self.src_disk_alias:
            if alias['alias_type'] == alias_type:
                return alias

        xlogging.raise_system_error('在disk_alias列表中未找到指定类型的alias项',
                                    'src_disk_alias={} type={}'.format(self.src_disk_alias, alias_type), 0, _logger)

    def _get_target_by_name_from_special_alias(self, alias_type, name):
        alias = self._get_special_alias_by_type(alias_type=alias_type)
        for alias_item in alias['alias_items']:
            if alias_item['name'] == name:
                return alias_item['target']

        xlogging.raise_system_error('在alias中未找到指定的item', 'alias={} name={}'.format(alias, name), 0, _logger)

    def _get_dev_uuid(self, dev_name):
        try:
            dev_uuid1 = self._get_name_by_target_from_special_alias(alias_type=r'by-blkid', target=dev_name)
        except Exception as e:
            _logger.warning('_get_name_by_target_from_special_alias, error, {} {} {}'.format('by-blkid', dev_name, e))
            dev_uuid1 = None

        dev_uuid2 = self._get_name_by_target_from_special_alias(alias_type=r'by-uuid', target=dev_name)
        _logger.info('dev_uuid1:{},dev_uuid2:{}'.format(dev_uuid1, dev_uuid2))
        return dev_uuid1 or dev_uuid2

    def _get_name_by_target_from_special_alias(self, alias_type, target):
        alias = self._get_special_alias_by_type(alias_type=alias_type)
        for alias_item in alias['alias_items']:
            if alias_item['target'] == target:
                return alias_item['name']

        return None

    def _get_alias_device_names_from_by_path_alias(self):
        try:
            alias = self._get_special_alias_by_type(alias_type=r'by-path')
        except Exception as e:
            _logger.info('_get_by_path_alias_device_names, empty, {}'.format(e))
            return []

        return [item['target'] for item in alias['alias_items']]

    def _modify_swap_entry(self, line_items):
        device_str = line_items[0]
        if device_str.startswith(r'/dev/disk/by-'):  # by-id, by-path, by-partuuid, by-uuid ...
            _, _, _, by_type, by_val = device_str.split(r'/')
            dev_name = self._get_target_by_name_from_special_alias(alias_type=by_type, name=by_val)
        elif device_str in self._get_alias_device_names_from_by_path_alias():
            dev_name = device_str
        else:
            dev_name = None

        if dev_name is None:
            return '   '.join(line_items) + os.linesep

        # dev_name: 非LVM的Swap设备名
        if dev_name in self.mount_wrapper.norm_swap_dev_label:  # 存在label, 使用原来的
            line_items[0] = r'LABEL={}'.format(self.mount_wrapper.norm_swap_dev_label[dev_name])
        else:
            line_items[0] = r'LABEL={}'.format(dev_name.lstrip(r'/').replace(r'/', r'-'))  # 不存在label, 按规则生成label

        return '   '.join(line_items) + os.linesep

    def _fix_fstab_entry(self, line_str):
        line_items = line_str.split()
        if not line_items:
            return os.linesep

        if len(line_items) < 6:
            _logger.info('_fix_fstab_entry invalid item count={}'.format(len(line_items)))
            return line_str

        if line_items[2] == "swap" and not line_str.startswith('#'):  # 单独处理Entry: "Swap"
            return self._modify_swap_entry(line_items)

        device_str = line_items[0]

        if device_str.startswith(r'/dev/disk/by-'):  # by-id, by-path, by-partuuid, by-uuid ...
            _, _, _, by_type, by_val = device_str.split(r'/')
            dev_name = self._get_target_by_name_from_special_alias(by_type, by_val)
        elif len(line_items) == 6 and not line_str.startswith('#'):
            dev_name = device_str
        else:
            return line_str

        dev_uuid = self._get_dev_uuid(dev_name=dev_name)
        if dev_uuid is None:
            return line_str

        line_items[0] = 'UUID={}'.format(dev_uuid)
        return '{}   {}   {}   {}   {}   {}\n'.format(*line_items)

    def _fix_fstab_according_to_src_disk_alias(self):
        if not self.src_disk_alias:
            _logger.info('src_disk_alias is empty, please check src system_info')
            return

        fixed_lines, fstab_path = [], os.path.join(self.root_path, 'etc', 'fstab')
        _logger.info('_fix_fstab_according_to_src_disk_alias_fstab_path:{}'.format(fstab_path))
        self._copy_file_with_retry(fstab_path, fstab_path + '.old.bk')
        with open(fstab_path, 'rt') as fin:
            for line in fin:
                _logger.info('original fstab line: {}'.format(line))
                fixed_lines.append(self._fix_fstab_entry(line.lstrip()))

        with open(fstab_path, 'wt') as fout:
            fout.writelines(fixed_lines)

        _logger.info('fixed fstab lines: {}'.format(fixed_lines))

    @staticmethod
    def find_file_in_dir(file_name, dir_path):
        for root, dirs, files in os.walk(dir_path):
            if file_name in files:
                _logger.info('find file_name : {}'.format(file_name))
                return os.path.join(root, file_name)

        return None

    def get_boot_efi_cfgs_path(self):
        exist_cfgs_path = []
        dir_path = os.path.join(self.root_path, 'boot', 'efi', 'efi')
        file_names = [r'xen.cfg', r'xen2.cfg', r'elilo.conf']
        for file_name in file_names:
            cfg_path = self.find_file_in_dir(file_name, dir_path)
            if cfg_path:
                _logger.info('found one cfg file: {}'.format(cfg_path))
                exist_cfgs_path.append(cfg_path)
            else:
                _logger.info('not found cfg file: {}'.format(file_name))
        file_name_s = [r'menu.lst', r'grub.cfg']
        for file_name in file_name_s:
            grub = "grub"
            check_grub2 = os.path.join(self.root_path, "boot", "grub2")
            if os.path.isdir(check_grub2):
                grub = "grub2"
            cfg_path = os.path.join(self.root_path, "boot", grub, file_name)
            if os.path.exists(cfg_path):
                exist_cfgs_path.append(cfg_path)
        return exist_cfgs_path

    @staticmethod
    def _get_sub_str_from_line_str(sub_mode, line_str):
        m = re.findall(pattern=sub_mode, string=line_str)
        return m[0] if m else None

    def _get_device_uuid_by_device_name(self, device_str):
        if device_str.startswith(r'/dev/disk/by-'):
            _, _, _, by_type, by_val = device_str.split(r'/')
            dev_name = self._get_target_by_name_from_special_alias(alias_type=by_type, name=by_val)
        else:
            dev_name = device_str

        return self._get_dev_uuid(dev_name=dev_name)

    def _fix_boot_efi_cfg_line(self, line_str):
        root_str = self._get_sub_str_from_line_str(r'root\s*=\s*/dev/\S+\s*', line_str)
        resume_str = self._get_sub_str_from_line_str(r'resume\s*=\s*/dev/\S+\s*', line_str)
        if root_str:
            root_str = str(root_str.strip().rstrip(r'"'))
            device_str = root_str.split('=')[-1].strip()
            dev_uuid = self._get_device_uuid_by_device_name(device_str)
            if dev_uuid:
                line_str = line_str.replace(device_str, r'UUID={}'.format(dev_uuid))

        if resume_str:
            resume_str = str(resume_str.strip().rstrip(r'"'))
            device_str = resume_str.split('=')[-1].strip()
            dev_uuid = self._get_device_uuid_by_device_name(device_str)
            if dev_uuid:
                line_str = line_str.replace(device_str, r'UUID={}'.format(dev_uuid))

        return line_str

    def _fix_boot_efi_configuration(self):
        if not self.src_disk_alias:
            _logger.info('src_disk_alias is empty, please check src system_info')
            return None

        efi_cfgs = self.get_boot_efi_cfgs_path()
        if not efi_cfgs:
            _logger.info('not found efi cfg file, do nothing')
            return None
        _logger.info('found efi cfg file: {}'.format(efi_cfgs))

        for efi_cfg in efi_cfgs:
            self._copy_file_with_retry(efi_cfg, efi_cfg + '.old.bk')
            fixed_lines = []
            with open(efi_cfg, 'rt') as fin:
                for line in fin:
                    fixed_lines.append(self._fix_boot_efi_cfg_line(line))

            with open(efi_cfg, 'wt') as fout:
                fout.writelines(fixed_lines)

            _logger.info('fixed efi cfg lines: {}'.format(fixed_lines))

    @staticmethod
    def find_sub_string(infos, sub_strings):
        for sub in sub_strings:
            if sub.lower() in infos.lower():
                return True
        return False

    def _fix_interfaces_name(self):
        distro_names = ['ubuntu', 'debian']
        issue_path = os.path.join(self.root_path, 'etc', 'issue')
        old_interfaces_path = os.path.join(self.root_path, 'etc', 'network', 'interfaces')
        new_interfaces_path = os.path.join(self.root_path, 'etc', 'network', 'interfaces_clerware_bk')
        if not os.path.exists(issue_path) or not os.path.exists(old_interfaces_path):
            return None

        ret_code, ret_info, _ = net_common.get_info_from_syscmd('cat {}'.format(issue_path))
        if ret_code != 0 or not self.find_sub_string(ret_info, distro_names):
            return None

        cmd_line = 'mv {0} {1}'.format(old_interfaces_path, new_interfaces_path)
        ret_code = os.system(cmd_line)

        _logger.info('_fix_interfaces_name, have got distro info: {}'.format(ret_info))
        _logger.info('_fix_interfaces_name, run cmd: {0}. code: {1}.'.format(cmd_line, ret_code))

    def _xen_hcall_modify_name(self):
        find_path = os.path.join(self.root_path, 'lib', 'modules')
        for root, dirs, files in os.walk(find_path):
            if 'xen-hcall' in dirs:
                xen_hcall_path = os.path.join(root, 'xen-hcall')
                _logger.info('xen_hcall_path:{}'.format(xen_hcall_path))
                modify_xen_hcall_path = os.path.join('/'.join(xen_hcall_path.split('/')[:-1]), 'xen-hcall-bk')
                cmd = 'mv ' + xen_hcall_path + ' ' + modify_xen_hcall_path
                _logger.info('xen_hcall_modify_name cmd is:{}'.format(cmd))
                net_common.get_info_from_syscmd(cmd)

    def _restore_logic(self, kvm_flag):
        self.fix_initrd()
        self.org_init_ram_fs_path = self.root_path + self.linux_info['initrdfs_path']
        self.initramfs = Initramfs.Initramfs(
            self.org_init_ram_fs_path, self.org_init_ram_fs_path, self.init_ram_fs_path,
            self.linux_info['platform'],
            self.linux_info['release'])
        self._fix_interfaces_name()
        self._fix_fstab_according_to_src_disk_alias()
        self._fix_boot_efi_configuration()
        self._copy_grub_to_backup_dir()
        self._xen_hcall_modify_name()
        lib_modules_path = self._get_lib_modules_path()
        pci_devices = self._convert_to_device_string(self.kvm_virtual_devices)
        _logger.info('_restore_logic pci_devices:{}'.format(pci_devices))
        if self.to_hyper_v_one:
            pci_devices.extend(['hv_vmbus.ko', 'hv_netvsc.ko', 'hv_storvsc.ko'])

        if self.to_xen:
            pci_devices.extend(self._get_xen_driver_name(lib_modules_path))
        _logger.info('_restore_logic pci_devices:{}'.format(pci_devices))
        driver_files, not_found_devices = self._search_driver_from_snapshot(lib_modules_path, pci_devices)
        firmware_from_snapshot = self._search_firmware_from_snapshot(driver_files)
        self._patch_virtio_drivers(driver_files, kvm_flag, pci_devices)
        self._search_driver_from_aio(not_found_devices, driver_files, kvm_flag)
        self._force_patch_virtio_drivers_from_kernel_folder(lib_modules_path, driver_files)
        self._unpack_img_and_fetch_old_sdb()
        self._install_firmware(firmware_from_snapshot)
        # self._install_python_so() 不需要支持python
        self._install_all_driver_and_app(driver_files)
        self._set_new_pdisk_labels()
        self._set_network()
        self._set_htb_guid()

        if (kvm_flag & 4) == 4:
            self._pause_kvm()

        self._pack_img()

        if (kvm_flag & 256) == 256:
            self._pause_kvm()

        self._set_clw_boot()

        self._alter_agent()
        if self.takeover_params is None:
            self._copy_bmf_data()

        if (kvm_flag & 32) == 32:
            self._pause_kvm()

    def _set_network(self):
        if len(self.ipconfigs):
            config = json.loads(self.restore_config['agent_service_configure'])
            key_adapter_config, all_adapter_configs = self.get_adapter_cfg(self.ipconfigs)
            if key_adapter_config[0]['is_to_self']:
                pass  # 本机还原不做操作
            else:
                self._generate_udev_rules(all_adapter_configs)
            net_config = {
                'ipconfigs': key_adapter_config,  # 驱动使用
                'router': config['routers']['router_list'],
                'all_adapter_configs': all_adapter_configs  # ip_service 使用
            }
            net_config_json_string = json.dumps(net_config)
            _logger.info(r'_set_new_disk_label net_config : {}'.format(net_config_json_string))

            ret = net_common.get_info_from_syscmd("/sbin/aio/regdata/regdata -set -string {} json_ip_route_name '{}'"
                                                  .format(self._get_reg_file_path(), net_config_json_string))
            if ret[0] != 0:
                _logger.raise_system_error('更新关键信息到驱动', '_set_networ regdata run fail!', 1010)
            else:
                _logger.info('_set_network run successful!')
        else:
            if self.takeover_params:
                _logger.info("_set_new_disk_label ipconfigs len is 0.")
            else:
                xlogging.raise_system_error('配置网卡信息失败', '_set_new_disk_label ipconfigs len is 0.', 33)

        self._remove_network_cfg()

    # 删除 suse 的网卡配置文件
    def _remove_network_cfg(self):
        base_dir = os.path.join(self.root_path, 'etc/sysconfig/network/')
        if not os.path.exists(base_dir):
            return
        for file_name in os.listdir(base_dir):
            if file_name.startswith('ifcfg-') and file_name != 'ifcfg-lo':
                os.remove(os.path.join(base_dir, file_name))
                _logger.debug('_remove_network_cfg remove:{}'.format(os.path.join(base_dir, file_name)))

    def _set_htb_guid(self):
        if self.is_htb():
            config = json.loads(self.restore_config['agent_service_configure'])
            htb_task_uuid = config['htb_task_uuid']
            _logger.info('_set_htb_guid htb_task_uuid:{}'.format(htb_task_uuid))
            ret = net_common.get_info_from_syscmd(r'/sbin/aio/regdata/regdata -set -guid {} hot_ready_task_id {}'
                                                  .format(self._get_reg_file_path(), htb_task_uuid))
            if ret[0] != 0:
                _logger.info('_set_htb_guid regdata run fail!')
            else:
                _logger.info('_set_htb_guid run successful!')
        else:
            pass

    def _set_new_pdisk_labels(self):
        for new_pdisk_label in self.new_pdisk_labels:
            cmd = r'/sbin/aio/regdata/regdata -set -qword {} aio_regdata_key_flag {}'.format(self._get_reg_file_path(),
                                                                                             new_pdisk_label)
            _logger.info('_set_new_pdisk_labels cmd:{}'.format(cmd))
            ret = net_common.get_info_from_syscmd(cmd)
            if ret[0] != 0:
                while True:
                    if not os.path.exists('/tmp/temp.txt'):
                        break
                    else:
                        _logger.info('_set_new_pdisk_labels Failed. remove ~~~/tmp/temp.txt~~~')
                        time.sleep(10)
                xlogging.raise_system_error('更新关键信息到驱动', '_set_new_pdisk_labels regdata run fail!', 1313)
            else:
                _logger.info('_set_new_pdisk_labels run successful!')

    def _install_python_so(self):
        for so in python_support_so:
            path_in_root = os.path.join(self.root_path, so)
            path_in_ram_init_fs = os.path.join(self.init_ram_fs_path, so)
            if os.path.exists(path_in_root) and not os.path.exists(path_in_ram_init_fs) \
                    and not os.path.isdir(path_in_ram_init_fs) and not os.path.islink(path_in_ram_init_fs):
                os.makedirs(os.path.split(path_in_ram_init_fs)[0], exist_ok=True)
                shutil.copy2(path_in_root, path_in_ram_init_fs)

    def _get_lib_modules_path(self):
        lib_modules_path = r'{}/lib/modules/{}'.format(self.root_path, self.linux_info['release'])
        if not os.path.exists(lib_modules_path):
            xlogging.raise_system_error(r'无法访问备份快照中的关键数据区域',
                                        r'_get_lib_modules_path failed : {}'.format(lib_modules_path), 1)
        _logger.info(r'_get_lib_modules_path ok : {}'.format(lib_modules_path))
        return lib_modules_path

    def _get_agent_app_path(self):
        path = self.root_path + self.linux_info['install_path']
        if not os.path.exists(path):
            xlogging.raise_system_error(r'无法访问备份快照中的关键数据区域',
                                        r'_get_agent_app_path failed : {}'.format(path), 1)
        return path

    def _get_soft_ident_path(self):
        path = os.path.join(self.root_path, 'boot', 'ClerwareSoftIdent')
        _logger.info(r'soft_ident_path : {}   {}'.format(path, os.path.exists(path)))
        return path

    @staticmethod
    def _convert_to_device_string(devices):
        result = list()
        for device in devices:
            params = device.split(',')[1:]
            val_dec = [param.split('=')[-1] for param in params]
            output = 'VEN_{0:0>4X}&DEV_{1:0>4X}&SUBSYS_{2:0>4X}{3:0>4X}&REV_{4:0>2X}&CLASS_{5:0>4X}{6:0>2X}'.format(
                int(val_dec[0]), int(val_dec[1]), int(val_dec[2]), int(val_dec[3]), int(val_dec[4]), int(val_dec[5]),
                int(val_dec[6]))
            result.append(output)
        return result

    @staticmethod
    def _search_driver_from_snapshot(lib_modules_path, pci_devices):
        driver_files = list()
        not_found_devices = list()
        _logger.info('lib_modules_path :{},pci_devices:{}'.format(lib_modules_path, pci_devices))
        returned, found, not_found = modget.ModDepGet(lib_modules_path, pci_devices)
        if returned == 0:
            if not_found:
                not_found_devices = not_found
            for files in found:
                for file in files:
                    file_path = os.path.join(lib_modules_path, file)
                    if file_path not in driver_files:
                        driver_files.append(file_path)
        else:
            _logger.warning(r'modget.ModDepGet failed {} {} {}'.format(returned, lib_modules_path, pci_devices))
        _logger.info('driver_files:{}, not_found_devices:{}'.format(driver_files, not_found_devices))
        return driver_files, not_found_devices

    def _search_firmware_from_snapshot(self, driver_from_snapshot):
        firmware_searcher = mod_firmware.GetModFirmware(self.linux_info['release'], self.root_path)
        firmware_files = list()
        for driver in driver_from_snapshot:
            returned, files = firmware_searcher.get_firmware(driver)
            if returned != 0:
                xlogging.raise_system_error(r'无法访问备份快照中的关键数据区域',
                                            r'_search_firmware_from_snapshot failed {}:{}'.format(returned, driver), 1)

            firmware_files.extend(files)

        firmware_files = list(set(firmware_files))
        _logger.info(r'_search_firmware_from_snapshot : {}'.format(firmware_files))
        return firmware_files

    def _unpack_img_and_fetch_old_sdb(self):
        if not os.path.exists(self.org_init_ram_fs_path):
            xlogging.raise_system_error(r'无法访问备份快照中的关键数据区域',
                                        r'_unpack_img failed : {}'.format(self.org_init_ram_fs_path), 1)
        (res, x_dir) = self.initramfs.extract()
        if not res:
            xlogging.raise_system_error(r'备份快照中的关键数据区域无效',
                                        r'_unpack_img failed : {}'.format(self.org_init_ram_fs_path), 1)

        self.init_ram_fs_path = x_dir  # 更新为实际的目录
        _logger.info(r'_unpack_img ok . {}'.format(self.init_ram_fs_path))

        base_dir = os.path.abspath(x_dir)
        modules_dep_path = os.path.join(base_dir, r'lib', r'modules', self.linux_info['release'], r'modules.dep')
        if os.path.exists(modules_dep_path):
            cmd = r'touch "{}"'.format(modules_dep_path)
            returned_code = os.system(cmd)
            _logger.info('change modules.dep in initramfs file time {} : {}'.format(returned_code, cmd))
            time.sleep(1)
        else:
            _logger.warning(r'can NOT find modules.dep {}'.format(modules_dep_path))

        self._fetch_old_sbd_driver()

    def _pack_img(self):
        if not self.initramfs.pack(self.init_ram_fs_path):
            xlogging.raise_system_error(r'备份快照中的关键数据区域无法写入',
                                        r'_pack_img failed : {}'.format(self.org_init_ram_fs_path), 1)

    def _install_firmware(self, firmware_files):
        for file in firmware_files:
            if not os.path.exists(file):
                _logger.warning(r'_install_firmware ignore: {}'.format(file))
                continue
            relative_path = os.path.relpath(file, self.root_path)
            target_path = os.path.join(self.init_ram_fs_path, relative_path)
            target_dir = os.path.dirname(target_path)
            os.makedirs(target_dir, exist_ok=True)
            shutil.copy2(file, target_path)
            _logger.info(r'_install_firmware : {} -> {}'.format(file, target_path))

    def clear_up_invalid_sbd_drivers(self):
        need_remove_key = []
        for ko_name, info in self.clerware_sbd_drivers.items():
            if ('.ko' not in ko_name) or (len(info) != 4):
                need_remove_key.append(ko_name)
        for ko_name in need_remove_key:
            self.clerware_sbd_drivers.pop(ko_name, None)

    @staticmethod
    @xlogging.convert_exception_to_value(False)
    def _copy_debug_sbd_driver(module_name, file_path):
        debug_sbd_driver_json_path = r'/dev/shm/debug_sbd_driver.json'
        if not os.path.exists(debug_sbd_driver_json_path):
            return False
        with open(debug_sbd_driver_json_path) as f:
            debug_sbd_driver_config = json.load(f)
        _logger.info(r'will serach {} exist debug file config'.format(module_name))
        debug_file_path = debug_sbd_driver_config.get(module_name, None)
        if debug_file_path:
            _logger.warning(r'{} exist debug file config {}'.format(module_name, debug_file_path))
            shutil.copy2(debug_file_path, file_path)
            return True
        return False

    def _fetch_old_sbd_driver(self):
        self.clerware_sbd_drivers = {'ko_name': {'old_path': '', 'params': '', 'module_name': '', 'ko_type': ''}}
        self.clerware_sbd_drivers = OrderedDict(self.clerware_sbd_drivers)
        self.new_pdisk_labels = []
        for config in Initramfs.get_sbd_driver_config():
            ko_name = config['ko_name']
            self.clerware_sbd_drivers[ko_name] = {'old_path': os.path.join(self.link_path, 'old_' + ko_name)}

        files = self.initramfs.get_added_files(self.init_ram_fs_path)
        if files is None:
            xlogging.raise_system_error(r'获取关键数据文件失败，无效的系统引导文件', r'_fetch_old_sbd_driver no files', 1)
        _logger.info('_fetch_old_sbd_driver, get_added_files: {}'.format(files))

        for ko_type, _, ko_name, params, module_name, ramfs_ko_path in files:
            if ko_type == 'driver' and ko_name in self.clerware_sbd_drivers:  # is clrd
                ramfs_ko_file = os.path.join(self.init_ram_fs_path, ramfs_ko_path)
                if not self._copy_debug_sbd_driver(module_name, self.clerware_sbd_drivers[ko_name]['old_path']):
                    shutil.copy2(ramfs_ko_file, self.clerware_sbd_drivers[ko_name]['old_path'])

                sbd_params, new_pdisk_label = self._calc_sbd_params(params)
                if new_pdisk_label:
                    self.new_pdisk_labels.append(new_pdisk_label)
                self.clerware_sbd_drivers[ko_name]['ko_type'] = ko_type
                self.clerware_sbd_drivers[ko_name]['params'] = sbd_params
                self.clerware_sbd_drivers[ko_name]['module_name'] = module_name

        self.clear_up_invalid_sbd_drivers()
        if not self.clerware_sbd_drivers:
            xlogging.raise_system_error(r'获取关键数据文件失败', r'_fetch_old_sbd_driver failed {}'.format(files), 1)
        _logger.info('_fetch_old_sbd_driver, self.clerware_sbd_drivers: {}'.format(self.clerware_sbd_drivers))

    def _install_all_driver_and_app(self, driver_files):
        files = list()
        # 加入sbd驱动
        for ko_name, info in self.clerware_sbd_drivers.items():
            files.append((info['ko_type'], info['old_path'], ko_name, info['params'], info['module_name']))

        # 加入设备驱动
        for driver in driver_files:
            driver_file_name = os.path.basename(driver)
            driver_module_name = self._get_driver_module_name(driver_file_name)
            files.append(
                ('driver', driver, driver_file_name, get_force_config_params(driver_file_name, ''), driver_module_name))
        # 加入ip-set应用
        # files.append(
        #     ('app', self._get_ip_set_path(), 'ip-set',
        #      get_force_config_params(force_config_params_ip_set, r'> /proc/filter_proc'), 'ip-set'))

        need = self.initramfs.need_initwait_app(self.init_ram_fs_path)
        _logger.info('initramfs.need_initwait_app need={}'.format(need))
        if need:
            initwait_path = self._get_initwait_path()
            files.append(('app', initwait_path, 'initwait', '', ''))

        _logger.info(r'initramfs.add_files : {}'.format(files))
        returned = self.initramfs.add_files(self.init_ram_fs_path, files, self.is_htb())
        if returned != 0:
            xlogging.raise_system_error(r'配置系统关键数据区域失败',
                                        r'_install_driver failed : {}'.format(returned), returned)

    # 获取centos5下, 等待app的路径
    def _get_initwait_path(self):
        # 如果是64位的, 里面应该含有64, 如果是32或32_PAE, 那么应该用32位的.
        _logger.info("linux_info['bit_opt']={}".format(self.linux_info['bit_opt']))
        bits = '32'
        if str(self.linux_info['bit_opt']).find('64') != -1:
            bits = '64'
        elif str(self.linux_info['bit_opt']).find('32') != -1:
            bits = '32'
        else:
            _logger.warning("unknown linux_info['bit_opt'], use initwait32")
        initwait_name = 'initwait' + bits
        initwait_path = os.path.join(loadIce.current_dir, r'clerware_linux_apps', initwait_name)
        _logger.info(r'_get_initwait_path : {}'.format(initwait_path))
        return initwait_path

    @staticmethod
    def _get_driver_module_name(driver_file_name):
        if '.' not in driver_file_name:
            return driver_file_name
        else:
            return '.'.join(driver_file_name.split('.')[:-1])

    def get_adapter_cfg(self, ip_configs):
        key_adapter = list()  # 驱动需要的数据
        all_adapter = list()  # ip_service 需要的数据
        for item in ip_configs:
            multi_info = json.loads(item['multiInfos'])
            ip_mask_pair = [{'ip': item['Ip'], 'mask': item['Mask']} for item in multi_info['ip_mask_pair']]
            mac = item['mac']
            if multi_info['target_nic']['isConnected']:
                adapter = dict()
                adapter['mac'] = mac
                adapter['name'] = multi_info.get('name', None)
                adapter['ipAddress'] = item['ipAddress']
                adapter['subnetMask'] = item['subnetMask']
                adapter['gateway'] = item['gateway']
                adapter['nameServer'] = item['nameServer']
                adapter['ips'] = ip_mask_pair[1:]
                adapter['is_to_self'] = multi_info.get('is_to_self', False)  # 接管没有这个参数
                key_adapter.append(adapter)
            _adapter = dict()
            _adapter['mac'] = mac
            _adapter['name'] = multi_info.get('name', None)
            _adapter['mtu'] = multi_info.get('mtu', -1)
            _adapter['ip_mask_pair'] = ip_mask_pair
            _adapter['dns_list'] = multi_info['dns_list']
            _adapter['gateway'] = multi_info['gate_way']
            all_adapter.append(_adapter)
        if len(key_adapter) != 1:
            xlogging.raise_system_error('配置网卡信息失败', 'not find key adapter,ip_configs:{}'.format(ip_configs), 33)

        return key_adapter, all_adapter

    def _backup_cfg_files(self, modify_handle, soft_ident_path):
        if not self.htb_key_data_dir:
            _logger.info(r'not htb, do NOT _backup_cfg_files')
            return

        with open(modify_handle.ini_file_path, 'rb') as f:
            content = f.read()
        ret = net_common.get_info_from_syscmd("/sbin/aio/regdata/regdata -set -string {} AgentService_ini '{}'"
                                              .format(self._get_reg_file_path(), base64.b64encode(content).decode()))
        if ret[0] != 0:
            _logger.info('_backup_cfg_files run fail!a')
        else:
            _logger.info('_backup_cfg_files run successful!a')
        with open(modify_handle.cfg_file_path, 'rb') as f:
            content = f.read()
        ret = net_common.get_info_from_syscmd("/sbin/aio/regdata/regdata -set -string {} AgentService_config '{}'"
                                              .format(self._get_reg_file_path(), base64.b64encode(content).decode()))
        if ret[0] != 0:
            _logger.info('_backup_cfg_files run fail!b')
        else:
            _logger.info('_backup_cfg_files run successful!b')
        with open(soft_ident_path, 'rb') as f:
            content = f.read()
        ret = net_common.get_info_from_syscmd("/sbin/aio/regdata/regdata -set -string {} soft_ident '{}'"
                                              .format(self._get_reg_file_path(), base64.b64encode(content).decode()))
        if ret[0] != 0:
            _logger.info('_backup_cfg_files run fail!c')
        else:
            _logger.info('_backup_cfg_files run successful!c')

    def _alter_agent(self):
        agent_app_path = self._get_agent_app_path()
        config = json.loads(self.restore_config['agent_service_configure'])
        modify_handle = ModifyConfig(agent_app_path, config)
        modify_handle.modify_ini()
        modify_handle.modify_cfg()

        # 修改 soft_ident
        soft_ident_path = self._get_soft_ident_path()
        with open(soft_ident_path, 'w') as f:
            f.write(config.get('soft_ident', ''))

        self._backup_cfg_files(modify_handle, soft_ident_path)

        # 删除现有的隧道
        self._del_current_tunnel()
        # 添加隧道
        self._add_tunnel(config)

    def _set_clw_boot(self):
        clw_boot_path = self.root_path + xdefine.CLW_BOOT_REDIRECT_GPT_LINUX_MOUNT_PATH  # clw 磁盘挂载的目录

        if not os.path.isdir(clw_boot_path):
            _logger.info(r'skip set clw boot, not clw_boot_path : {}'.format(clw_boot_path))
            return
        target_grub_path = os.path.join(clw_boot_path, 'grub2', 'grub.cfg')
        if not os.path.isfile(target_grub_path):
            _logger.info(r'skip set clw boot, not target_grub_path : {}'.format(target_grub_path))
            return

        # 以上情况不开启引导重定向功能

        init_ram_fs_file = os.path.basename(self.org_init_ram_fs_path)

        grub_path = self._search_grub_path()

        kernel_line = self._search_kernel_line(grub_path, '/' + init_ram_fs_file)
        if not kernel_line:
            xlogging.raise_system_error('解析GRUB参数失败', '_search_kernel_line failed', 1)

        source_kernel_path = self._find_kernel_path(kernel_line)
        target_kernel_path = shutil.copy2(source_kernel_path, clw_boot_path)
        target_init_ram_fs_path = shutil.copy2(self.org_init_ram_fs_path, clw_boot_path)

        _logger.info(r'copy [{}] -> [{}] ; [{}] -> [{}]'.format(source_kernel_path, target_kernel_path,
                                                                self.org_init_ram_fs_path, target_init_ram_fs_path))

        self._change_kernel_and_initrd(target_grub_path, kernel_line, '/' + init_ram_fs_file)

    def _search_grub_path(self):
        """按照以下路径搜索grub config

        '/boot/efi/EFI/redhat/grub.conf'
        '/boot/efi/EFI/centos/grub.cfg'
        '/boot/grub/grub.cfg'

        :raises:
            当无法搜索到grub config时会抛出异常
        :return:
            在一体机中挂载的源机路径中 grub config 的绝对路径
        """
        grub_path = None
        for r_path in ('/boot/efi/EFI/redhat/grub.conf', '/boot/efi/EFI/centos/grub.cfg', '/boot/grub/grub.cfg'):
            grub_path = self.root_path + r_path
            if os.path.isfile(grub_path):
                break
        else:
            xlogging.raise_system_error('查找GRUB配置文件失败', 'find grub file failed', 1)

        _logger.info('_search_grub_path : {}'.format(grub_path))
        return grub_path

    def _find_kernel_path(self, kernel_line):
        source_kernel_file = kernel_line.split()[1]

        source_kernel_path = self.root_path + source_kernel_file
        if os.path.exists(source_kernel_path):
            return source_kernel_path

        source_kernel_path = os.path.dirname(self.org_init_ram_fs_path) + source_kernel_file
        if os.path.exists(source_kernel_path):
            return source_kernel_path

        source_kernel_path = os.path.join(os.path.dirname(self.org_init_ram_fs_path),
                                          os.path.basename(source_kernel_file))
        if os.path.exists(source_kernel_path):
            return source_kernel_path

        source_kernel_path = self.root_path + '/boot' + source_kernel_file
        if os.path.exists(source_kernel_path):
            return source_kernel_path

        xlogging.raise_system_error('解析GRUB参数失败，无法搜索到有效的内核文件',
                                    '_find_kernel_path failed {}'.format(kernel_line), 1)

    @staticmethod
    def _change_kernel_and_initrd(target_grub_path, kernel_line, init_ram_fs_file):
        _logger.info(r'begin fix kernel_line : {}'.format(kernel_line))
        CLW_GRUB_KERNEL_FLAG = 'linux16'
        CLW_GRUB_INITRD_FLAG = 'initrd16'
        kernel_line_split = kernel_line.split()
        kernel_line_split[0] = CLW_GRUB_KERNEL_FLAG
        kernel_line_split[1] = '/' + os.path.basename(kernel_line_split[1])
        new_kernel_line = ' '.join(kernel_line_split)
        _logger.info(r'end fix kernel_line : {}'.format(new_kernel_line))

        with open(target_grub_path) as f:
            grub = f.readlines()

        with open(target_grub_path, 'w') as f:
            for line in grub:
                line_strip = line.strip()
                if line_strip.startswith(CLW_GRUB_KERNEL_FLAG):
                    f.write('        {}\n'.format(new_kernel_line))
                elif line_strip.startswith(CLW_GRUB_INITRD_FLAG):
                    f.write('        {} {}\n'.format(CLW_GRUB_INITRD_FLAG, init_ram_fs_file))
                else:
                    f.write(line)

        with open(target_grub_path) as f:
            grub = f.read()
            _logger.info(r'new grub : {}'.format(grub))

    @staticmethod
    def _search_kernel_line(source_grub_path, init_ram_fs_file):

        def _is_kernel_line():
            return source.startswith('kernel') or source.startswith('linuxefi') or source.startswith('linux')

        def _is_init_ram_fs_line():
            return (source.startswith('initrd') or source.startswith('initrdefi')) and source.endswith(init_ram_fs_file)

        kernel_line = None
        find_init_ram_fs_file = False
        with open(source_grub_path) as f:
            source_grub = f.readlines()

        for source in source_grub:
            if source.startswith(' ') or source.startswith('\t'):
                source = source.strip()

                if _is_kernel_line():
                    kernel_line = source
                elif _is_init_ram_fs_line():
                    find_init_ram_fs_file = True
            else:
                kernel_line = None
                find_init_ram_fs_file = False

            if kernel_line and find_init_ram_fs_file:
                _logger.info('find kernel line [{}] with init_ram_fs_file [{}]'.format(kernel_line, init_ram_fs_file))
                return kernel_line

        _logger.error(r'can not find {} in {} : {}'.format(init_ram_fs_file, source_grub_path, source_grub))

    @staticmethod
    def read_bin_file_no_print_context(file_path):
        try:
            max_buffer_bytes = 8 * 1024 * 1024
            with open(file_path, 'rb') as file_handle:
                while True:
                    read_bytes = len(file_handle.read(max_buffer_bytes))
                    _logger.info("file_path = {},read len = {}".format(file_path, read_bytes))
                    if read_bytes < max_buffer_bytes or read_bytes == 0:
                        break
        except Exception as e:
            _logger.error(r'read_bin_file_no_print_context {} failed. {}'.format(file_path, e), exc_info=True)

    # 拷贝bmf
    def _copy_bmf_data(self):
        bmf_dir_boot = os.path.join(self.root_path, 'boot')
        bmf_dir_bin = self._get_agent_app_path()
        bmf_dir, bmf_file_names = find_bmf_file(bmf_dir_boot, bmf_dir_bin, self.root_path)
        _logger.info('bmf_dir:{}, bmf_file_names{}'.format(bmf_dir, bmf_file_names))
        if bmf_file_names and (len(bmf_file_names) % 3 == 0):
            with open(self.floppy_path, "wb") as f:
                f.seek(4 * 1024)
                bad_index = []
                bmf_file_names.sort()
                for index, file_path in enumerate(bmf_file_names):

                    # 必须把bmf文件完整的读取，否则在bmf文件跨越 64k 块并且未读取过时，会被还原掉。。。
                    self.read_bin_file_no_print_context(file_path)

                    with open(file_path, "rb") as f1:
                        content = f1.read(4 * 1024)
                    if not content:
                        _logger.error("_copy_bmf_data bmf file is empty, file path:{}".format(file_path))
                        continue
                    if len(content) != 4 * 1024:
                        _logger.error("_copy_bmf_data bmf file is not 4K, file path:{}".format(file_path))
                        continue
                    if index % 3 == 0:
                        bad_index = get_bad_index(content, bad_index, index)
                    if index in bad_index:
                        _logger.error("_copy_bmf_data bmf file is bad, file path:{}".format(file_path))
                        continue
                    _logger.info('_copy_bmf_data bmf file is success, file path:{}'.format(file_path))
                    f.write(content)
        else:
            xlogging.raise_system_error(r'备份快照中的关键数据区域无效',
                                        r'_copy_bmf_data failed not find bmf file, bmf_dir:{} {}'.format(
                                            bmf_dir, bmf_file_names), 1)

    @staticmethod
    def _calc_sbd_params(old_sbd_params):
        if (old_sbd_params is None) or ('pdisk_label' not in old_sbd_params):
            return old_sbd_params, None

        params = dict()
        for kv in old_sbd_params.split(' '):
            kv_object = kv.split('=')
            params[kv_object[0]] = kv_object[1]

        old_pdisk_label = int(params['pdisk_label'])

        new_pdisk_label = old_pdisk_label
        while new_pdisk_label == old_pdisk_label:
            new_pdisk_label = random.randint(60000, 200000000)
        params['pdisk_label'] = str(new_pdisk_label)

        sbd_params = ''
        for param_key in params.keys():
            if len(sbd_params) != 0:
                sbd_params += ' '
            sbd_params += '{}={}'.format(param_key, params[param_key])

        _logger.info(r'_calc_sbd_params : {}'.format(sbd_params))
        return sbd_params, params['pdisk_label']

    def _del_current_tunnel(self):
        ret = net_common.get_info_from_syscmd(
            "/sbin/aio/regdata/regdata -del_proxy {}".format(self._get_reg_file_path()))
        if ret[0] != 0:
            _logger.info('_del_current_tunnel run fail!')
        else:
            _logger.info('_del_current_tunnel run successful!')

    def _add_tunnel(self, config):
        if config['aio_ip'] == '127.0.0.1':
            tunnel_ip = config['tunnel_ip']
            tunnel_port = config['tunnel_port']
            cmd = "/sbin/aio/regdata/regdata -add_proxy {} {} {} 20010\|20011\|20002\|20003".format(
                self._get_reg_file_path(), tunnel_ip, tunnel_port)
            retval, stdout, stderr = net_common.get_info_from_syscmd(cmd)
            if retval != 0:
                _logger.info('_add_tunnel run fail!')
            if retval == 0:
                _logger.info('_add_tunnel run successful!')

        else:
            pass

    def is_htb(self):
        config = json.loads(self.restore_config['agent_service_configure'])
        _logger.info('[is_htb] agent_service_configure={}'.format(config))
        rev = config.get('htb_task_uuid', False) and len(config['htb_task_uuid']) == 32
        _logger.info('restore target:{} is_htb:{}'.format(self.pe_ident, rev))
        return bool(rev)

    # 根据网络配置，生成udev规则
    def _generate_udev_rules(self, ip_configs):
        # suse_support.modify_suse_udev_rules(self.root_path, ip_configs)
        """
        if not os.path.exists(dir_path):
            _logger.info('_generate_udev_rules not find:{}, do nothing'.format(dir_path))
            return None

        attr_key = self._get_udev_rules_attr_key(dir_path)
        _logger.info('_generate_udev_rules attr key is :{}'.format(attr_key))

        common = ['SUBSYSTEM=="net"',
                  'ACTION=="add"',
                  'DRIVERS=="?*"',
                  '{attr_key}{{type}}=="1"'.format(attr_key=attr_key)
                  ]
        mac_fmt, name_fmt = '{attr_key}{{address}}=="{mac}"', 'NAME="{name}"'
        lines = list()
        for index, ip_config in enumerate(ip_configs):
            content_list = common.copy()
            content_list.append(mac_fmt.format(mac=self._format_mac(ip_config['mac']), attr_key=attr_key))
            if ip_config['name']:
                content_list.append(name_fmt.format(name=ip_config['name']))
            else:
                content_list.append(name_fmt.format(name='eth{}'.format(index)))

            lines.append('{}\n'.format(','.join(content_list)))

        with open(os.path.join(dir_path, '99-persistent-net-clwd.rules'), 'wt') as f:
            f.writelines(lines)
        """
        pass

    # 格式化成 xx:xx:xx:xx:xx:xx
    @staticmethod
    def _format_mac(mac):
        mac = mac.replace(' ', '').replace('-', '').replace(':', '').lower()
        assert len(mac) == 12
        mac_new = ''
        for index, value in enumerate(mac, 1):
            if index % 2 == 0:
                mac_new += '{}:'.format(value)
            else:
                mac_new += value
        return mac_new.rstrip(':')

    # 返回 udev attr key
    # 老版本udev 使用 SYSFS作为属性key, 新版本使用 ATTR
    @staticmethod
    def _get_udev_rules_attr_key(search_dir):
        cmd = r'grep SYSFS {}/*'.format(search_dir)
        code, *_ = net_common.get_info_from_syscmd(cmd)
        if code == 0:
            return 'SYSFS'
        else:
            return 'ATTR'

    def _load_clrd_initrd_info(self):
        install_path = os.path.dirname(self._get_agent_app_path())
        _logger.debug('[_load_clrd_initrd_info] install_path {}'.format(install_path))
        json_path = save_clrd_initrd.get_clrd_initrd_json_path(install_path)
        if not os.path.exists(json_path):
            _logger.warning('[_load_clrd_initrd_info] not found path {}'.format(json_path))
            return None, None
        with open(json_path) as fp:
            content = json.load(fp)
        return content, save_clrd_initrd.get_clrd_initrd_dir_path(install_path)

    # 将 grub vmlinuz initr 进行覆盖
    @xlogging.convert_exception_to_value(False)
    def fix_initrd(self):
        """
        将备份的initrd, grub, vmlinuz 按照规则进行覆盖
        """
        content, clrd_initrd_dir = self._load_clrd_initrd_info()
        if not content:
            _logger.info('[fix_initrd] not content, skip fix')
            return
        _logger.info('[fix_initrd] clrd_initrd_dir {} content {}'.format(clrd_initrd_dir, content))

        """
        以下文件中，若save_clrd_initrd 中存在，目标不存在，或者2者MD5不一样则进行覆盖
        """
        copy_map = list()
        for file in (
                content.get(save_clrd_initrd.key_grub_path, ''),
                content.get(save_clrd_initrd.key_grubenv_path, ''),
                content.get(save_clrd_initrd.key_initrd_path, ''),
                content.get(save_clrd_initrd.key_vmlinuz_path, ''),
        ):
            if file:
                name = os.path.basename(file)
                file_path = os.path.join(clrd_initrd_dir, name)
                if os.path.exists(file_path):
                    copy_map.append((file_path, self.root_path + file))
        if not copy_map:
            _logger.info('[fix_initrd] copy_map is empty, skip fix'.format(copy_map))
            return

        # 检测是否需要覆盖
        for src, dst in copy_map:
            if not os.path.exists(dst):
                _logger.warning('[fix_initrd] dst file {} not exists, need fix'.format(src))  # 目标不存在 认为也需要覆盖
                break
            else:
                if self._GetFileMd5(src) != self._GetFileMd5(dst):
                    _logger.warning('[fix_initrd] diff {} and {}, need fix'.format(src, dst))
                    break
        else:
            _logger.info('[fix_initrd] same src and dst, skip fix'.format(copy_map))
            return

        def _my_copy(src_path, dst_path):
            _logger.debug('[fix_initrd] start copy {} to {}'.format(src_path, dst_path))
            try:
                shutil.copy2(src_path, dst_path)
            except Exception as e:
                _logger.error('[fix_initrd] _my_copy error:{}'.format(e), exc_info=True)
                return False
            else:
                if not os.path.exists(dst_path):
                    return False
                else:
                    return True

        for src, dst in copy_map:
            if not _my_copy(src, dst):
                break
            else:
                _logger.info('[fix_initrd] copy {} to {} successful'.format(src, dst))
        else:
            _logger.info('[fix_initrd], fix successful')
            self.linux_info['initrdfs_path'] = content[save_clrd_initrd.key_initrd_path]  # 使用新的initrd

    def _copy_grub_to_backup_dir(self):
        """
        将修正完成的grub 文件拷贝一份到 clrd_initrd_dir
        """
        _logger.debug('[_copy_grub_to_backup_dir] begin ...')
        content, clrd_initrd_dir = self._load_clrd_initrd_info()
        if not content:
            _logger.info('[_copy_grub_to_backup_dir] not content, skip fix')
            return
        path = content.get(save_clrd_initrd.key_grub_path, '')
        if not path:
            _logger.info('[_copy_grub_to_backup_dir] not path, skip fix')
            return
        name = os.path.basename(path)
        dst = os.path.join(clrd_initrd_dir, name)
        src = self.root_path + path
        _logger.debug('[_copy_grub_to_backup_dir] start copy {} to {}'.format(src, dst))
        self._copy_file_with_retry(src, dst)
        _logger.debug('[_copy_grub_to_backup_dir] copy {} to {} successful'.format(src, dst))
        _logger.debug('[_copy_grub_to_backup_dir] end ...')
