# coding=utf-8
# !/usr/bin/python

import os
import shlex
import shutil
import subprocess
import sys
import threading
import time

import kvm_host
import linux_system_locker
import net_common
import xlogging

_logger = xlogging.getLogger(__name__)
_nbd_logger = xlogging.getLogger('nbd_r')
_device_size = None

_TMP_DIR = r'/dev/shm/dev'
_EXEC_PATH = r'/sbin/aio/gznbd'
_QEMU_NDB_EXEC_PATH = r'qemu-nbd'
_LVM_CFG_PATH = r'/etc/lvm/lvm.conf'
_LVM_CFG_TEMP_PATH = r'/etc/lvm/lvm.conf.tmp'
_LVM_CFG_BEGIN = r'#CLW_FLAG_BEGIN'
_LVM_CFG_END = r'#CLW_FLAG_END'
_LVM_CFG_FILE_LOCK = r'/run/systemlocker.logic_serivce.lvm_cfg'

_lvm_global_filter = set()
_lvm_global_filter_locker = threading.RLock()


class nbd_direct_images(threading.Thread):
    def __init__(self, name, nbd_wrapper_object, disk_snapshots):
        threading.Thread.__init__(self)
        self.name = name
        self.disk_snapshots = disk_snapshots
        self.nbd_wrapper_object = nbd_wrapper_object

    def start(self):
        self.nbd_wrapper_object.is_thread_alive = True
        try:
            super(nbd_direct_images, self).start()
        except Exception as e:
            _logger.error(r'!!!~~!!! start thread failed {}'.format(e), exc_info=True)
            self.nbd_wrapper_object.is_thread_alive = False
            raise

    def run(self):
        try:
            _logger.debug('nbd_direct_images {} - {} start'.format(self.name, self.nbd_wrapper_object.device_name))
            self.nbd_wrapper_object.mount_with_disk_snapshot(self.disk_snapshots)
            _logger.debug('nbd_direct_images {} - {} exit'.format(self.name, self.nbd_wrapper_object.device_name))
        except Exception as e:
            _logger.error('nbd_direct_images error:{}'.format(e), exc_info=True)
        finally:
            self.name = None
            self.disk_snapshots = None
            self.nbd_wrapper_object.is_thread_alive = False
            self.nbd_wrapper_object = None


class nbd_wrapper(object):
    def __init__(self, allocator, use_qemu_nbd=False):
        self._allocator = allocator
        self.use_qemu_nbd = use_qemu_nbd
        self.is_mount = False
        self.__cmd_unmount_nbd = None
        self.is_thread_alive = False

    @property
    def device_index(self):
        return self._allocator.device_index

    @property
    def device_name(self):
        return self._allocator.device_name

    @property
    def device_path(self):
        return self._allocator.device_path

    @property
    def vnc_address(self):
        return self._allocator.vnc_address

    @property
    def serial_port(self):
        return self._allocator.serial_port

    def __del__(self):
        _logger.info('nbd_wrapper __del__ device:{}'.format(self.device_path))
        try:
            self.unmount()
        finally:
            self.set_no_longer_used()

    def set_no_longer_used(self):
        if self._allocator:
            self._allocator.set_unused()
            self._allocator = None

    @staticmethod
    def set_unused(device_name):
        if device_name is None:
            return
        path = os.path.join(_TMP_DIR, device_name)
        if os.path.exists(path):
            _logger.info('nbd_wrapper set_unused remove:{}'.format(path))
            os.remove(path)

    @staticmethod
    def set_used(device_name):
        if device_name is None:
            return
        path = os.path.join(_TMP_DIR, device_name)
        if os.path.exists(path):
            return

        tfd = os.open(path, os.O_CREAT | os.O_EXCL)
        os.close(tfd)

        nbd_wrapper.check_unused(device_name)

    @staticmethod
    def check_unused(device_name):
        _logger.debug('nbd_wrapper check_unused device_name:{}'.format(device_name))
        if os.path.exists('/dev/{}'.format(device_name)) and nbd_wrapper.nbd_read_ok('/dev/{}'.format(device_name)):
            xlogging.raise_system_error(r'内部错误，虚拟磁盘设备残留', r'nbd_wrapper set_used {}'.format(device_name), 2312)

    @staticmethod
    def find_unused():
        for i in range(0, _device_size):
            try:
                nbd_device_name = r'nbd{:d}'.format(i)
                tfd = os.open(os.path.join(_TMP_DIR, nbd_device_name), os.O_CREAT | os.O_EXCL)
                os.close(tfd)
                nbd_wrapper.check_unused(nbd_device_name)
                return (i,
                        nbd_device_name,
                        os.path.join('/dev', nbd_device_name),
                        r'0.0.0.0:{:d}'.format(200 + i),
                        r'tcp::{:d}'.format(5100 + i) if os.path.exists(r'/dev/shm/kvm_serial') else None
                        )
            except OSError:
                continue
        xlogging.raise_system_error(r'系统资源耗尽，已经使用全部虚拟磁盘设备', r'_find_unused not unused device',
                                    _device_size, _logger)

    @staticmethod
    def find_unused_reverse():
        for i in range(_device_size - 1, -1, -1):
            try:
                nbd_device_name = r'nbd{:d}'.format(i)
                tfd = os.open(os.path.join(_TMP_DIR, nbd_device_name), os.O_CREAT | os.O_EXCL)
                os.close(tfd)
                nbd_wrapper.check_unused(nbd_device_name)
                return (i,
                        nbd_device_name,
                        os.path.join('/dev', nbd_device_name),
                        r'0.0.0.0:{:d}'.format(200 + i),
                        r'tcp::{:d}'.format(5100 + i) if os.path.exists(r'/dev/shm/kvm_serial') else None
                        )
            except OSError:
                continue
        xlogging.raise_system_error(r'系统资源耗尽，已经使用全部虚拟磁盘设备', r'find_unused_reverse not unused device',
                                    _device_size, _logger)

    def mount_with_box_service(self, peHostIdent, diskToken, diskBytes):
        try:
            if self.is_mount:
                xlogging.raise_system_error(r'内部错误，重复挂载虚拟磁盘设备', r'mount_with_box_service is_mount {}'
                                            .format(self.device_path), self.device_index, _logger)

            nbd_wrapper.check_unused(self.device_name)

            if nbd_wrapper.nbd_read_ok(self.device_path):
                xlogging.raise_system_error(r'内部错误，挂载虚拟磁盘设备重复', r'mount_with_box_service nbd_read_ok {}'
                                            .format(self.device_path), self.device_index, _logger)

            cmd_nbd = "{} -b {} {} {} {:d} 5".format(_EXEC_PATH, self.device_path, peHostIdent, diskToken, diskBytes)

            split_nbd_cmd = shlex.split(cmd_nbd)
            with subprocess.Popen(split_nbd_cmd, stderr=subprocess.PIPE, universal_newlines=True) as p:
                self.is_mount = True
                _logger.info("mount_with_box_service pid:{} {} ".format(p.pid, cmd_nbd))
                for line in p.stderr:
                    _nbd_logger.debug('{}:{}'.format(p.pid, line.rstrip()))
            _logger.info("mount_with_box_service end : pid:{} - {}".format(p.pid, p.returncode))
        finally:
            self.is_mount = False

    def mount_with_disk_snapshot(self, disk_snapshots):
        try:
            if self.is_mount:
                xlogging.raise_system_error(r'内部错误，重复挂载虚拟磁盘设备', r'mount_with_disk_snapshot is_mount {}'
                                            .format(self.device_path), self.device_index, _logger)

            nbd_wrapper.check_unused(self.device_name)

            if self.use_qemu_nbd:
                cmd_nbd = "{} -c {}".format(_QEMU_NDB_EXEC_PATH, self.device_path)
                for disk_snapshot in disk_snapshots:
                    cmd_nbd += r' {}'.format(disk_snapshot['path'])
            else:
                cmd_nbd = "{} -c {}".format(_EXEC_PATH, self.device_path)
                for disk_snapshot in disk_snapshots:
                    cmd_nbd += r' {} {}'.format(disk_snapshot['path'], disk_snapshot['ident'])

            split_nbd_cmd = shlex.split(cmd_nbd)
            self.is_mount = True
            with subprocess.Popen(split_nbd_cmd, stderr=subprocess.PIPE, universal_newlines=True) as p:
                _logger.info("mount_with_disk_snapshot pid:{} {} ".format(p.pid, cmd_nbd))
                for line in p.stderr:
                    _nbd_logger.debug('{}:{}'.format(p.pid, line.rstrip()))
            _logger.info("mount_with_disk_snapshot end : pid:{} - {}".format(p.pid, p.returncode))
        finally:
            if self.use_qemu_nbd:
                pass
            else:
                self.is_mount = False

    def mount_with_input_cmd(self, cmd_mount_nbd, cmd_unmount_nbd):
        try:
            if self.is_mount:
                xlogging.raise_system_error(r'内部错误，重复挂载虚拟磁盘设备', r'mount_with_disk_snapshot is_mount {}'
                                            .format(self.device_path), self.device_index, _logger)

            self.__cmd_unmount_nbd = cmd_unmount_nbd
            nbd_wrapper.check_unused(self.device_name)
            split_nbd_cmd = shlex.split(cmd_mount_nbd)
            self.is_mount = True
            with subprocess.Popen(split_nbd_cmd, stderr=subprocess.PIPE, universal_newlines=True) as p:
                _logger.info("mount_with_disk_snapshot pid:{} {} ".format(p.pid, cmd_mount_nbd))
                for line in p.stderr:
                    _nbd_logger.debug('{}:{}'.format(p.pid, line.rstrip()))
            _logger.info("mount_with_disk_snapshot end : pid:{} - {}".format(p.pid, p.returncode))
        finally:
            self.is_mount = False

    def unmount(self):
        if self.is_mount:
            net_common.get_info_from_syscmd(r"sync")
            if self.__cmd_unmount_nbd:
                cmd_nbd = self.__cmd_unmount_nbd
            else:
                if self.use_qemu_nbd:
                    cmd_nbd = "{} -d {}".format(_QEMU_NDB_EXEC_PATH, self.device_path)
                else:
                    cmd_nbd = "{} -d {}".format(_EXEC_PATH, self.device_path)
            _logger.info("unmount : {}".format(cmd_nbd))
            status = net_common.get_info_from_syscmd(cmd_nbd)[0]
            _logger.info("unmount end : {} - {}".format(status, cmd_nbd))
            if self.use_qemu_nbd and status == 0:
                self.is_mount = False

    def wait_no_mounting(self):
        _logger.info(r'wait_no_mounting begin : {}'.format(self.device_name))
        retry_times = 0
        while self.is_mount:
            time.sleep(1)
            retry_times += 1
            if (retry_times % 5) == 0:
                self.unmount()
        _logger.info(r'wait_no_mounting end : {}'.format(self.device_name))

    @staticmethod
    def nbd_read_ok(nbd_dev_path):
        try:
            _logger.info(r'begin read {} sector 0'.format(nbd_dev_path))
            with open(nbd_dev_path, 'rb') as nbd_file:
                nbd_file.seek(0)
                nbd_content = nbd_file.read(64 * 1024)  # 64KBytes
                if len(nbd_content) == 0:
                    raise Exception(r'len(nbd_content) == 0')
                else:
                    _logger.info(r'read {} sector 0 ok'.format(nbd_dev_path))
                    return True
        except Exception as e:
            _logger.warning(r'begin read {} sector 0 failed : {}'.format(nbd_dev_path, e))
            return False

    @staticmethod
    def wait_nbd_read_ok(nbd_object, loop_retry_times=300):  # 30分钟
        try:
            nbd_read_ok = False

            read_retry_times = 6

            while not nbd_read_ok:
                nbd_read_ok = nbd_wrapper.nbd_read_ok(nbd_object.device_path)
                if nbd_read_ok:
                    break
                else:
                    read_retry_times -= 1
                    if read_retry_times > 0:
                        time.sleep(1)
                        continue
                    else:
                        pass

                read_retry_times = 6
                loop_retry_times -= 1

                if (not nbd_object.is_mount) and (not nbd_object.is_thread_alive):
                    xlogging.raise_system_error(
                        r'内部异常，启动NBD组件失败',
                        r'_wait_nbd_read_ok failed. is_mount is False {}'.format(nbd_object.device_path),
                        0, _logger)
                elif not nbd_read_ok:
                    if loop_retry_times < 0:
                        xlogging.raise_system_error(
                            r'内部异常，NBD组件读取失败',
                            r'_wait_nbd_read_ok failed. is_mount is true {}'.format(nbd_object.device_path),
                            0, _logger)
                    else:
                        _logger.warning(r'read {} need retry : {}'.format(nbd_object.device_path, loop_retry_times))
                else:
                    pass  # nbd_read_ok == True
        except Exception:
            nbd_object.wait_no_mounting()
            raise


class nbd_wrapper_empty_allocator(object):
    def __init__(self, device_index, device_name, device_path, vnc_address):
        self.device_index = device_index
        self.device_name = device_name
        self.device_path = device_path
        self.vnc_address = vnc_address
        self.serial_port = None

    def __del__(self):
        self.set_unused()

    def set_unused(self):
        self.device_index = None
        self.device_name = None
        self.device_path = None
        self.vnc_address = None
        self.serial_port = None


class nbd_wrapper_local_device_allocator(object):
    def __init__(self, reverse=False):
        self.device_index = None
        self.device_name = None
        self.device_path = None
        self.vnc_address = None
        self.serial_port = None
        if reverse:
            self.device_index, self.device_name, self.device_path, self.vnc_address, self.serial_port = \
                nbd_wrapper.find_unused_reverse()
        else:
            self.device_index, self.device_name, self.device_path, self.vnc_address, self.serial_port = \
                nbd_wrapper.find_unused()

    def __del__(self):
        self.set_unused()

    def set_unused(self):
        device_name = self.device_name
        self.device_index = None
        self.device_name = None
        self.device_path = None
        self.vnc_address = None
        if device_name:
            nbd_wrapper.set_unused(device_name)


class nbd_wrapper_disable_lvm_allocator(object):
    def __init__(self, allocator):
        self._allocator = allocator
        self.disable_lvm_scan(self.device_path)

    def __del__(self):
        try:
            self.set_unused()
        finally:
            if self._allocator:
                self._allocator.set_unused()
                self._allocator = None

    @property
    def device_index(self):
        return self._allocator.device_index

    @property
    def device_name(self):
        return self._allocator.device_name

    @property
    def device_path(self):
        return self._allocator.device_path

    @property
    def vnc_address(self):
        return self._allocator.vnc_address

    @property
    def serial_port(self):
        return self._allocator.serial_port

    def set_unused(self):
        device_path = self.device_path
        if device_path:
            self.enable_lvm_scan(device_path)

    @staticmethod
    def disable_lvm_scan(device_path):
        with _lvm_global_filter_locker:
            with linux_system_locker.LinuxSystemLocker(_LVM_CFG_FILE_LOCK):
                _lvm_global_filter.add(device_path)
                nbd_wrapper_disable_lvm_allocator.alter_lvm_cfg()

    @staticmethod
    def enable_lvm_scan(device_path):
        with _lvm_global_filter_locker:
            with linux_system_locker.LinuxSystemLocker(_LVM_CFG_FILE_LOCK):
                _lvm_global_filter.discard(device_path)
                nbd_wrapper_disable_lvm_allocator.alter_lvm_cfg()

    @staticmethod
    def alter_lvm_cfg():
        if len(_lvm_global_filter):
            global_filter = 'global_filter = [ {} ]\n'.format(
                ','.join([r'"r|^{}$|"'.format(x) for x in _lvm_global_filter]))
        else:
            global_filter = '\n'
        nbd_wrapper_disable_lvm_allocator.create_temp_lvm_cfg(global_filter)
        for i in range(3):
            try:
                shutil.copyfile(_LVM_CFG_TEMP_PATH, _LVM_CFG_PATH)
                return
            except Exception as e:
                _logger.error('copy lvm.cfg error:{}'.format(e), exc_info=True)
                time.sleep(0.1)

        # os.remove(_LVM_CFG_PATH)
        # os.rename(_LVM_CFG_TEMP_PATH, _LVM_CFG_PATH)
        # os.system('sync')

    @staticmethod
    def create_temp_lvm_cfg(global_filter):
        global_filter_content = [
            _LVM_CFG_BEGIN + '\n',
            'devices {\n',
            global_filter,
            '}\n',
            _LVM_CFG_END + '\n',
        ]
        with open(_LVM_CFG_PATH) as r:
            with open(_LVM_CFG_TEMP_PATH, 'w') as w:
                for line in r:
                    content = line.rstrip()
                    if content == _LVM_CFG_BEGIN:
                        w.writelines(global_filter_content)
                        break
                    else:
                        w.write(content + '\n')
                else:
                    w.writelines(global_filter_content)


class nbd_on_remote(nbd_wrapper):
    def __init__(self, allocator, kvm_host_object):
        super(nbd_on_remote, self).__init__(allocator)
        self._kvm_host_object = kvm_host_object
        self.gznbd_path = os.path.join(self._kvm_host_object.host_dir, 'gznbd')
        _logger.info(r'nbd_on_remote {} {}'.format(self.device_name, self.device_path))

    def mount_with_box_service(self, peHostIdent, diskToken, diskBytes):
        try:
            if self.is_mount:
                xlogging.raise_system_error(
                    r'内部错误，重复挂载虚拟磁盘设备', r'mount_with_box_service is_mount {} on {}'
                        .format(self.device_path, self._kvm_host_object.name), self.device_index, _logger)

            cmd_nbd = "{} -b {} {} {} {:d} 5".format(
                self.gznbd_path, self.device_path, peHostIdent, diskToken, diskBytes)

            self.is_mount = True
            cmd_runner = self._kvm_host_object.Popen(cmd_nbd,
                                                     kvm_host.get_logger_file_name('mount-' + self.device_path))
            _logger.info("pid {} mount : {} on {}".format(cmd_runner.pid, cmd_nbd, self._kvm_host_object.name))
            _logger.info("end mount return : {}  {} on {} "
                         .format(cmd_runner.returncode, cmd_nbd, self._kvm_host_object.name))
        finally:
            self.is_mount = False

    @xlogging.convert_exception_to_value(None)
    def unmount(self):
        if self.is_mount:
            kvm_host.kvm_host_exec_helper(self._kvm_host_object, r'sync', r'sync', _logger)
            cmd_nbd = r'"{}" -d {}'.format(self.gznbd_path, self.device_path)
            kvm_host.kvm_host_exec_helper(self._kvm_host_object, cmd_nbd, 'umount-' + self.device_path, _logger)

    @staticmethod
    def wait_nbd_on_remote_read_ok(nbd_object):
        # TODO : 需要检查nbd设备读取数据
        time.sleep(10)


def get_local_dir_path():
    path = os.path.split(os.path.realpath(__file__))[0]
    _logger.info(r'nbd path : {}'.format(path))
    return path


def init(device_size):
    global _device_size
    _device_size = device_size
    try:
        os.remove(_LVM_CFG_FILE_LOCK)
    except:
        pass
    if sys.platform.startswith('win32'):
        _logger.info(r'running in windows do NOT call insmod')
    else:
        _logger.info(r'running in linux')
        os.makedirs(_TMP_DIR, exist_ok=True)
        if not (os.path.exists(r'/dev/nbd{}'.format(device_size - 1))):
            insmod_nbd(device_size, 'nbd.862.ko')
            insmod_nbd(device_size, 'nbd.514.ko')
            insmod_nbd(device_size, 'nbd.ko')
            shutil.rmtree(_TMP_DIR, True)
            os.makedirs(_TMP_DIR)
    nbd_wrapper_disable_lvm_allocator.enable_lvm_scan('')
    for dev_name in os.listdir('/sys/class/block'):
        if not dev_name.startswith('nbd'):
            continue
        try:
            if not os.path.isfile('/sys/class/block/{}/queue/scheduler'.format(dev_name)):
                continue
            with open('/sys/class/block/{}/queue/scheduler'.format(dev_name), 'r+') as f:
                f.write('cfq')
        except:
            pass


def insmod_nbd(device_size, file_name):
    nbd_ko_path = os.path.join(get_local_dir_path(), file_name)
    nbd_max_part = device_size
    cmd_mod = r'insmod "{}" nbds_max={:d} max_part=32'.format(nbd_ko_path, nbd_max_part)
    os.system(cmd_mod)
