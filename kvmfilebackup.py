import os

import kvmcmdmgr
import kvmrunningmgr
import nbd
import nbdrwthread
import nettapmgr
import qemuimgcmd
import xlogging

_logger = xlogging.getLogger(__name__)


def read_kvm_file_backup_memory_mbytes(memory_mbytes=512):
    file_path = r'/etc/aio/kvm_file_backup_memory_mbytes'
    if os.path.isfile(file_path):
        try:
            with open(file_path) as f:
                memory_mbytes = int(f.read().strip())
        except Exception as e:
            _logger.error(r'read_kvm_file_backup_memory_mbytes failed {}'.format(e))
    return memory_mbytes


class KvmFileBackup(object):
    # 需要启动kvm，要2个网卡，期中一个网卡要指定mac地址，2个硬盘。
    # 参数:  aio_server_ip, diskbytes, disksnapshots
    def __init__(self, backup_params):
        self.__kvm_running = None
        self.__nbd_rw_thread = None
        self.__kvm_cmd_mgr = None
        self.__tap_nic = None
        self.__mac_address = None
        self.__ip_addr = None
        self.__tap_name = None

        self._backup_params = backup_params
        self.__key_info = dict()
        self.__key_info[r'logic'] = r'linux'
        self.__key_info['cores'] = self._backup_params['cores']
        self.__key_info['memory_mbytes'] = self._backup_params['memory_mbytes']

    def create_nbd_device(self, backup_params):

        _nbd_dev_name, _nbd_dev_number = self.__nbd_rw_thread.get_nbd_device_name()
        _cmd_nbd_umount = "/sbin/aio/nbdrw  -d  {}".format(_nbd_dev_name)
        _cmd_nbd_mount = "/sbin/aio/nbdrw  -rw  {} {}".format(_nbd_dev_name, backup_params['diskbytes'])
        for _disk_snapshot in backup_params['disksnapshots']:
            _cmd_nbd_mount += r' {} {}'.format(_disk_snapshot['path'], _disk_snapshot['ident'])
        self.__nbd_rw_thread.setDaemon(True)
        self.__nbd_rw_thread.start_and_wait_ready(_cmd_nbd_mount, _cmd_nbd_umount)

        return _nbd_dev_name, _nbd_dev_number

    def create_temp_qcow_file(self, temp_qcow_file):
        try:
            os.remove(temp_qcow_file)
        except:
            pass
        qemuimgcmd.QemuImgCmd().create_qcow2_file_base_old('/home/file_backup/nas.qcow2',
                                                           temp_qcow_file)

        if not os.path.exists(temp_qcow_file):
            raise Exception("create filie failed:{}".format(temp_qcow_file))

    def start(self):
        try:
            self.__nbd_rw_thread = nbdrwthread.NbdReadWriteThread()

            # 启动nbd
            _nbd_dev_name, _nbd_dev_number = self.create_nbd_device(self._backup_params)
            self.__key_info['vnc'] = "0.0.0.0:{}".format(_nbd_dev_number + 200)

            # 这里要打临时文件的快照。
            self.create_temp_qcow_file(self._backup_params['temp_qcow'])
            _blocks = [self._backup_params['temp_qcow'], _nbd_dev_name]

            # kvm命令行管理。
            self.__kvm_cmd_mgr = kvmcmdmgr.KvmCmdLineMgr(self.__key_info)

            # 应该是 2 块硬盘。
            for _file_path in _blocks:
                self.__kvm_cmd_mgr.add_block_dev('scsi-hd', _file_path)

            # 应该是 2 块网卡。
            self.__tap_nic = nettapmgr.NetTapMgr(self._backup_params['aio_server_ip'], r'fbtap', r'172.29.110')
            try:
                self.__tap_nic.start()
            except Exception as e:
                msg = "start tap failed: {}".format(e)
                _logger.error(msg)
                raise Exception(msg)

            self.__mac_address = self.__tap_nic.get_mac_address()
            self.__ip_addr = self.__tap_nic.get_ip_address()
            self.__tap_name = self.__tap_nic.get_tap_name()

            self.__kvm_cmd_mgr.add_net_dev(r'virtio-net-pci', self.__tap_name, None, self.__mac_address)

            # 获得 kvm 运行句柄。
            self.__kvm_running = kvmrunningmgr.KvmRunningThread(self.__kvm_cmd_mgr)

            self.__kvm_running.start()
        except Exception:
            self.kill()
            self.join()
            raise

    def get_ip_and_mac(self):
        return self.__ip_addr, self.__mac_address

    def join(self):
        _logger.info(r'KvmFileBackup start join')
        if self.__kvm_running:
            _logger.info(r'KvmFileBackup kvm running...')
            self.__kvm_running.join()
            self.__kvm_running = None
        if self.__nbd_rw_thread:
            _logger.info(r'KvmFileBackup __nbd_rw_thread...')
            self.__nbd_rw_thread.umount()
            self.__nbd_rw_thread.join()
            self.__nbd_rw_thread = None
        _logger.info(r'KvmFileBackup end join')

    def kill(self):
        _logger.info(r'KvmFileBackup start kill')
        if self.__kvm_running:
            self.__kvm_running.kill()
        _logger.info(r'KvmFileBackup end kill')

    def is_active(self):
        if self.__kvm_running:
            return self.__kvm_running.is_active()
        return False

    def nbd_alive(self):
        if self.__nbd_rw_thread and self.__nbd_rw_thread.is_alive():
            return True
        else:
            return False

    def kvm_alive(self):
        if self.__kvm_running and self.__kvm_running.is_active():
            return True
        else:
            return False


class KvmDBBackup(object):
    # 需要启动kvm，要2个网卡，期中一个网卡要指定mac地址，2个硬盘。
    # 参数:  aio_server_ip, diskbytes, disksnapshots
    def __init__(self, backup_params):
        self.__kvm_running = None
        self.__nbd_rw_thread = None
        self.__kvm_cmd_mgr = None
        self.__tap_nic = None
        self.__mac_address = None
        self.__ip_addr = None
        self.__tap_name = None

        self._backup_params = backup_params
        self.__key_info = dict()
        self.__key_info[r'logic'] = r'linux'
        self.__key_info['cores'] = self._backup_params['cores']
        self.__key_info['memory_mbytes'] = self._backup_params['memory_mbytes']

    def create_nbd_device(self, backup_params):

        _nbd_dev_name, _nbd_dev_number = self.__nbd_rw_thread.get_nbd_device_name()
        _cmd_nbd_umount = "/sbin/aio/nbdrw  -d  {}".format(_nbd_dev_name)
        _cmd_nbd_mount = "/sbin/aio/nbdrw  -rw  {} {}".format(_nbd_dev_name, backup_params['diskbytes'])
        for _disk_snapshot in backup_params['disksnapshots']:
            _cmd_nbd_mount += r' {} {}'.format(_disk_snapshot['path'], _disk_snapshot['ident'])
        self.__nbd_rw_thread.setDaemon(True)
        self.__nbd_rw_thread.start_and_wait_ready(_cmd_nbd_mount, _cmd_nbd_umount)

        return _nbd_dev_name, _nbd_dev_number

    def create_temp_qcow_file(self, temp_qcow_file):
        try:
            os.remove(temp_qcow_file)
        except:
            pass
        qemuimgcmd.QemuImgCmd().create_qcow2_file_base_old('/home/file_backup/nas.qcow2',
                                                           temp_qcow_file)

        if not os.path.exists(temp_qcow_file):
            raise Exception("create filie failed:{}".format(temp_qcow_file))

    def start(self):
        try:
            self.__nbd_rw_thread = nbdrwthread.NbdReadWriteThread()

            # 启动nbd
            _nbd_dev_name, _nbd_dev_number = self.create_nbd_device(self._backup_params)
            self.__key_info['vnc'] = "0.0.0.0:{}".format(_nbd_dev_number + 200)

            # 这里要打临时文件的快照。
            self.create_temp_qcow_file(self._backup_params['temp_qcow'])
            _blocks = [self._backup_params['temp_qcow'], _nbd_dev_name]

            # kvm命令行管理。
            self.__kvm_cmd_mgr = kvmcmdmgr.KvmCmdLineMgr(self.__key_info)

            # 应该是 2 块硬盘。
            for _file_path in _blocks:
                self.__kvm_cmd_mgr.add_block_dev('scsi-hd', _file_path)

            # 应该是 2 块网卡。
            self.__tap_nic = nettapmgr.NetTapMgr(self._backup_params['aio_server_ip'], r'fbtap', r'172.29.110')
            try:
                self.__tap_nic.start()
            except Exception as e:
                msg = "start tap failed: {}".format(e)
                _logger.error(msg)
                raise Exception(msg)

            self.__mac_address = self.__tap_nic.get_mac_address()
            self.__ip_addr = self.__tap_nic.get_ip_address()
            self.__tap_name = self.__tap_nic.get_tap_name()

            self.__kvm_cmd_mgr.add_net_dev(r'virtio-net-pci', self.__tap_name, None, self.__mac_address)

            # 获得 kvm 运行句柄。
            self.__kvm_running = kvmrunningmgr.KvmRunningThread(self.__kvm_cmd_mgr)

            self.__kvm_running.start()
        except Exception:
            self.kill()
            self.join()
            raise

    def get_ip_and_mac(self):
        return self.__ip_addr, self.__mac_address

    def join(self):
        _logger.info(r'KvmFileBackup start join')
        if self.__kvm_running:
            _logger.info(r'KvmFileBackup kvm running...')
            self.__kvm_running.join()
            self.__kvm_running = None
        if self.__nbd_rw_thread:
            _logger.info(r'KvmFileBackup __nbd_rw_thread...')
            self.__nbd_rw_thread.umount()
            self.__nbd_rw_thread.join()
            self.__nbd_rw_thread = None
        _logger.info(r'KvmFileBackup end join')

    def kill(self):
        _logger.info(r'KvmFileBackup start kill')
        if self.__kvm_running:
            self.__kvm_running.kill()
        _logger.info(r'KvmFileBackup end kill')

    def is_active(self):
        if self.__kvm_running:
            return self.__kvm_running.is_active()
        return False

    def nbd_alive(self):
        if self.__nbd_rw_thread and self.__nbd_rw_thread.is_alive():
            return True
        else:
            return False

    def kvm_alive(self):
        if self.__kvm_running and self.__kvm_running.is_active():
            return True
        else:
            return False


if __name__ == "__main__":
    nbd.init(100)

    backup_params = dict()
    backup_params['aio_server_ip'] = '172.29.16.2'
    backup_params['diskbytes'] = 1024 * 1024 * 1024 * 1024
    backup_params['disksnapshots'] = [
        {
            'path': '/home/mnt/nodes/9f792d48fb564b94aeabaf75f0155f8a/images/4a56657040fe4722a705b10306b29e3f/7ce6901129de4bada1202c0fc1515cc9.qcow',
            'ident': '01cb671e5a414f7c97b17eb3f09d3e59'}]
    backup_params['temp_qcow'] = r'/home/temp.qcow'
    backup_params['cores'] = 5
    backup_params['memory_mbytes'] = 1024

    _new_kvm = KvmFileBackup(backup_params)

    _new_kvm.start()

    _new_kvm.join()

    print("end!")

    pass
