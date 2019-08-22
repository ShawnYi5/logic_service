import kvmcmdmgr
import kvmrunningmgr
import nbd
import nettapmgr
import xlogging
from nbd import nbd_direct_images, nbd_wrapper

_logger = xlogging.getLogger(__name__)


class KvmServer(object):
    # 需要启动kvm，要2个网卡，期中一个网卡要指定mac地址，2个硬盘。
    # 参数:  aio_server_ip, diskbytes, disksnapshots
    def __init__(self, kvm_params):
        self.__kvm_running = None
        _key_info = dict()
        _key_info['logic'] = kvm_params['logic']
        _key_info['memory_mbytes'] = kvm_params['memory_mbytes']
        _key_info['vnc'] = kvm_params['vnc']

        # 启动nbd
        # self.create_nbd_device(kvm_params)

        # kvm命令行管理。
        self.__kvm_cmd_mgr = kvmcmdmgr.KvmCmdLineMgr(_key_info)

        for block_device in kvm_params['block_device']:
            self.__kvm_cmd_mgr.add_block_dev(block_device['type'], block_device['file'], block_device['disk_ident'])

        # 应该是 2 块网卡。
        self.__tap_nic = nettapmgr.NetTapMgr(kvm_params['aio_server_ip'], r'kvtap', r'172.29.120')
        try:
            self.__tap_nic.start()
        except Exception as e:
            str = "start tap failed: {}".format(e)
            _logger.error(str)
            raise Exception(str)

        self.__mac_address = self.__tap_nic.get_mac_address()
        self.__ip_addr = self.__tap_nic.get_ip_address()
        self.__tap_name = self.__tap_nic.get_tap_name()

        self.__kvm_cmd_mgr.add_net_dev('e1000', self.__tap_name, None, self.__mac_address)

        # 获得 kvm 运行句柄。
        self.__kvm_running = kvmrunningmgr.KvmRunningThread(self.__kvm_cmd_mgr)

    def _wait_all_nbd_read_ok(self):
        for data_nbd_object in self.data_nbd_objects:
            nbd_wrapper.wait_nbd_read_ok(data_nbd_object['nbd_object'])

    def get_block_device(self):
        return self.__kvm_cmd_mgr.get_block_device()

    @staticmethod
    def _nbd_object_by_data_device(data_device):
        device_profile = data_device['device_profile']
        nbdinfo = device_profile['nbd']
        return nbd.nbd_wrapper(
            nbd.nbd_wrapper_disable_lvm_allocator(
                nbd.nbd_wrapper_empty_allocator(nbdinfo['device_index'], nbdinfo['device_name'],
                                                nbdinfo['device_path'], nbdinfo['vnc_address'])
            )
        )

    def create_nbd_device(self, kvm_params):
        self.data_nbd_objects = list()
        for data_device in kvm_params['disk_devices']:
            nbd_object = self._nbd_object_by_data_device(data_device)
            self.data_nbd_objects.append({'nbd_object': nbd_object, 'data_device': data_device})

        data_index = 0
        for data_nbd_object in self.data_nbd_objects:
            data_index += 1
            name = r'nbd ({}) data disk {}'.format(data_nbd_object['nbd_object'].device_path, data_index)
            disk_snapshots = data_nbd_object['data_device']['disk_snapshots']
            data_nbd_thread = nbd_direct_images(name, data_nbd_object['nbd_object'], disk_snapshots)
            data_nbd_thread.start()

        self._wait_all_nbd_read_ok()

    def start(self):
        if self.__kvm_running:
            # 启动kvm.
            self.__kvm_running.start()

    def get_ip_and_mac(self):
        return self.__ip_addr, self.__mac_address

    def join(self):
        _logger.info(r'KvmFileBackup start join')
        if self.__kvm_running:
            _logger.info(r'KvmFileBackup kvm running...')
            self.__kvm_running.join()
            self.__kvm_running = None
        for data_nbd_object in self.data_nbd_objects:
            data_nbd_object['nbd_object'].unmount()
        for data_nbd_object in self.data_nbd_objects:
            data_nbd_object['nbd_object'].wait_no_mounting()
            data_nbd_object['nbd_object'].set_no_longer_used()
            data_nbd_object['nbd_object'] = None
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
        # TODO
        return True

    def kvm_alive(self):
        if self.__kvm_running and self.__kvm_running.is_active():
            return True
        else:
            return False


if __name__ == "__main__":
    kvm_params = dict()
    kvm_params['memory_mbytes'] = 1024
    kvm_params['block_device'] = list()
    block_device = {'type': 'scsi-cd', 'file': '/mnt/nodes/6198d5d02e5646af9091e8d77cead005/WinPE_amd64.iso'}
    kvm_params['block_device'].append(block_device)
    kvm_params['logic'] = 'windows'
    kvm_params['vnc'] = "0.0.0.0:200"
    kvm_params['aio_server_ip'] = '172.29.16.2'

    _new_kvm = KvmServer(kvm_params)
    _new_kvm.start()
    _new_kvm.join()

    print("end!")
