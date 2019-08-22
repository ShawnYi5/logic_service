import os
import uuid

import nbd
import kvmcmdmgr
import kvmrunningmgr
import nbdrwthread
import nettapmgr
import qemuimgcmd
import xlogging

_logger = xlogging.getLogger(__name__)


def _remove_no_exception(path):
    try:
        os.remove(path)
    except:
        pass


class KvmDBBackup(object):
    """
    安装一个os
    """

    def __init__(self, host_params):
        self.__kvm_running = None
        self.__kvm_cmd_mgr = None
        self.__tap_nic = None
        self.__mac_address = None
        self.__ip_addr = None
        self.__tap_name = None
        self._nbds = list()
        self._nets = list()
        self._new_qcow_files = list()

        self._host_params = host_params
        self.__key_info = dict()
        self.__key_info[r'kvm_uuid'] = self._host_params.get('kvm_uuid')
        self.__key_info[r'logic'] = self._host_params['logic']
        self.__key_info['cores'] = self._host_params.get('cores', '1')
        self.__key_info['sockets'] = self._host_params.get('sockets', '4')
        self.__key_info['is_efi'] = self._host_params.get('is_efi', False)
        self.__key_info['memory_mbytes'] = self._host_params.get('memory_mbytes', 1024)
        self._ip_prefix = self._host_params.get('ip_prefix', '172.29.130')
        self._tap_name_prefix = self._host_params.get('tap_name_prefix', 'dbbackup')

    def create_nbd_device(self):
        if not self._host_params['disksnapshots']:
            xlogging.raise_system_error('参数错误, 无效的磁盘信息', 'no disk info', 3036)
        vnc_address = None
        for disk_info in self._host_params['disksnapshots']:
            _nbd_type = disk_info.get('nbd_type', 'nbdrw')
            nbd_object = nbdrwthread.NbdReadWriteThread()
            _nbd_dev_name, _nbd_dev_number = nbd_object.get_nbd_device_name()
            if _nbd_type == 'nbdrw':
                _cmd_nbd_umount = "/sbin/aio/nbdrw -d {}".format(_nbd_dev_name)
                _cmd_nbd_mount = "/sbin/aio/nbdrw -rw {} {}".format(_nbd_dev_name, disk_info['disk_bytes'])
            elif _nbd_type == 'gznbd':
                _cmd_nbd_umount = "/sbin/aio/gznbd -d {}".format(_nbd_dev_name)
                _cmd_nbd_mount = "/sbin/aio/gznbd -c {}".format(_nbd_dev_name)
            else:
                xlogging.raise_system_error('未知的nbd类型', 'not support nbd type : {}'.format(_nbd_type), 2055)
                return
            for _disk_snapshot in disk_info['images']:
                _cmd_nbd_mount += r' {} {}'.format(_disk_snapshot['path'], _disk_snapshot['ident'])
            nbd_object.setDaemon(True)
            nbd_object.set_scsi_id(disk_info.get('scsi_id', uuid.uuid4().hex))
            nbd_object.start_and_wait_ready(_cmd_nbd_mount, _cmd_nbd_umount)
            if vnc_address is None:
                if os.path.exists('/dev/shm/debug_vnc'):
                    vnc_address = '0.0.0.0:{}'.format(200 + _nbd_dev_number)
                else:
                    vnc_address = '127.0.0.1:{}'.format(200 + _nbd_dev_number)
            self._nbds.append(nbd_object)
        return vnc_address

    def _create_qcows(self):
        for qcow_file in self._host_params['qcow_files']:
            base_file = qcow_file.get('base')  # 不是必须
            disk_bytes = qcow_file.get('disk_bytes')  # 不是必须
            new_file = qcow_file['new']
            qcow_type = qcow_file['qcow_type']
            self._new_qcow_files.append(new_file)
            _remove_no_exception(new_file)
            if qcow_type == 'with_base':
                assert base_file
                rev = qemuimgcmd.QemuImgCmd().create_qcow2_file_base_old(base_file, new_file)
            elif qcow_type == 'empty':
                assert disk_bytes
                rev = qemuimgcmd.QemuImgCmd().create_qcow2_file_empty(new_file, disk_bytes)
            else:
                xlogging.raise_system_error('未知的qcow类型', 'not support qcow type : {}'.format(qcow_type), 2092)
                return
            if rev[0] != 0:
                xlogging.raise_system_error('创建虚拟磁盘失败', '_create_qcow failed, rev:{}'.format(rev), 2066)

    def start(self):
        try:
            # 启动nbd
            vnc_address = self.create_nbd_device()
            self._create_qcows()
            self.__key_info['vnc'] = vnc_address
            # kvm命令行管理。
            self.__kvm_cmd_mgr = kvmcmdmgr.KvmCmdLineMgr(self.__key_info)

            blks_disk = list()
            # 添加磁盘镜像
            for _qcow_file in self._new_qcow_files:
                blks_disk.append((self._host_params['disk_ctl_type'], _qcow_file))

            # 添加硬盘
            for _nbd in self._nbds:
                blks_disk.append((self._host_params['disk_ctl_type'], _nbd.device_path, _nbd.scsi_id))

            blk_isos = list()
            for _cdrom in self._host_params.get('cdroms', list()):
                blk_isos.append(('ide-cd', _cdrom['iso_path']))

            if self._host_params.get('boot_order', 'disk') == 'iso':
                blks = blk_isos + blks_disk
            else:
                blks = blks_disk + blk_isos

            for _blk in blks:
                self.__kvm_cmd_mgr.add_block_dev(*_blk)

            # 内部固定通信网卡
            self.__tap_nic = nettapmgr.NetTapMgr(self._host_params['aio_server_ip'], self._tap_name_prefix,
                                                 self._ip_prefix)
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

            # 其他额外网卡
            """
                {'mac': net['mac'],
                 'con_type': net['con_type'],
                 'phy_nic': net.get('phy_nic', 'bond0'),  # todo 界面需要设置 macvtap 链接的物理网卡名,
                 'net_card_type': kvm_info_ext_info['net_card_type']
                 }
            """
            addr = 18
            for net in self._host_params.get('nets', list()):
                if net['con_type'] == 'private':  # 私有
                    net_mgr = nettapmgr.NetTapMgr(self._host_params['aio_server_ip'], r'dbbackup', r'172.29.130',
                                                  net['mac'])
                    self._nets.append(net_mgr)
                    net_mgr.start()
                    self.__kvm_cmd_mgr.add_net_dev(net['net_card_type'], net_mgr.get_tap_name(), None,
                                                   net_mgr.get_mac_address())
                else:
                    net_mgr = nettapmgr.NetMacVTapMgr('dbmacvtap', net['phy_nic'], net['mac'])

                    self._nets.append(net_mgr)
                    net_mgr.start()
                    self.__kvm_cmd_mgr.add_net_dev(net['net_card_type'], None, net_mgr.get_ifindex(),
                                                   net_mgr.get_mac_address(), addr)
                    addr += 1

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
        _logger.info(r'KvmFileBackup __nbd_rw_thread...')
        while self._nbds:
            _nbd = self._nbds.pop()
            _nbd.umount()
            _nbd.join()
        if self.__tap_nic:
            self.__tap_nic.stop()
            self.__tap_nic = None
        while self._nets:
            _nets = self._nets.pop()
            _nets.stop()
        while self._new_qcow_files:
            _new_qcow_file = self._new_qcow_files.pop()
            _remove_no_exception(_new_qcow_file)
        _logger.info(r'KvmFileBackup end join {} {}'.format(self._nets, self.__tap_nic))

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
        for _nbd in self._nbds:
            if not _nbd.is_alive():
                break
        else:
            return True
        return False

    def kvm_alive(self):
        if self.__kvm_running and self.__kvm_running.is_active():
            return True
        else:
            return False


if __name__ == '__main__':
    import logging

    _logger.addHandler(logging.StreamHandler())
    nbd.init(100)

    backup_params = dict()
    backup_params['aio_server_ip'] = '172.29.16.2'
    backup_params['ip_prefix'] = '172.29.140'
    backup_params['disksnapshots'] = [
        {
            'images': [
                {
                    'path': '/home/mnt/nodes/b7f1e05d286d4aad933fd49ff8eeceb9/images/caafc820558645198cf01ef30a27c8cb/f39e736f6abf45ae9f8d8cc36bf2287b.qcow',
                    'ident': 'e26d469412ef464ea22fcc5f39a00dce'}
            ],
            'disk_bytes': 20 * 1024 ** 3,
            'nbd_type': 'gznbd'
        }
    ]
    backup_params['qcow_files'] = [
        {
            'base': '/tmp/tmp_qcow/mtest.qcow2',
            'new': '/tmp/tmp_qcow/tmp_mtest.qcow2'
        }
    ]
    backup_params['nets'] = [
        {'mac': 'cc:cc:1c:2c:3c:4c',
         'con_type': 'private',
         'phy_nic': '',
         'net_card_type': 'e1000'
         },
        {'mac': '00:cc:1c:2c:3c:7c',
         'con_type': 'bond',
         'phy_nic': 'bond0',
         'net_card_type': 'e1000'
         }
    ]
    backup_params['cdroms'] = []
    backup_params['disk_ctl_type'] = 'ide-hd'  # or virtio
    backup_params['cores'] = 4
    backup_params['sockets'] = 1
    backup_params['logic'] = 'linux'
    backup_params['memory_mbytes'] = 1024
    backup_params['boot_order'] = 'disk'
    backup_params['kvm_name'] = 'zbtest'
    backup_params['kvm_uuid'] = '85dd684b-1f03-4ae5-91a7-7d62e936a9cc'
    backup_params['is_efi'] = False

    _new_kvm = KvmDBBackup(backup_params)

    _new_kvm.start()

    _new_kvm.join()

    print("end!")

    pass
