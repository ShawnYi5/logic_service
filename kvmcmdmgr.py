import copy
import os
import xlogging
import json
import uuid

PE_PATH_FILE = '/dev/shm/external_pe_file.json'

_logger = xlogging.getLogger(__name__)


class KvmCmdLineMgr(object):
    # key_info 要包含的信息及默认信息。
    # 1、下面是必须填的：
    # 'logic': linux/windows
    # 'vnc':'xxx',

    # 2、下面是可选，有默认信息的：
    # 'is_efi': False
    # 'memory_mbytes':1024
    # 'sockets' = 1
    # 'cores' = 4
    # 'cpu':'core2duo'
    # 'vga': 'std'

    # 3、下面是默认没有的：
    # 'rom_path'='
    # 'serial'
    # 'cpuid'
    # 'rom_path'
    # 'ext'
    # 'block_device':['type'='scsi-hd/scsi-cd',
    #                 'file'='xxxx'}] , 启动硬盘填写在第一个。
    #

    # 'net_device':[{'hardware_type'='virtio-net-pci/rtl8139/e1000',
    #               'mac_addr' = 可选
    #               'pci_addr' = 可选
    #               'ifname' = 'tap0'
    #               'tap_index' = 2  , 其中ifname和tap_index是2选一。填写一个。
    #              }]
    #

    def __init__(self, key_info):
        self._key_info = copy.copy(key_info)

    def get_memory_mbyte(self):
        return self._key_info.get('memory_mbytes', 1024)

    def add_block_dev(self, block_type, file, disk_ident=None):
        _new_block_dev = dict()
        _new_block_dev['type'] = block_type
        _new_block_dev['file'] = file
        if disk_ident is None:
            _new_block_dev['uuid'] = uuid.uuid4().hex
        else:
            _new_block_dev['uuid'] = disk_ident
        if 'block_device' not in self._key_info:
            self._key_info['block_device'] = list()
        self._key_info['block_device'].append(_new_block_dev)

    def get_block_device(self):
        return self._key_info['block_device']

    def add_net_dev(self, hardware_type, ifname, tap_index, mac_addr=None, pci_addr=None):
        _new_net_dev = dict()
        _new_net_dev['hardware_type'] = hardware_type
        if ifname:
            _new_net_dev['ifname'] = ifname
        if tap_index:
            _new_net_dev['tap_index'] = tap_index
        if ifname and tap_index:
            raise Exception("can not config ifname and tap_index")

        if mac_addr:
            _new_net_dev['mac_addr'] = mac_addr
        if pci_addr:
            _new_net_dev['pci_addr'] = pci_addr

        if 'net_device' not in self._key_info:
            self._key_info['net_device'] = list()

        self._key_info['net_device'].append(_new_net_dev)

    def generate_kvm_cmd_line(self):

        if self.is_aio_sys_vt_valid():
            _kvm_bios_path = r'/usr/share/seabios/bios-256k.bin'
            _kvm_efi_bios_path = r'/usr/share/efibios/OVMF.fd'
            _kvm_bios_original_path = r'/usr/share/seabios/bios-256k.original.bin'

            kvm_cmd = r'/usr/libexec/qemu-kvm'
            kvm_cmd += r" -enable-kvm"
            kvm_cmd += r" -smp sockets={sockets},cores={cores}".format(sockets=self._key_info.get('sockets', 1),
                                                                       cores=self._key_info.get('cores', 4))
            kvm_cmd += r' -usbdevice tablet'
        else:
            _kvm_bios_path = r'/sbin/aio/qemu-nokvm/bios-256k.bin'
            _kvm_efi_bios_path = r'/usr/share/efibios/OVMF.fd'
            _kvm_bios_original_path = r'/usr/share/seabios/bios-256k.original.bin'

            kvm_cmd = r'/sbin/aio/qemu-nokvm/qemu-system-x86_64'
            kvm_cmd += r" -smp sockets=1,cores=1"
            kvm_cmd += r' -usb -device usb-tablet'

        if self._key_info.get('kvm_uuid'):
            # format %08x-%04x-%04x-%04x-%012x
            kvm_cmd += r" -uuid {kvm_uuid}".format(kvm_uuid=self._key_info['kvm_uuid'])

        if 'kvm_name' in self._key_info:
            kvm_cmd += r' -name "{name}"'.format(name=self._key_info['kvm_name'])

        if self._key_info.get('is_efi', False):
            kvm_cmd += r' -bios "{}"'.format(_kvm_efi_bios_path)
        else:
            if self._key_info['logic'] == 'windows':
                kvm_cmd += r' -bios "{}"'.format(_kvm_bios_path)
            else:
                kvm_cmd += r' -bios "{}"'.format(_kvm_bios_original_path)

        kvm_cmd += r" -vnc {vnc}".format(vnc=self._key_info['vnc'])

        kvm_cmd += r"  -cpu {}".format(self._key_info.get('cpu', 'core2duo'))
        kvm_cmd += r"  -vga {}".format(self._key_info.get('vga', 'std'))
        kvm_cmd += r" -m {}M".format(self.get_memory_mbyte())
        kvm_cmd += r' -boot menu=on,splash-time={}'.format(self._get_splash_time_default(1000))
        kvm_cmd += r" -device virtio-scsi-pci,id=scsi0"

        if 'serial' in self._key_info:
            kvm_cmd += r' -serial {serial},server,nowait,nodelay'.format(serial=self._key_info['serial'])

        if self._key_info['logic'] == 'windows':
            kvm_cmd += r" -rtc base=localtime,clock=host,driftfix=none"
            if 'rom_path' in self._key_info:
                kvm_cmd += r" -rom-memory {rom_path}".format(rom_path=self._key_info['rom_path'])
        else:
            kvm_cmd += r" -rtc clock=host,driftfix=none"
            kvm_cmd += r" -no-clerwaredev"

        if 'cpuid' in self._key_info:
            kvm_cmd += r" -cpuid {cpuid}".format(cpuid=self._key_info['cpuid'])

        _index = 1
        _boot_index = 100
        _ide_index = 0
        for _one_block_device in self._key_info.get('block_device', []):
            if _ide_index > 3:
                xlogging.raise_system_error('IDE磁盘数大于4', 'too much ide', 1141)
            device_type = _one_block_device.get('type', 'scsi-hd')
            _file_path = _one_block_device['file']
            _uuid = _one_block_device['uuid']
            if device_type == 'ide-cd':
                kvm_cmd += (r" -drive file={file},if=none,id=drive-ide{index},media=cdrom"
                            r" -device ide-cd,bus=ide.{bus},unit={index},drive=drive-ide{index},id=ide{index},"
                            r"bootindex={bootindex}").format(bootindex=_boot_index,
                                                             file=_file_path,
                                                             index=_ide_index % 2,
                                                             bus=_ide_index // 2)
                _ide_index += 1
            elif device_type == 'ide-hd':
                kvm_cmd += (r" -drive file={file},if=none,id=drive-ide{index}"
                            r" -device ide-hd,bus=ide.{bus},unit={index},drive=drive-ide{index},id=ide{index},"
                            r"bootindex={bootindex}").format(bootindex=_boot_index,
                                                             file=_file_path,
                                                             index=_ide_index % 2,
                                                             bus=_ide_index // 2)
                _ide_index += 1
            elif device_type == 'virtio_blk':
                kvm_cmd += r" -drive file={file},if=none,id=drive-virtio-disk{index}{writethrough}" \
                           r" -device virtio-blk-pci,scsi=off,drive=drive-virtio-disk{index},serial={wwid}," \
                           r"bootindex={bootindex}" \
                    .format(file=_file_path, writethrough='', index=_index, wwid=_uuid, bootindex=_boot_index)
            elif device_type in ('scsi-cd', 'scsi-hd'):
                kvm_cmd += r" -drive file={file},if=none,id=drive-scsi0-0-{index}-0" \
                           r" -device {type},bus=scsi0.0,channel=0,scsi-id={index},lun=0,drive=drive-scsi0-0-{index}-0," \
                           r"bootindex={bootindex},serial={uuid}".format(file=_file_path, type=device_type,
                                                                         index=_index,
                                                                         bootindex=_boot_index, uuid=_uuid)
            else:
                _logger.warning('not support block {}'.format(_one_block_device))
                continue

            _index += 1
            _boot_index += 100

        # 添加tap
        _net_index = 0
        _pci_address = 18
        for _one_net_dev in self._key_info.get('net_device', []):
            _hardware_type = _one_net_dev.get('hardware_type', 'e1000')  # 默认用e1000网卡。'virtio-net-pci/rtl8139/e1000'
            _dev_cmd = r' -device {nic_type},netdev=net{net_index}'.format(nic_type=_hardware_type,
                                                                           net_index=_net_index)
            if 'mac_addr' in _one_net_dev:
                _dev_cmd += r',mac={mac}'.format(mac=_one_net_dev['mac_addr'])
            if 'pci_addr' in _one_net_dev:
                _dev_cmd += r',bus=pci.0,addr=0x{pci_addr:x},id=net{net_index}'.format(
                    net_index=_net_index, pci_addr=_one_net_dev['pci_addr'])

            if 'tap_index' in _one_net_dev:
                _net_cmd = r' -netdev type=tap,id=net{net_index}'.format(net_index=_net_index)
            else:
                _net_cmd = r' -netdev type=tap,id=net{net_index},script=no'.format(net_index=_net_index)

            if 'ifname' in _one_net_dev:
                _net_cmd += r',ifname={ifname}'.format(ifname=_one_net_dev['ifname'])
            if 'tap_index' in _one_net_dev:
                # fixme， 这部分代码没有调试过。应该是有问题的。
                _net_cmd += ',fd={tap_index} {tap_index}<>/dev/tap{tap_index}'. \
                    format(tap_index=_one_net_dev['tap_index'])
            _net_index += 1
            _pci_address += 1
            kvm_cmd += _dev_cmd
            kvm_cmd += _net_cmd

        kvm_cmd += self._key_info.get('ext', '')

        _logger.info('_generate_kvm_cmd_line return:{}'.format(kvm_cmd))
        return kvm_cmd

    @staticmethod
    def is_aio_sys_vt_valid():
        if os.path.isfile(r'/var/db/disable_vt'):
            return False
        return True

    @xlogging.convert_exception_to_value(None)
    def _get_splash_time_default(self, default_value):
        kvm_debug_cfg_file = '/dev/shm/kvm_serial'
        splash_time = default_value
        if os.path.isfile(kvm_debug_cfg_file):
            with open(kvm_debug_cfg_file, 'r') as fout:
                kvm_cfg = json.loads(fout.read())
                splash_time = int(kvm_cfg.get('splash_time')) * 1000
        if splash_time is None and os.path.isfile(PE_PATH_FILE):
            splash_time = 5 * 1000
        return splash_time


if __name__ == "__main__":
    pass
