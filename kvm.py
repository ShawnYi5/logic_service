import datetime
import hashlib
import json
import os
import shlex
import socket
import subprocess
import threading
import time
import traceback
import uuid

import psutil

import all_big_mm
import kvm_host
import loadIce
import xdefine
import xlogging
from VirtualHardwareMgr import CVirtualHarddiskMgr
from disk_read_ahead.disk_read_ahead import force_read_ESP_and_MSR_partition_range
from nbd import nbd_wrapper, nbd_direct_images, nbd_on_remote, nbd_wrapper_local_device_allocator
from net_common import get_info_from_syscmd

LDM_RAD_REPAIR_PATH = '/sbin/aio/ldm_rad_repair'

_logger = xlogging.getLogger(__name__)
_kvm_logger = xlogging.getLogger('kvm_r')

_disable_sys_in_kvm_file_path = os.path.join(loadIce.current_dir, 'disable_sys_in_kvm.json')
_dpsmbr_path = os.path.join(loadIce.current_dir, 'dpsmbr.bin')
_fixc_mbr_path = os.path.join(loadIce.current_dir, 'fixc_mbr.bin')
DRIVE_FILE = '/home/disable_sys_in_kvm/new_disable_sys_in_kvm.json'
PE_PATH_FILE = '/dev/shm/external_pe_file.json'
import Utils

ADD_DISABLE_DEVICE_HARD_ID_TO_ROM = 1

MEMORY_FOR_RESTORE_KVM = 3 * 1024

kvm_max_minutes_worker = None


class kvm_max_minutes(threading.Thread):
    locker = threading.RLock()
    kvm_session = list()

    def __int__(self):
        super(kvm_max_minutes, self).__init__()

    def run(self):
        while True:
            if os.path.exists(r'/dev/shm/not_kill_kvm'):
                _logger.warn(r'have "/dev/shm/not_kill_kvm", NOT check kvm run time')
            else:
                kill_kvm = self.fetch_kill()
                if kill_kvm:
                    for kvm_obj in kill_kvm:
                        self.kill_kvm_object(kvm_obj)
                    kill_kvm.clear()
            time.sleep(180)

    @staticmethod
    @xlogging.convert_exception_to_value(None)
    def kill_kvm_object(kvm_obj):
        _logger.info('kill kvm_object. kvm_pid:{} pe_ident:{}'.format(kvm_obj.kvm_pid, kvm_obj.peHostIdent))
        kvm_obj.close_kvm((r'为目标客户端配置硬件信息失败', 'kill kvm minutes {}'.format(kvm_obj.max_kvm_minutes)))

    @xlogging.convert_exception_to_value(None)
    def fetch_kill(self):
        result = list()
        with self.locker:
            for kvm_obj in self.kvm_session:
                if kvm_obj.kill_datetime < datetime.datetime.now():
                    result.append(kvm_obj)

            for r in result:
                self.kvm_session.remove(r)

        return result

    def insert(self, kvm_object):
        _logger.info(
            'insert kvm_object. pe_ident:{} kill_datetime:{}'.format(kvm_object.peHostIdent, kvm_object.kill_datetime))
        with self.locker:
            self.kvm_session.append(kvm_object)

    @xlogging.convert_exception_to_value(None)
    def remove(self, kvm_object):
        _logger.info('remove kvm_object. kvm_pid:{} pe_ident:{}'.format(kvm_object.kvm_pid, kvm_object.peHostIdent))
        with self.locker:
            if kvm_object in self.kvm_session:
                self.kvm_session.remove(kvm_object)


class nbd_thread(threading.Thread):
    def __init__(self, pe_host_ident, disk_token, disk_bytes, kvm_wrapper_object, nbd_object, debug_name):
        super(nbd_thread, self).__init__()
        self.pe_host_ident = pe_host_ident
        self.disk_token = disk_token
        self.disk_bytes = disk_bytes
        self.kvm_wrapper_object = kvm_wrapper_object
        self.nbd_object = nbd_object
        self.name = debug_name

    def start(self):
        self.nbd_object.is_thread_alive = True
        try:
            super(nbd_thread, self).start()
        except Exception as e:
            _logger.error(r'!!!~~!!! start thread failed {}'.format(e), exc_info=True)
            self.nbd_object.is_thread_alive = False
            raise

    def run(self):
        try:
            self.nbd_object.mount_with_box_service(self.pe_host_ident, self.disk_token, self.disk_bytes)
        finally:
            self.nbd_object.is_thread_alive = False
            if self.kvm_wrapper_object:
                self.kvm_wrapper_object.close_kvm((r'磁盘快照读取错误', r'nbd_thread failed {}'.format(self.name)))
                self.kvm_wrapper_object = None
            self.nbd_object = None


class KvmBase(object):
    def __init__(self):
        self.is_aio_sys_vt_valid = self._is_aio_sys_vt_valid()
        if self.is_aio_sys_vt_valid:
            self.kvm_exec_path = r'/usr/libexec/qemu-kvm'
            self.kvm_efi_bios_path = r'/usr/share/efibios/OVMF.fd'
            self.kvm_bios_path = r'/usr/share/seabios/bios-256k.bin'
            self.kvm_bios_original_path = r'/usr/share/seabios/bios-256k.original.bin'
        else:
            self.kvm_exec_path = r'/sbin/aio/qemu-nokvm/qemu-system-x86_64'
            self.kvm_efi_bios_path = r'/usr/share/efibios/OVMF.fd'
            self.kvm_bios_path = r'/sbin/aio/qemu-nokvm/bios-256k.bin'
            self.kvm_bios_original_path = r'/usr/share/seabios/bios-256k.original.bin'

    def _generate_cmd(self, params):
        kvm_cmd = self.kvm_exec_path
        kvm_cmd += r" -device virtio-scsi-pci,id=scsi0"

        splash_time = self._get_splash_time()
        if splash_time:
            kvm_cmd += r' -boot menu=on,splash-time={}'.format(splash_time)
        else:
            kvm_cmd += r' -boot menu=off'

        if params['logic'] == 'windows':
            kvm_cmd += r" -rtc base=localtime,clock=host,driftfix=none"
        else:
            kvm_cmd += r" -rtc clock=host,driftfix=none"
            kvm_cmd += r" -no-clerwaredev"

        if self.is_aio_sys_vt_valid:
            kvm_cmd += r" -enable-kvm"
            kvm_cmd += r" -smp sockets=1,cores=4"
            kvm_cmd += r' -usbdevice tablet'
        else:
            kvm_cmd += r" -smp sockets=1,cores=1"
            kvm_cmd += r' -usb -device usb-tablet'

        if params['is_efi']:
            kvm_cmd += r' -bios "{}"'.format(self.kvm_efi_bios_path)
        else:
            if params['logic'] == 'windows':
                kvm_cmd += r' -bios "{}"'.format(self.kvm_bios_path)
            else:
                kvm_cmd += r' -bios "{}"'.format(self.kvm_bios_original_path)

        _logger.info('_generate_kvm_cmd return:{}'.format(kvm_cmd))

        return kvm_cmd

    @staticmethod
    def _is_aio_sys_vt_valid():
        if os.path.isfile(r'/var/db/disable_vt'):
            return False
        return True

    @xlogging.convert_exception_to_value(None)
    def _get_splash_time(self):
        kvm_debug_cfg_file = '/dev/shm/kvm_serial'
        splash_time = None
        if os.path.isfile(kvm_debug_cfg_file):
            with open(kvm_debug_cfg_file, 'r') as fout:
                kvm_cfg = json.loads(fout.read())
                splash_time = int(kvm_cfg.get('splash_time')) * 1000
        if splash_time is None and os.path.isfile(PE_PATH_FILE):
            splash_time = 5 * 1000
        return splash_time


class kvm_wrapper(KvmBase):
    def __init__(self, max_kvm_minutes, boot_nbd_object, peHostIdent, diskToken, diskBytes, devices, cpuId, isoPath,
                 rom_path, floppy_path, data_nbd_objects, is_efi, vbus_bin_path, start_kvm_flag_file, htb_disk_path,
                 takeover_params, remote_nbd_config_path, remote_kvm_host_object):
        self.max_kvm_minutes = max_kvm_minutes
        self.boot_nbd_object = boot_nbd_object
        self.peHostIdent = peHostIdent
        self.diskToken = diskToken
        self.diskBytes = diskBytes
        self.devices = devices
        self.cpuId = cpuId
        self.isoPath = isoPath
        self.running = False
        self.kvm_pid = None
        self.rom_path = rom_path
        self.floppy_path = self.local_floppy_path = floppy_path
        self.data_nbd_objects = data_nbd_objects
        self.is_efi = is_efi
        self.some_error = None
        self.kill_datetime = None
        self.vbus_bin_path = vbus_bin_path
        self.start_kvm_flag_file = start_kvm_flag_file
        self.htb_disk_path = htb_disk_path
        self.takeover_params = takeover_params
        self.remote_nbd_config_path = remote_nbd_config_path
        self.remote_kvm_host_object = remote_kvm_host_object
        super(kvm_wrapper, self).__init__()

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

    @staticmethod
    def push_base_files(remote_kvm_host_object, base_files):
        remote_kvm_host_object.push_file(base_files, 'base_files')
        remote_file_path = os.path.join(remote_kvm_host_object.host_dir, 'base_files')
        tar_cmd = 'tar -xzvf {} -C {}'.format(remote_file_path, remote_kvm_host_object.host_dir)
        kvm_host.kvm_host_exec_helper(remote_kvm_host_object, tar_cmd, 'tar', _logger)
        init_sh_path = os.path.join(remote_kvm_host_object.host_dir, 'init.sh')
        kvm_host.kvm_host_exec_helper(remote_kvm_host_object, init_sh_path, 'init_sh', _logger)

    @staticmethod
    def create_remote_nbd_config(local_ip):
        nbd_config_path = r'/dev/shm/{}.nbd_config'.format(uuid.uuid4().hex)
        with open(nbd_config_path, 'w') as f:
            f.write('Ice.Default.Host = {}\r\n'.format(local_ip))
            f.write('BoxApi.Proxy = apis:tcp -p 20000 -t 20000\r\n')
            f.flush()
        return nbd_config_path

    def _create_floppy_file(self):
        flag_string = r'hhekaxxm9idsvW5PdutqgPthyuwuqwq6w5yjfbt9zgTbCtkvebrrknmpzspqhuC2'
        raw_content = [ord(letter) for letter in flag_string]

        with open(self.floppy_path, 'wb') as file_object:
            file_bytes = 1024 * 1024 * 2  # 2MB
            file_object.truncate(file_bytes + 4096)
            file_object.seek(file_bytes - 512)  # 2096640 bytes， 4095 sector
            file_object.write(bytearray(raw_content))

    def _push_file(self, local_path, remote_file_name):
        self.remote_kvm_host_object.push_file(local_path, remote_file_name)
        os.remove(local_path)
        return os.path.join(self.remote_kvm_host_object.host_dir, remote_file_name)

    @staticmethod
    def _wait_all_nbd_read_ok(boot_nbd_object, data_nbd_objects):
        nbd_wrapper.wait_nbd_read_ok(boot_nbd_object)
        for data_nbd_object in data_nbd_objects:
            nbd_wrapper.wait_nbd_read_ok(data_nbd_object['nbd_object'])

    def _wait_all_remote_nbd_read_ok(self):
        nbd_on_remote.wait_nbd_on_remote_read_ok(self.boot_nbd_object)
        for data_nbd_object in self.data_nbd_objects:
            nbd_on_remote.wait_nbd_on_remote_read_ok(data_nbd_object['nbd_object'])

    def _is_stop_kvm(self, start_kvm_flag_file):
        while True:
            if not os.path.exists(start_kvm_flag_file):
                self.close_kvm((r'用户取消任务', 'user cancel task, pe={}'.format(self.peHostIdent)))
                break
            time.sleep(10)

    def _clean_remote_dir(self, kvm_flag):
        if (kvm_flag & 1) == 1:
            _logger.warning(r'do NOT clean dir : {}'.format(self.remote_kvm_host_object.name))
            return
        rm_cmd = r'rm -rf "{}"'.format(self.remote_kvm_host_object.host_dir)
        kvm_host.kvm_host_exec_helper(self.remote_kvm_host_object, rm_cmd, 'clean', _logger)

    @xlogging.convert_exception_to_value(None)
    def remove_start_kvm_flag_file(self):
        if os.path.exists(self.start_kvm_flag_file):
            os.remove(self.start_kvm_flag_file)

    def run(self, kvm_flag):
        self._fix_nbd_before()  # 不适用于接管，仅适用于还原逻辑
        self._run_kvm(kvm_flag)
        self._fix_nbd_after()  # 不适用于接管，仅适用于还原逻辑

    def _run_kvm(self, kvm_flag):
        if self.takeover_params:
            return self.run_for_takeover()
        elif self.remote_nbd_config_path:
            return self.run_on_other_host_logic(kvm_flag)
        return self.run_for_restore()

    def run_on_other_host_logic(self, kvm_flag):
        try:
            self.running = True

            self._create_floppy_file()

            self.floppy_path = self._push_file(self.floppy_path, 'floppy_file')
            self.isoPath = self._push_file(self.isoPath, 'iso_file')
            self.rom_path = self._push_file(self.rom_path, 'rom_file')
            self._push_file(self.remote_nbd_config_path, 'gznbd.config')
            if self.vbus_bin_path:
                vbus_bin_file_name = os.path.basename(self.vbus_bin_path)
                self._push_file(self.vbus_bin_path, vbus_bin_file_name)

            self.kvm_exec_path = os.path.join(self.remote_kvm_host_object.host_dir, 'qemu-kvm')
            self.kvm_efi_bios_path = os.path.join(self.remote_kvm_host_object.host_dir, 'OVMF.fd')
            self.kvm_bios_path = os.path.join(self.remote_kvm_host_object.host_dir, 'bios-256k.bin')

            self.start_nbd_thread(self, self.boot_nbd_object, self.data_nbd_objects)

            kvm_cmd, disk_index = self._generate_restore_kvm_cmd()

            self.kill_datetime = datetime.datetime.now() + datetime.timedelta(minutes=self.max_kvm_minutes)
            kvm_max_minutes_worker.insert(self)  # add to kvm session

            # 检查文件start_kvm_flag_file，不存在则关闭KVM
            threading.Thread(target=self._is_stop_kvm, args=(self.start_kvm_flag_file,), daemon=True).start()

            cmd_runner = self.remote_kvm_host_object.Popen(kvm_cmd, kvm_host.get_logger_file_name('kvm'))
            self.kvm_pid = cmd_runner.pid
            _logger.info("start qemu-kvm pid:{} on {} | {} ".format(
                self.kvm_pid, self.remote_kvm_host_object.name, kvm_cmd))
            return_code = cmd_runner.returncode
            _logger.info("qemu-kvm quit {} pid:{} on {}".format(
                self.kvm_pid, self.remote_kvm_host_object.name, return_code))

            self.remote_kvm_host_object.pull_file('floppy_file', self.local_floppy_path)
        except Exception as e:
            tb = traceback.format_exc()
            _logger.error(r'run_on_other_host_logic failed . {} - {}'.format(e, tb))
        finally:
            kvm_max_minutes_worker.remove(self)
            self.running = False
            self.boot_nbd_object.unmount()
            for data_nbd_object in self.data_nbd_objects:
                data_nbd_object['nbd_object'].unmount()
            self.boot_nbd_object.wait_no_mounting()
            self.boot_nbd_object.set_no_longer_used()
            self.boot_nbd_object = None
            for data_nbd_object in self.data_nbd_objects:
                data_nbd_object['nbd_object'].wait_no_mounting()
                data_nbd_object['nbd_object'].set_no_longer_used()
                data_nbd_object['nbd_object'] = None
            self.remove_start_kvm_flag_file()
            self._clean_remote_dir(kvm_flag)

    def _fix_nbd_before(self):
        _logger.info('_fix_nbd_before start')
        if self.takeover_params:
            _logger.info('_fix_nbd_before in takeover skip')
            return
        boot_nbd_object = nbd_wrapper(nbd_wrapper_local_device_allocator())
        data_nbd_objects = list()
        for data_info in self.data_nbd_objects:
            data_nbd_objects.append({
                'nbd_object': nbd_wrapper(nbd_wrapper_local_device_allocator()),
                'data_device': data_info['data_device']
            })
        try:
            self.start_nbd_thread(None, boot_nbd_object, data_nbd_objects)
            self._wait_all_nbd_read_ok(boot_nbd_object, data_nbd_objects)

            self.kill_mbr_virus(boot_nbd_object.device_path)

            if not self.read_clw_boot_redirct_gpt_disk(data_nbd_objects):
                self.read_clw_boot_redirct_mbr_disk(data_nbd_objects, boot_nbd_object)
        finally:
            boot_nbd_object.unmount()
            for data_nbd_object in data_nbd_objects:
                data_nbd_object['nbd_object'].unmount()
        _logger.info('_fix_nbd_before end')

    def _fix_nbd_after(self):
        _logger.info('_fix_nbd_after start')
        if self.takeover_params:
            _logger.info('_fix_nbd_after in takeover skip')
            return
        boot_nbd_object = nbd_wrapper(nbd_wrapper_local_device_allocator())
        try:
            self.start_nbd_thread(None, boot_nbd_object, list())
            self._wait_all_nbd_read_ok(boot_nbd_object, list())

            _logger.info('_fix_nbd_after begin read mini partition {}'.format(boot_nbd_object.device_path))
            force_read_ESP_and_MSR_partition_range(boot_nbd_object.device_path)
            _logger.info('_fix_nbd_after read mini partition over {}'.format(boot_nbd_object.device_path))

            floppy_path = self.local_floppy_path if self.remote_nbd_config_path else self.floppy_path
            _logger.info('_fix_nbd_after begin _fix_chs {}'.format(boot_nbd_object.device_path))
            self._fix_chs(boot_nbd_object.device_path, floppy_path)
            _logger.info('_fix_nbd_after end  _fix_chs {}'.format(boot_nbd_object.device_path))
        finally:
            boot_nbd_object.unmount()
        _logger.info('_fix_nbd_after end')

    @staticmethod
    @xlogging.convert_exception_to_value(None)
    def kill_mbr_virus(boot_device_path, normal_mbr_path='/sbin/aio/logic_service/2008.mbr.bin'):
        with open(boot_device_path, 'r+b') as wp:
            _old_mbr = wp.read(512)

            virus = b'\xFA\x33\xC0\x8E\xD0\xBC\x00\x7C\x8B\xF4\x50\x07\x0E\x1F\xFB\x26' \
                    b'\x8B\x2E\x13\x04\x4D\x4D\x26\x89\x2E\x13\x04\xB1\x06\xD3\xE5\x8E'

            virus_len = len(virus)

            for i in range(0, 0 + virus_len):
                if virus[i - virus_len] != _old_mbr[i]:
                    return

            _logger.warn(r'kill_mbr_virus find virus {}'.format(boot_device_path))

            with open(normal_mbr_path, 'rb') as rp:
                _new_mbr = bytearray(rp.read())

            for i in range(0x1b8, 0x200):
                _new_mbr[i] = _old_mbr[i]

            wp.seek(0)
            wp.write(_new_mbr)

    def run_for_restore(self):
        try:
            self.running = True

            self._create_floppy_file()

            self.start_nbd_thread(self, self.boot_nbd_object, self.data_nbd_objects)

            self._wait_all_nbd_read_ok(self.boot_nbd_object, self.data_nbd_objects)

            kvm_cmd, disk_index = self._generate_restore_kvm_cmd()
            get_info_from_syscmd(LDM_RAD_REPAIR_PATH + ' -clearlog ' + self.boot_nbd_object.device_path)
            for data_nbd_object in self.data_nbd_objects:
                get_info_from_syscmd(LDM_RAD_REPAIR_PATH + ' -clearlog ' + data_nbd_object['nbd_object'].device_path)
            alloc_success = False
            while not alloc_success:
                alloc_success = all_big_mm.CAllocBigMM.try_alloc(all_big_mm.RESTORE_KVM_MEMORY_MB)
                if not alloc_success:
                    _logger.warning(r'alloc mem for kvm failed,will retry')
                    for i in range(30):
                        time.sleep(1)
                        if not os.path.exists(self.start_kvm_flag_file):
                            self.some_error = (r'用户取消任务', 'user cancel task, pe={}'.format(self.peHostIdent))
                            xlogging.raise_system_error(self.some_error[0], self.some_error[1], 0)

            self.kill_datetime = datetime.datetime.now() + datetime.timedelta(minutes=self.max_kvm_minutes)
            kvm_max_minutes_worker.insert(self)  # add to kvm session

            # 检查文件start_kvm_flag_file，不存在则关闭KVM
            threading.Thread(target=self._is_stop_kvm, args=(self.start_kvm_flag_file,), daemon=True).start()
            if self.is_aio_sys_vt_valid:
                cwd = None
            else:
                cwd = r'/sbin/aio/qemu-nokvm'
            if os.path.isfile(PE_PATH_FILE):
                with open(PE_PATH_FILE, 'r') as f:
                    result = json.loads(f.read())
                pe_path = result['pe_path']
                _logger.info('pe_path is :{}'.format(pe_path))
                number = disk_index + 1
                kvm_cmd += r" -drive file={pe_path},if=none,id=drive-scsi0-0-{index}-0".format(pe_path=pe_path,
                                                                                               index=number)
                kvm_cmd += r" -device scsi-cd,bus=scsi0.0,channel=0,scsi-id={index},lun=0,drive=drive-scsi0-0-{index}-0,bootindex=0".format(
                    index=number)

            split_kvm_cmd = shlex.split(kvm_cmd)

            with subprocess.Popen(split_kvm_cmd, cwd=cwd, stderr=subprocess.PIPE, universal_newlines=True) as p:
                self.kvm_pid = p.pid
                _logger.info("start qemu-kvm pid:{} {} ".format(p.pid, kvm_cmd))
                for line in p.stderr:
                    _kvm_logger.debug('{}:{}'.format(p.pid, line.rstrip()))
            _logger.info("qemu-kvm quit {} {}".format(self.kvm_pid, p.returncode))

            # kvm结束，检测是否有异常
            if self.some_error is not None:
                xlogging.raise_system_error(self.some_error[0], self.some_error[1], 0)

            os.system(r'\cp -f "{}" {}'.format(self.floppy_path, '/tmp/restore_floppy'))
        except Exception as e:
            tb = traceback.format_exc()
            _logger.error(r'kvm run failed . {} - {}'.format(e, tb))
            raise e
        finally:
            kvm_max_minutes_worker.remove(self)
            self.running = False
            self.boot_nbd_object.unmount()
            for data_nbd_object in self.data_nbd_objects:
                data_nbd_object['nbd_object'].unmount()
            self.boot_nbd_object.wait_no_mounting()
            self.boot_nbd_object.set_no_longer_used()
            self.boot_nbd_object = None
            for data_nbd_object in self.data_nbd_objects:
                data_nbd_object['nbd_object'].wait_no_mounting()
                data_nbd_object['nbd_object'].set_no_longer_used()
                data_nbd_object['nbd_object'] = None
            self.remove_start_kvm_flag_file()

    @staticmethod
    def read_clw_boot_redirct_gpt_disk(data_nbd_objects):
        for data_nbd_object in data_nbd_objects:
            if data_nbd_object['data_device']['normal_snapshot_ident'] == xdefine.CLW_BOOT_REDIRECT_GPT_UUID:
                break
        else:
            return False
        _logger.info('_read_clw_boot_redirct_gpt_disk find clwbootdisk data_nbd_object:{}'.format(data_nbd_object, ))
        with open('/sbin/aio/logic_service/clwbdisk_win_gpt.bin', 'rb') as fsrc:
            with open(data_nbd_object['nbd_object'].device_path, 'rb+') as fdst:
                buf = xlogging.DataHolder()
                while buf.set(fsrc.read(64 * 1024)):
                    if not all(v == 0 for v in buf.get()):
                        fdst.write(buf.get())
                    else:
                        fdst.seek(len(buf.get()), os.SEEK_CUR)
        return True

    @staticmethod
    def read_clw_boot_redirct_mbr_disk(data_nbd_objects, boot_nbd_object):
        for data_nbd_object in data_nbd_objects:
            if data_nbd_object['data_device']['normal_snapshot_ident'] == xdefine.CLW_BOOT_REDIRECT_MBR_UUID:
                break
        else:
            return
        _logger.info('read_clw_boot_redirct_mbr_disk find clwbootdisk data_nbd_object:{}'.format(data_nbd_object, ))
        with open(boot_nbd_object.device_path, 'rb') as f:
            content = f.read(512)

        with open('/sbin/aio/logic_service/clwbdisk.bin', 'rb') as f:
            boot_content = f.read()

        with open(data_nbd_object['nbd_object'].device_path, 'rb+') as f:
            f.seek(0)
            f.write(boot_content)
            f.seek(512)
            f.write(content)

    def start_nbd_thread(self, kvm_wrapper_object, boot_nbd_object, data_nbd_objects):
        boot_nbd_thread = nbd_thread(self.peHostIdent, self.diskToken, self.diskBytes, kvm_wrapper_object,
                                     boot_nbd_object,
                                     r'nbd ({}) boot disk'.format(boot_nbd_object.device_path))
        boot_nbd_thread.start()
        data_index = 0
        for data_nbd_object in data_nbd_objects:
            data_index += 1
            data_device = data_nbd_object['data_device']
            data_nbd_thread = nbd_thread(
                self.peHostIdent, data_device['token'], data_device['disk_bytes'], kvm_wrapper_object,
                data_nbd_object['nbd_object'],
                r'nbd ({}) data disk {}'.format(data_nbd_object['nbd_object'].device_path, data_index))
            data_nbd_thread.start()

    def _generate_restore_kvm_cmd(self):
        # -drive file=./o.qcow,if=none,id=drive-scsi0-0-%target%-0
        # -device scsi-hd,bus=scsi0.0,channel=0,scsi-id=%target%,lun=0,drive=drive-scsi0-0-%target%-0,bootindex=100
        kvm_cmd = r'"{kvm_exec_path}"' \
                  r" -cpu core2duo" \
                  r" -rtc base=localtime,clock=host,driftfix=none" \
                  r" -device virtio-scsi-pci,id=scsi0" \
                  r" -drive file={cdrom},if=none,id=drive-scsi0-0-0-0" \
                  r" -device scsi-cd,bus=scsi0.0,channel=0,scsi-id=0,lun=0,drive=drive-scsi0-0-0-0" \
                  r" -m 3072M" \
                  r" -cpuid {cpuid}" \
                  r" -vnc {vnc}" \
                  r" -rom-memory {rom_path}" \
                  r" -drive file={file},if=none,id=drive-scsi0-0-1-0" \
                  r" -device scsi-hd,bus=scsi0.0,channel=0,scsi-id=1,lun=0,drive=drive-scsi0-0-1-0,bootindex=100" \
            .format(file=self.boot_nbd_object.device_path, vnc=self.boot_nbd_object.vnc_address, cpuid=self.cpuId,
                    cdrom=self.isoPath, rom_path=self.rom_path, kvm_exec_path=self.kvm_exec_path)
        splash_time = self._get_splash_time()
        if splash_time:
            kvm_cmd += r' -boot menu=on,splash-time={}'.format(splash_time)
        else:
            kvm_cmd += r' -boot menu=off'
        if self.is_aio_sys_vt_valid:
            kvm_cmd += r" -enable-kvm"
            kvm_cmd += r" -smp sockets=1,cores=4"
            kvm_cmd += r' -usbdevice tablet'
        else:
            kvm_cmd += r" -smp sockets=1,cores=1"
            kvm_cmd += r' -usb -device usb-tablet'

        if self.is_efi:
            kvm_cmd += r' -bios "{}"'.format(self.kvm_efi_bios_path)
        else:
            kvm_cmd += r' -bios "{}"'.format(self.kvm_bios_path)

        if self.boot_nbd_object.serial_port:
            kvm_cmd += r' -serial {},server,nowait,nodelay'.format(self.boot_nbd_object.serial_port)

        device_count = 0
        for device in self.devices:
            if ',class_id=1537,' in device:
                _logger.warning(r'ignore device {}. because ",class_id=1537,"  CC0601'.format(device))
                continue
            kvm_cmd += ' -device '
            kvm_cmd += device
            device_count += 1

        if device_count > 27:
            xlogging.raise_system_error(
                r'内部错误，模拟目标机硬件信息失败', 'virtual pci device too much, max:{} current:{}'.format(27, device_count), 3131)

        disk_index = 1
        for data_nbd_object in self.data_nbd_objects:
            disk_index += 1
            cmd_data_disk = \
                r" -drive file={file},if=none,id=drive-scsi0-0-{index}-0" \
                r" -device scsi-hd,bus=scsi0.0,channel=0,scsi-id={index},lun=0,drive=drive-scsi0-0-{index}-0" \
                r"".format(file=data_nbd_object['nbd_object'].device_path, index=disk_index)
            kvm_cmd += cmd_data_disk
        disk_index += 1
        cmd_floppy_disk = \
            r" -drive file={floppy_path},if=none,id=drive-scsi0-0-{index}-0" \
            r" -device scsi-hd,bus=scsi0.0,channel=0,scsi-id={index},lun=0,drive=drive-scsi0-0-{index}-0" \
            r"".format(floppy_path=self.floppy_path, index=disk_index)
        kvm_cmd += cmd_floppy_disk

        if self.vbus_bin_path is not None:
            if self.remote_nbd_config_path:
                vbus_bin_file_name = os.path.basename(self.vbus_bin_path)
                remote_vbus_bin_path = os.path.join(self.remote_kvm_host_object.host_dir, vbus_bin_file_name)
                kvm_cmd += r' -device pci-vdev,subdev_hwid={}'.format(remote_vbus_bin_path)
            else:
                kvm_cmd += r' -device pci-vdev,subdev_hwid={}'.format(self.vbus_bin_path)
        return kvm_cmd, disk_index

    def _send_vnc_cmd(self, server_address, cmd):
        rev = None
        _logger.info('_send_vnc_cmd cmd={},server_address={}'.format(cmd, server_address))
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(server_address)
            sock.sendall(cmd.encode('utf8'))
            time.sleep(1)
            rev = sock.recv(1024).decode('utf8')
            _logger.info('_send_vnc_cmd rev={}'.format(rev))
        except Exception as e:
            _logger.error('_send_vnc_cmd Failed.cmd={}'.format(cmd))
            self._save_kvm_run_info('debug', str(e))
        finally:
            sock.close()
        return rev

    def _FmtMAC(self, mac):
        mac = mac.replace(' ', '').replace('-', '').replace(':', '').upper()
        if len(mac) == 12:
            mac = '{}:{}:{}:{}:{}:{}'.format(mac[0:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:])
        return mac

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

    @xlogging.convert_exception_to_value(None)
    def _fix_chs(self, boot_device_path, floppy_path):
        with open(floppy_path, 'rb') as fp:
            fp.seek(1024 * 1024 * 2)
            system_info = fp.read(4096).decode().strip('\0')
            if len(system_info) == 0:
                return
            _logger.info(r'_fix_chs system_info : {}'.format(system_info))
            if int(json.loads(system_info)['windows_version']['major']) >= 6:
                return

        with open(_dpsmbr_path, 'rb') as dp:
            _dpsmbr_data = bytearray(dp.read())

        with open(_fixc_mbr_path, 'rb') as fmp:
            _fixc_mbr_data = fmp.read().ljust(512, b'\0')

        with open(boot_device_path, 'r+b') as bd:
            _old_mbr = bd.read(512)
            mbr_cache_sector_index = 1
            empty_sectors = max([8, 1 + (len(_fixc_mbr_data) // 512)])
            while mbr_cache_sector_index < 1024 * 1024 * 1024:
                bd.seek(mbr_cache_sector_index * 512)
                all_empty, empty_offset = self._get_empty_offset(bd.read(empty_sectors * 512), empty_sectors)
                if all_empty:
                    break
                else:
                    mbr_cache_sector_index += empty_offset
            else:
                xlogging.raise_system_error(
                    r'修正CHS失败，未搜索到足够的空闲区域', '_fix_chs can NOT find mbr_cache_sector_index', 0)

            _logger.info(r'_fix_chs {} mbr_cache_sector_index {}'.format(boot_device_path, mbr_cache_sector_index))

            bd.seek(mbr_cache_sector_index * 512)
            bd.write(_old_mbr)
            bd.write(_fixc_mbr_data)

            lba_bytes = mbr_cache_sector_index.to_bytes(4, 'little')
            for i in range(0, 4):
                _dpsmbr_data[0x24 + i] = lba_bytes[i]
            for i in range(0x1b8, 0x200):
                _dpsmbr_data[i] = _old_mbr[i]
            bd.seek(0)
            bd.write(_dpsmbr_data)

    def _get_empty_offset(self, data, sectors):
        for i in range(sectors - 1, -1, -1):
            if not self._is_empty_sector(data[i * 512:(i + 1) * 512]):
                return False, i + 1
        else:
            return True, None

    @staticmethod
    def _is_empty_sector(data):
        assert len(data) == 512
        for byte in data:
            if byte is not 0:
                return False
        else:
            return True

    def _is_cancel_kvm(self):
        if not os.path.exists(self.start_kvm_flag_file):
            raise xlogging.raise_system_error('用户取消任务', 'start_kvm_flag_file not exists', 1)

    def run_for_takeover(self):
        isException = False
        isCreateQcow2 = False
        kvm_adpter = self.takeover_params['kvm_adpter']
        device_path_list = list()
        monitors_addr = r'{}_m'.format(self.start_kvm_flag_file)
        try:
            self.running = True
            self._is_cancel_kvm()
            memory_size_MB = int(self.takeover_params['memory_size_MB'])
            disk_snapshots = self.takeover_params['disk_snapshots']
            kvm_pwd = self.takeover_params.get('kvm_pwd', None)
            logic = self.takeover_params['logic']
            debug = int(self.takeover_params.get('debug', 0))
            name = r'nbd ({}) boot disk'.format(self.boot_nbd_object.device_path)
            self._save_kvm_run_info('msg', '准备虚拟机设备')
            self._save_kvm_run_info('debug', name)
            boot_nbd_thread = nbd_direct_images(name, self.boot_nbd_object,
                                                disk_snapshots['boot_devices'][0]['disk_snapshots'])
            boot_nbd_thread.start()

            self._is_cancel_kvm()

            data_index = 0
            for data_nbd_object in self.data_nbd_objects:
                data_index += 1
                name = r'nbd ({}) data disk {}'.format(data_nbd_object['nbd_object'].device_path, data_index)
                self._save_kvm_run_info('debug', name)
                disk_snapshots = data_nbd_object['data_device']['disk_snapshots']
                data_nbd_thread = nbd_direct_images(name, data_nbd_object['nbd_object'], disk_snapshots)
                data_nbd_thread.start()

            self._wait_all_nbd_read_ok(self.boot_nbd_object, self.data_nbd_objects)

            self.kill_mbr_virus(self.boot_nbd_object.device_path)

            self._is_cancel_kvm()

            hdd_drive = self.takeover_params['hdd_drive']
            net = self.takeover_params['net']
            vga = self.takeover_params['vga']
            cpu = self.takeover_params.get('cpu', 'host')

            # -drive file=./o.qcow,if=none,id=drive-scsi0-0-%target%-0
            # -device scsi-hd,bus=scsi0.0,channel=0,scsi-id=%target%,lun=0,drive=drive-scsi0-0-%target%-0,bootindex=100
            kvm_cmd = self.kvm_exec_path
            kvm_cmd += r" -device virtio-scsi-pci,id=scsi0"

            splash_time = self._get_splash_time()
            if splash_time:
                kvm_cmd += r' -boot menu=on,splash-time={}'.format(splash_time)
            else:
                kvm_cmd += r' -boot menu=off'

            if logic == 'windows':
                kvm_cmd += r" -rtc base=localtime,clock=host,driftfix=none"
            else:
                kvm_cmd += r" -rtc clock=host,driftfix=none"

            if self.is_aio_sys_vt_valid:
                kvm_cmd += r" -enable-kvm"

            kvm_cmd += r' -cpu {}'.format(cpu)

            if os.path.exists(monitors_addr):
                os.unlink(monitors_addr)

            if logic == 'windows':
                kvm_cmd += r" -rom-memory {rom_path}".format(rom_path=self.rom_path)

            if self.cpuId:
                kvm_cmd += r" -cpuid {cpuid}".format(cpuid=self.cpuId)
            self._save_kvm_run_info('vnc_address', self.boot_nbd_object.vnc_address)

            if logic == 'linux':
                kvm_cmd += r" -no-clerwaredev"

            sockets = int(self.takeover_params['sockets'])
            cores = int(self.takeover_params['cores'])
            if self.is_aio_sys_vt_valid:
                kvm_cmd += r" -smp sockets={sockets},cores={cores}".format(sockets=sockets, cores=cores)
            else:
                kvm_cmd += r" -smp sockets=1,cores=1"
            kvm_cmd += r" -m {}M".format(memory_size_MB)

            qemu_img_cmd = None
            boot_device = self.takeover_params['disk_snapshots']['boot_devices'][0]['device_profile']
            device_path = boot_device['qcow2path']
            boot_wwid = boot_device.get('wwid', uuid.uuid4().hex)
            user_data_max_size = boot_device['DiskSize']

            if not device_path:
                xlogging.raise_system_error('参数错误，无用户数据硬盘', 'boot_device={}'.format(boot_device), 0,
                                            _logger)

            if not os.path.isfile(device_path):
                qemu_img_cmd = 'qemu-img create -b {} -f qcow2 {} {}'.format(self.boot_nbd_object.device_path,
                                                                             device_path, user_data_max_size)

            self._save_kvm_run_info('msg', '准备用户数据硬盘（disk0）')
            self._save_kvm_run_info('debug', qemu_img_cmd)
            if qemu_img_cmd:
                _logger.info(r'kvm_wrapper.run qemu_img_cmd={}'.format(qemu_img_cmd))
                split_qemu_img_cmd = shlex.split(qemu_img_cmd)
                with subprocess.Popen(split_qemu_img_cmd, stderr=subprocess.PIPE, universal_newlines=True) as p:
                    stdoutdata, stderrdata = p.communicate()
                    if stdoutdata:
                        _logger.info(r'run_for_takeover stdoutdata={}'.format(stdoutdata))
                    if stderrdata:
                        _logger.info(r'run_for_takeover stderrdata={}'.format(stderrdata))
                _logger.info("run_for_takeover returncode={}".format(p.returncode))
                isCreateQcow2 = True
                self._save_qcow2_file_md5(device_path)

            device_path_list.append(device_path)

            bwritethrough = False
            if self.takeover_params['kvm_type'] == 'forever_kvm':
                bwritethrough = True

            VirtualHarddiskMgr = CVirtualHarddiskMgr(hdd_drive, bwritethrough)

            kvm_cmd += VirtualHarddiskMgr.get_disk_kvm_params(device_path, boot_wwid)
            if self.isoPath:
                kvm_cmd += r" -drive file={cdrom},if=none,id=drive-scsi0-0-0-0".format(cdrom=self.isoPath)
                kvm_cmd += r" -device scsi-cd,bus=scsi0.0,channel=0,scsi-id=0,lun=0,drive=drive-scsi0-0-0-0"
                number = 1
            else:
                number = 0

            if self.is_efi:
                kvm_cmd += r' -bios {}'.format(self.takeover_params['efibios'])
            elif self.takeover_params['seabios']:
                kvm_cmd += r' -bios {}'.format(self.takeover_params['seabios'])

            netindex = 0
            addr = 18
            for adpter in kvm_adpter:
                if adpter['macvtap'].startswith('takeovertap'):
                    kvm_cmd += r' -device {net},mac={address},netdev=net{netindex} -netdev type=tap,id=net{netindex},ifname={ifname},script=no'.format(
                        net=net, netindex=netindex, ifname=adpter['macvtap'], address=self._FmtMAC(adpter['mac']))
                    netindex = netindex + 1
                else:
                    with open(r'/sys/class/net/{macvtap}/address'.format(macvtap=adpter['macvtap']), 'r') as fout:
                        address = fout.read()
                        address = address.strip()
                    with open(r'/sys/class/net/{macvtap}/ifindex'.format(macvtap=adpter['macvtap']), 'r') as fout:
                        ifindex = fout.read()
                        ifindex = ifindex.strip()
                    kvm_cmd += r' -netdev type=tap,id=net{netindex},fd={ifindex} {ifindex}<>/dev/tap{ifindex} -device {net},mac={address},netdev=net{netindex},bus=pci.0,addr=0x{addr:x},id=net{netindex}'.format(
                        netindex=netindex, ifindex=ifindex, address=address, addr=addr, net=net)
                    netindex = netindex + 1
                    addr = addr + 1

            tmp_index = 1
            for data_nbd_object in self.data_nbd_objects:
                qemu_img_cmd = None
                device_profile = data_nbd_object['data_device']['device_profile']
                device_path = device_profile['qcow2path']
                user_data_max_size = device_profile['DiskSize']

                if not device_path:
                    xlogging.raise_system_error('参数错误，无用户数据硬盘', 'data_device={}'.format(device_profile), 0,
                                                _logger)

                if not os.path.isfile(device_path):
                    qemu_img_cmd = 'qemu-img create -b {} -f qcow2 {} {}'.format(
                        data_nbd_object['nbd_object'].device_path,
                        device_path, user_data_max_size)

                _logger.info(r'run_for_takeover qemu_img_cmd={}'.format(qemu_img_cmd))

                self._save_kvm_run_info('msg', '准备用户数据硬盘（disk{}）'.format(tmp_index))
                self._save_kvm_run_info('debug', qemu_img_cmd)
                tmp_index += 1
                if qemu_img_cmd:
                    split_qemu_img_cmd = shlex.split(qemu_img_cmd)
                    with subprocess.Popen(split_qemu_img_cmd, stderr=subprocess.PIPE, universal_newlines=True) as p:
                        stdoutdata, stderrdata = p.communicate()
                        if stdoutdata:
                            _logger.info(r'run_for_takeover stdoutdata={}'.format(stdoutdata))
                        if stderrdata:
                            _logger.info(r'run_for_takeover stderrdata={}'.format(stderrdata))
                    isCreateQcow2 = True
                    _logger.info("run_for_takeover returncode={}".format(p.returncode))
                    self._save_qcow2_file_md5(device_path)

            disk_index = 1
            for data_nbd_object in self.data_nbd_objects:
                data_device = data_nbd_object['data_device']
                disk_index += 1
                device_path = data_device['device_profile']['qcow2path']
                data_wwid = data_device['device_profile'].get('wwid', uuid.uuid4().hex)
                device_path_list.append(device_path)
                cmd_data_disk = VirtualHarddiskMgr.get_disk_kvm_params(device_path, data_wwid)
                kvm_cmd += cmd_data_disk

            if self.vbus_bin_path is not None:
                kvm_cmd += r' -device pci-vdev,subdev_hwid={}'.format(self.vbus_bin_path)

            floppy_path = self.takeover_params.get('floppy_path', None)
            if floppy_path and os.path.isfile(floppy_path):
                disk_index += 1
                cmd_floppy_disk = VirtualHarddiskMgr.get_disk_kvm_params(floppy_path, uuid.uuid4().hex)
                kvm_cmd += cmd_floppy_disk

            kvm_cmd += r' -vga {}'.format(vga)
            if logic == 'windows':
                if self.is_aio_sys_vt_valid:
                    kvm_cmd += r' -usbdevice tablet'
                else:
                    kvm_cmd += r' -usb -device usb-tablet'
            else:
                kvm_cmd += r' -usb'
            serial = int(self.boot_nbd_object.vnc_address.split(':')[1])
            _logger.info('serial:{}'.format(serial))
            if debug == 1:
                if logic == 'windows':
                    kvm_cmd += r' -serial tcp::{},server,nowait,nodelay'.format(5100 + serial)
                else:
                    kvm_cmd += r' -serial file:/var/log/aio/debug_serial_kvm{}.txt'.format(serial)
            alloc_success = False
            while not alloc_success:
                alloc_success = all_big_mm.CAllocBigMM.try_alloc(memory_size_MB + all_big_mm.RESTORE_KVM_MEMORY_MB)
                if not alloc_success:
                    self.some_error = (r'启动接管主机失败，内存不足', 'memory_size_MB={}'.format(memory_size_MB))
                    xlogging.raise_system_error(self.some_error[0], self.some_error[1], 0)

            # split_kvm_cmd = shlex.split(kvm_cmd)

            # 检查文件start_kvm_flag_file，不存在则关闭KVM
            threading.Thread(target=self._is_stop_kvm, args=(self.start_kvm_flag_file,), daemon=True).start()

            self._save_kvm_run_info('msg', '启动虚拟机')
            self._save_kvm_run_info('debug', kvm_cmd)
            _logger.info("kvm_cmd={}".format(kvm_cmd))
            if self.is_aio_sys_vt_valid:
                cwd = None
            else:
                cwd = r'/sbin/aio/qemu-nokvm'
            if os.path.isfile(PE_PATH_FILE):
                with open(PE_PATH_FILE, 'r') as f:
                    result = json.loads(f.read())
                pe_path = result['pe_path']
                _logger.info('pe_path is :{}'.format(pe_path))
                kvm_cmd += r" -drive file={},if=none,id=drive-scsi0-0-{}-0".format(pe_path, number)
                kvm_cmd += r" -device scsi-cd,bus=scsi0.0,channel=0,scsi-id={index},lun=0,drive=drive-scsi0-0-{index}-0,bootindex=0".format(
                    index=number)

            if kvm_pwd:
                kvm_cmd += r" -vnc {vnc},password -monitor unix:{monitors},server,nowait".format(
                    vnc=self.boot_nbd_object.vnc_address,
                    monitors=monitors_addr)
            else:
                kvm_cmd += r" -vnc {vnc}, -monitor unix:{monitors},server,nowait".format(
                    vnc=self.boot_nbd_object.vnc_address,
                    monitors=monitors_addr)

            with subprocess.Popen(kvm_cmd, shell=True, cwd=cwd, stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, universal_newlines=True) as p:
                self.kvm_pid = self._get_kvm_pid(device_path_list)
                if self.kvm_pid:
                    if kvm_pwd:
                        st1 = datetime.datetime.now()
                        while True:
                            rev = self._send_vnc_cmd(monitors_addr, 'change vnc password\n{}\n'.format(kvm_pwd))
                            if rev is None:
                                _logger.info('_send_vnc_cmd Failed.try it')
                                rev = ''
                            rev = rev.split('\n')
                            line1_ok = False
                            line2_ok = False
                            for line in rev:
                                line = line.strip()
                                if len(line) == 767:
                                    # line=(qemu) change vnc password,len=767
                                    line1_ok = True
                                if len(line) == 94:
                                    # line=Password: ******,len=94
                                    line2_ok = True
                            if line1_ok and line2_ok:
                                break
                            time.sleep(1)
                            _logger.info('change vnc password Failed.try it')
                            st2 = datetime.datetime.now()
                            if (st2 - st1).seconds > 60:
                                _logger.error('change vnc password Failed.')
                                self._save_kvm_run_info('msg', '设置密码出错，请尝试按下关机或断电按钮')
                                break
                    self._save_kvm_run_info('msg', '已开机')
                    self._save_kvm_run_info('debug', kvm_cmd)
                    _logger.info("start qemu-kvm pid:{}".format(self.kvm_pid))
                    psutil.Process(self.kvm_pid).wait()
                else:
                    _logger.error("qemu-kvm not start.")
                    raise Exception("qemu-kvm not start")
            _logger.info("qemu-kvm quit {}".format(self.kvm_pid))
            self.remove_start_kvm_flag_file()

        except Exception as e:
            isException = True
            tb = traceback.format_exc()
            _logger.error(r'kvm run failed . {} - {}'.format(e, tb))
            self._save_kvm_run_info('msg', '启动虚拟机异常')
            self._save_kvm_run_info('debug', r'kvm run failed . {} - {}'.format(e, tb))

        finally:
            self.running = False
            self.boot_nbd_object.unmount()
            for data_nbd_object in self.data_nbd_objects:
                data_nbd_object['nbd_object'].unmount()
            self.boot_nbd_object.wait_no_mounting()
            self.boot_nbd_object.set_no_longer_used()
            self.boot_nbd_object = None
            for data_nbd_object in self.data_nbd_objects:
                data_nbd_object['nbd_object'].wait_no_mounting()
                data_nbd_object['nbd_object'].set_no_longer_used()
                data_nbd_object['nbd_object'] = None

            if self.isoPath and os.path.isfile(self.isoPath):
                os.remove(self.isoPath)

            for adpter in kvm_adpter:
                cmd = r'ip li delete {macvtap}'.format(macvtap=adpter['macvtap'])
                with subprocess.Popen(shlex.split(cmd), stderr=subprocess.PIPE, universal_newlines=True) as p:
                    p.communicate()

            need_del_qcow2 = False
            if isException and isCreateQcow2:
                need_del_qcow2 = True
            if self.takeover_params['kvm_type'] in ('temporary_kvm', 'verify_kvm',):
                need_del_qcow2 = True

            if need_del_qcow2:
                for device_path in device_path_list:
                    if os.path.isfile(device_path):
                        os.remove(device_path)
                        filesizepath = device_path + '.md5'
                        if os.path.isfile(filesizepath):
                            os.remove(filesizepath)
            else:
                for device_path in device_path_list:
                    if os.path.isfile(device_path):
                        fd = os.open(device_path, os.O_RDWR)
                        try:
                            os.fsync(fd)
                        finally:
                            os.close(fd)

            if os.path.exists(monitors_addr):
                os.unlink(monitors_addr)

    @staticmethod
    def _get_kvm_pid(device_path_list):
        st1 = datetime.datetime.now()
        while True:
            p = psutil.process_iter()
            for r in p:
                if r.name().strip().lower() in ('qemu-kvm', 'qemu-system-x86_64',):
                    for line in r.cmdline():
                        for device_path in device_path_list:
                            if device_path in line:
                                return r.pid
            time.sleep(5)
            _logger.info('_get_kvm_pid Failed.try it')
            st2 = datetime.datetime.now()
            if (st2 - st1).seconds > 60:
                break
        return None

    def kill_kvm(self, kill_param):
        if self.remote_kvm_host_object:
            self._kill_remote_kvm(kill_param)
        else:
            self._kill_local_kvm(kill_param)
        return datetime.datetime.now()

    def _kill_remote_kvm(self, kill_param):
        kill_cmd = r'kill -{} {}'.format(kill_param, self.kvm_pid)
        kvm_host.kvm_host_exec_helper(self.remote_kvm_host_object, kill_cmd, 'kill', _logger)

    def _kill_local_kvm(self, kill_param):
        _logger.info(r'close_kvm will kill {} by {}'.format(self.kvm_pid, kill_param))
        os.kill(self.kvm_pid, kill_param)
        _logger.info(r'close_kvm killed {}'.format(self.kvm_pid))

    def close_kvm(self, some_error):
        while self.running and self.kvm_pid is None:
            _logger.warning(r'close_kvm : wait kvm start')
            time.sleep(5)  # 等待kvm进程启动

        if not self.running:
            _logger.info(r'close_kvm do nothing')
            return

        # 可能掩盖真实错误
        if not self.some_error:
            self.some_error = some_error

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
            _logger.error(r'close kvm failed . {} - {}'.format(e, tb))

    @staticmethod
    def create_vbus_file(kvm_vbus_devices):
        if kvm_vbus_devices is None or len(kvm_vbus_devices) == 0:
            return None

        vbus_bin_path = r'/dev/shm/{}.vbus'.format(uuid.uuid4().hex)
        try:
            with open(vbus_bin_path, 'wt') as _file:
                _file.write(kvm_vbus_devices)
            return vbus_bin_path
        except Exception as e:
            xlogging.raise_system_error('内部异常，临时缓存写入失败', 'create_vbus_file failed：{}'.format(e), 0, _logger)

    @staticmethod
    def create_rom_file(deviceHids):
        # 第三个字节表示总长度 0x80 为 128个扇区
        raw_content = [0x55, 0xAA, 0x80, 0x90, 0x90, 0x90, 0xCB, 0x66,
                       0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x20, 0x16, 0x06, 0x10, 0x15, 0x57, 0x20, 0x20]
        RAW_LEN = raw_content[2] * 512
        HEAD_LEN = 24
        CONTENT_LEN = RAW_LEN - HEAD_LEN - 8

        for hid in deviceHids:
            hid_content = 'HWID:{}\0'.format(hid)
            raw_content.extend([ord(letter) for letter in hid_content])
        with open(_disable_sys_in_kvm_file_path) as f:
            disable_sys_in_kvm_file = json.load(f)
        if not os.path.exists(DRIVE_FILE):
            new_disable_sys_in_kvm_file = disable_sys_in_kvm_file['sys']
        else:
            with open(DRIVE_FILE) as f:
                new_disable_sys = json.load(f)
            new_disable_sys_in_kvm_file = new_disable_sys['sys'] + disable_sys_in_kvm_file['sys']
        _logger.info('new_disable_sys_in_kvm_file:{}'.format(new_disable_sys_in_kvm_file))
        for disable_sys_in_kvm in new_disable_sys_in_kvm_file:
            disable_sys = 'SYSN:{}\0'.format(disable_sys_in_kvm)
            raw_content.extend([ord(letter) for letter in disable_sys])

        raw_content.append(0)

        # 检查内容是否超过容量限制，padding仅是用于检查与调试输出
        padding = CONTENT_LEN + HEAD_LEN - len(raw_content)
        if padding < 0:
            xlogging.raise_system_error('设备过多，无法完成虚拟', 'create_rom_file padding：{}'.format(padding), padding,
                                        _logger)

        padding = RAW_LEN - len(raw_content)
        raw_content.extend([0 for n in range(padding)])

        raw_path = r'/dev/shm/{}.raw'.format(uuid.uuid4().hex)
        rom_path = r'/dev/shm/{}.rom'.format(uuid.uuid4().hex)
        try:
            with open(raw_path, 'wb') as raw_file:
                raw_file.write(bytearray(raw_content))

            returned_code = os.system(r'python "/sbin/aio/signrom.py" "{}" "{}"'.format(raw_path, rom_path))
            if returned_code != 0:
                xlogging.raise_system_error(
                    '内部错误', 'signrom.py failed : {} {} | {}'.format(returned_code, raw_path, rom_path),
                    returned_code, _logger)
            else:
                _logger.info('signrom.py ok : {} | {}'.format(raw_path, rom_path))
            return rom_path
        except Utils.SystemError:
            raise
        except Exception as e:
            xlogging.raise_system_error('内部异常，临时缓存写入失败', 'create_rom_file failed：{}'.format(e), 0, _logger)
        finally:
            os.remove(raw_path)
