import json
import logging
import os
import threading
import time
import nbd
import kvm_server_helper
import hostSession
import xlogging
import uuid
import qemuimgcmd
import xdefine

_logger = xlogging.getLogger(__name__)

import BoxLogic
import kvm_server
import Utils

KVM_HOST_START_TIMEOUTS_SECONDS = 60 * 10
NAS_MOUNT_PATH = r'/mnt/nas'
NAS_MOUNT_TIMEOUTS_SECONDS = 60 * 5
NAS_UMOUNT_TIMEOUTS_SECONDS = 60
BACKUP_MOUNT_PATH = r'/mnt/backup'
KVM_STOPPED_TIMEOUTS_SECONDS = 60 * 5
FILE_BACKUP_LOGIC_START_TIMEOUTS_SECONDS = 60
over_kvm_flag = '/opt/over_kvm_flag.temp'


class LoggerAdapter(logging.LoggerAdapter):

    def process(self, msg, kwargs):
        return '[{}] {}'.format(self.extra['prefix'], msg), kwargs


class KVMShell(threading.Thread):

    def __init__(self, kvm_params, linux_storage=None, linux_disk_index_info=None):
        kvm_params['block_device'] = list()
        if kvm_params['logic'] == 'windows':
            kvm_params['memory_mbytes'] = 1024
            if kvm_params['system_type'] == 32:
                block_device = {'type': 'scsi-cd', 'file': '/home/kvm_rpc/WinPE_x86.iso'}
            else:
                block_device = {'type': 'scsi-cd', 'file': '/home/kvm_rpc/WinPE_amd64.iso'}
        else:
            kvm_params['memory_mbytes'] = 512
            self._create_temp_qcow_file('/home/kvm_rpc/Clerware-7-x86_64-1611.mini.loader.qcow2',
                                        kvm_params['tmp_qcow'])
            block_device = {'type': 'scsi-hd', 'file': kvm_params['tmp_qcow'], 'disk_ident': uuid.uuid4().hex}
        kvm_params['block_device'].append(block_device)
        for disk_device in kvm_params['disk_devices']:
            block_device = {'type': 'scsi-hd', 'file': disk_device['device_profile']['nbd']['device_path'],
                            'disk_ident': disk_device['disk_ident']}
            kvm_params['block_device'].append(block_device)

        kvm_params['vnc'] = "0.0.0.0:{}".format(kvm_params['vnc'])
        kvm_params['name'] = 'kvm'
        self._linux_storage = linux_storage
        self._linux_disk_index_info = linux_disk_index_info
        self._kvm_params = kvm_params
        super(KVMShell, self).__init__(name='{}'.format(self._kvm_params['name']))
        self.name = 'kvm_shell_{}'.format(self._kvm_params['name'])
        self.logger = LoggerAdapter(_logger, {'prefix': self.name})
        self.__linux_kvm_file_backup = None
        self.error = None
        self._helper = kvm_server_helper.KVMServerHelper(self.name, self.logger, self._kvm_params['logic'])

        self._in_stopping = False
        self._in_stopping_locker = threading.RLock()

        self.guest_ip = None
        self.guest_mac = None
        self.block_device = list()
        self.create_params = False
        self.check_kvm_is_over = False

    def run(self):
        self.logger.info('start logic, {}'.format(self._kvm_params))
        try:
            self._create_params_file()
            self._do_work()
            self._clean_temp_file()
        finally:
            self.logger.info('end logic, {}'.format(self._kvm_params))

    def _create_temp_qcow_file(self, qcow_file, temp_qcow_file):
        if os.path.isfile(temp_qcow_file):
            os.remove(temp_qcow_file)
        qemuimgcmd.QemuImgCmd().create_qcow2_file_base_old(qcow_file, temp_qcow_file)

        if not os.path.isfile(temp_qcow_file):
            raise Exception("_create_temp_qcow_file failed temp_qcow_file={}".format(temp_qcow_file))

    def _clean_temp_file(self):
        if self._kvm_params.get('tmp_qcow') is None:
            return
        if not os.path.exists(r'/dev/shm/not_remove_boot_qcow_file_backup'):
            if os.path.exists(self._kvm_params['tmp_qcow']):
                os.remove(self._kvm_params['tmp_qcow'])
        else:
            self.logger.info(r'do NOT clean file : {}'.format(self._kvm_params['tmp_qcow']))

    def get_snapshot_disk_index(self, disk_ident):
        for info in self._linux_disk_index_info:
            if disk_ident == info['disk_ident']:
                return info['snapshot_disk_index']
        xlogging.raise_system_error(
            r'内部异常，代码3110',
            'get_snapshot_disk_index failed {} not in {}'.format(disk_ident, self._linux_disk_index_info), 1)

    @staticmethod
    def _get_disk_snapshot_ident_by_nbd(open_kvm_params, disk_ident):
        for params in open_kvm_params['disk_devices']:
            if disk_ident == params['disk_ident']:
                return disk_ident

    def _create_params_file(self):
        disk_list = list()
        try:
            for block in self._kvm_params['block_device']:
                disk_ident = self._get_disk_snapshot_ident_by_nbd(self._kvm_params, block['disk_ident'])
                if disk_ident and disk_ident != xdefine.CLW_BOOT_REDIRECT_MBR_UUID:
                    disk_index = self.get_snapshot_disk_index(disk_ident)
                    disk_list.append({'diskid': disk_index, 'nbd_uuid': disk_ident})
            key_info = {
                'username': 'wuo',  # over_kvm中会使用此用户名
                'hostname': uuid.uuid4().hex,
                'linux_storage': self._linux_storage,
                'userpwd': '843207',
                'disklist': disk_list,
                'ostype': 'linux',
                'include_ranges': [],
                'script': 'add_share',
                'install_path': self._kvm_params.get('install_path', '')
            }
            params_file_path = self._kvm_params['write_new']['src_path']
            with open(params_file_path, "w") as f:
                json.dump(key_info, f)
            self.create_params = True
        except Exception as e:
            _logger.info('_create_params_file failed:{}'.format(e))

    def over_kvm(self):
        """
        结束Linux还原阶段的kvm，非通用方法
        :return:
        """
        if self._kvm_params['logic'] == 'linux':
            # 用户名wuo固定的，见_create_params_file
            cmd = r'/home/python3.6/bin/python3.6 /home/patch/linux_iso/scripts/add_share_restore_takeover.py --kvmparams unmount --username wuo'
            work_dir = r'/home/patch/linux_iso'
            timeouts = None
            self._helper.run_on_remote(cmd, work_dir, timeouts)
        self._helper.shutdown()
        if not self._wait_kvm_stopped(KVM_STOPPED_TIMEOUTS_SECONDS):
            self._stop_kvm()
        _logger.info('linux restore is over')

    def _do_work(self):
        try:
            self.__linux_kvm_file_backup = kvm_server.KvmServer(self._kvm_params)
            self.guest_ip, self.guest_mac = self.__linux_kvm_file_backup.get_ip_and_mac()
            _logger.info('1111_guest_ip:{}'.format(self.guest_ip))
            self.block_device = self.__linux_kvm_file_backup.get_block_device()
            self.__linux_kvm_file_backup.start()
            self.logger.info('_do_work _wait_host_online _guest_ip={}'.format(self.guest_ip))
            self._wait_host_online(self.guest_ip)
            self.logger.info('_do_work _wait_host_online OK')
            self._helper.fetch_patch(self._kvm_params['aio_server_ip'])
            write_new = self._kvm_params['write_new']
            with open(write_new['src_path'], 'rb') as f:
                inputBs = bytearray(f.read())
            inputJson = {
                "type": "write_new",
                "path": write_new['dest_path']
            }
            self._helper._rw_file_in_kvm(inputJson, inputBs)

            for cmd in self._kvm_params['cmd_list']:
                rc = self._helper.run_on_remote(cmd['cmd'], cmd['work_dir'], cmd['timeouts'])
                if rc:
                    rc['r'] = 0
                    self.logger.info('_do_work cmd={},rc={}'.format(cmd, rc))
                else:
                    rc = {'r': 1}
                    self.logger.info('_do_work Failed.cmd={}'.format(cmd))
                if cmd['post_result_url']:
                    if cmd['post_result_params']:
                        rc.update(cmd['post_result_params'])
                    hostSession.http_common_post(cmd['post_result_url'], rc)
            self._check_nbd_and_kvm()
            if self._linux_storage is None:
                self._finish_work()
        except Exception as e:
            self.error = e
            self.logger.error(r' failed {}'.format(e), exc_info=True)
            if self._linux_storage is None:
                self._clean_resource_when_failed()
        finally:
            pass

    @xlogging.convert_exception_to_value(False)
    def _wait_kvm_stopped(self, timeouts_seconds):
        if self.__linux_kvm_file_backup is None:
            return True

        for _ in range(timeouts_seconds):
            if self.__linux_kvm_file_backup.is_active():
                time.sleep(1)
            else:
                return True
        return False

    def _stop_kvm(self):
        if self.__linux_kvm_file_backup is not None:
            self.__linux_kvm_file_backup.kill()

    def _wait_host_online(self, host_ip):
        self._helper.connect(host_ip, KVM_HOST_START_TIMEOUTS_SECONDS)

    @xlogging.convert_exception_to_value(None)
    def _report_warning_info_when_successful(self, status):
        description, debug = status['finished_description'], status['finished_debug']
        if not description:
            return
        payload = {'status': 'warning_info', 'description': description, 'debug': debug}
        task_type, task_uuid = 'nas_file_backup', self._kvm_params['task_uuid']
        return hostSession.http_report_task_status(task_type, task_uuid, payload)

    def _check_nbd_and_kvm(self):
        if not self.__linux_kvm_file_backup.nbd_alive():
            xlogging.raise_system_error('nbd组件异常退出', 'nbd not alive', 143)
        if not self.__linux_kvm_file_backup.kvm_alive():
            xlogging.raise_system_error('代理虚拟机异常退出', 'kvm not alive', 145)
        return True

    def _shutdown(self):
        if self._kvm_params['shutdown']:
            self._helper.shutdown()

    def _finish_work(self):
        self._shutdown()
        self.__clean_kvm_resource(True)

    def _clean_resource_when_failed(self):
        if self.__linux_kvm_file_backup is not None and self.__linux_kvm_file_backup.is_active():
            self.__clean_kvm_resource(False, 0)

    def __clean_kvm_resource(self, raise_exception, waite_seconds=KVM_STOPPED_TIMEOUTS_SECONDS):
        try:
            if not self._wait_kvm_stopped(waite_seconds):
                self._stop_kvm()
        except Exception as e:
            if raise_exception:
                raise
            else:
                self.logger.warning(r'stop_kvm failed : {}'.format(e), exc_info=True)

        if self.__linux_kvm_file_backup:
            self.__linux_kvm_file_backup.join()
            self.__linux_kvm_file_backup = None

        for disk_device in self._kvm_params['disk_devices']:
            nbd.nbd_wrapper.set_unused(disk_device['device_profile']['nbd']['device_name'])

    @xlogging.convert_exception_to_value(None)
    def stop(self):
        with self._in_stopping_locker:
            if self._in_stopping:
                self.logger.warning('_in_stopping , return')
                return
            else:
                self._in_stopping = True
        try:
            if self.is_alive():
                self._shutdown()
            else:
                self.logger.warning('not alive, skip cancel')
        finally:
            with self._in_stopping_locker:
                self._in_stopping = False


class KVMShellManager(object):

    def __init__(self):
        self._instance = dict()
        self._locker = threading.RLock()

    def new(self, key, params):
        ins = self._fetch(key)
        if ins:
            _logger.warning('FileBackupManager new fail, key:{} is already in'.format(key))
        else:
            with self._locker:
                t = KVMShell(params)
                t.setDaemon(True)
                t.start()
                self._instance[key] = t

    def raise_last_error(self, key, params):
        ins = self._fetch(key)
        if ins and ins.error:
            raise ins.error
        else:
            xlogging.raise_system_error('无效的错误码', 'not found error, ins:{}'.format(ins), 197)

    def poll(self, key, params):
        ins = self._fetch(key)
        status = list()
        if ins:
            status.append('has_worker')
            if ins.isAlive():
                status.append('alive')
        else:
            status.append('no_worker')
        return status

    def delete(self, key, params):
        ins = self._fetch(key)
        if ins:
            try:
                ins.stop()
                ins.join()
            finally:
                self._del(key)
        else:
            pass

    def _fetch(self, key):
        with self._locker:
            return self._instance.get(key)

    def _del(self, key):
        with self._locker:
            self._instance.pop(key, None)

    def work(self, params):
        action = params.pop('action')
        key = params.pop('key')
        info = params.pop('info', {})
        try:
            rev = getattr(self, action)(key, info)
        except Utils.SystemError:
            raise
        except Exception as e:
            xlogging.raise_system_error('内部异常，代码F221', 'error:{} k:{} i:{}'.format(e, key, info), 221)
        else:
            return json.dumps({'result': rev})


kvm_shell_mgr = KVMShellManager()

if __name__ == '__main__':
    pass
