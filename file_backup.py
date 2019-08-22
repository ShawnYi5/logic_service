import json
import logging
import os
import threading
import time
import uuid
from itertools import chain

import file_backup_helper
import hostSession
import xlogging
import net_common
import db_backup_logic
import remote_helper
import logicService
import samba

_logger = xlogging.getLogger(__name__)

import BoxLogic
import kvmfilebackup
import Utils

KVM_HOST_START_TIMEOUTS_SECONDS = 60 * 10
NAS_MOUNT_PATH = r'/mnt/nas'
NAS_MOUNT_TIMEOUTS_SECONDS = 60 * 5
NAS_UMOUNT_TIMEOUTS_SECONDS = 60
BACKUP_MOUNT_PATH = r'/mnt/backup'
KVM_STOPPED_TIMEOUTS_SECONDS = 60 * 5
FILE_BACKUP_LOGIC_START_TIMEOUTS_SECONDS = 60
dynamic_config_path = '/etc/clw_backup.json'
DB_BACKUP_DEBUG_FILE = '/dev/shm/debug_db_backup'


class LoggerAdapter(logging.LoggerAdapter):

    def process(self, msg, kwargs):
        return '[{}] {}'.format(self.extra['prefix'], msg), kwargs


class FileBackup(threading.Thread):

    def __init__(self, backup_params):
        """
        :param backup_params:
        {
            'host_ident': str       主机标识
            'name': str             可读性任务标识
            'nas_type': str         'nfs' or 'cifs'
            'nas_excludes': [str, ]
            'nas_path': str         nfs为 '172.16.1.3:/nfs_dir' cifs为 '\\172.16.1.3\cifs_dir'
            'nas_user': str             cifs 需要
            'nas_pwd': str              cifs 需要
            'diskbytes': int        备份空间
            'aio_server_ip':[(str, str), ]
            'disksnapshots':[{'path':'', 'ident':''}, ]
            'temp_qcow':''          临时QCOW
            'task_uuid': str
            "enum_threads": int,         # 枚举目录线程数量（初始值，后续根据配置文件调整）
            "enum_level": int,           # 枚举目录深度
            "sync_threads": int,         # 同步数据线程数量（初始值，后续根据配置文件调整）
            "sync_queue_maxsize": int,   # 同步任务队列深度
            "dynamic_config_path": path, # 动态配置文件
            "cores": int,                # CPU数量
            "memory_mbytes": int,        # 内存大小
        }
        """
        self._backup_params = backup_params
        super(FileBackup, self).__init__(name='FileBackup_{}'.format(self._backup_params['name']))
        self.name = 'FileBackup_{}'.format(self._backup_params['name'])
        self.logger = LoggerAdapter(_logger, {'prefix': self.name})
        self.__linux_kvm_file_backup = None
        self.error = None
        self._helper = file_backup_helper.FileBackupHelper(self.name, self.logger)
        self._has_sync_files = False

        self._in_stopping = False
        self._in_stopping_locker = threading.RLock()
        self._is_host_online = False

    def run(self):
        self.logger.info('start logic, {}'.format(self._backup_params))
        try:
            self._do_work()
        finally:
            self.logger.info('end logic, {}'.format(self._backup_params))

    def _do_work(self):
        try:
            self.__linux_kvm_file_backup = kvmfilebackup.KvmFileBackup(self._backup_params)
            self.__linux_kvm_file_backup.start()
            _guest_ip, _guest_mac = self.__linux_kvm_file_backup.get_ip_and_mac()
            self._wait_host_online(_guest_ip)
            self._send_backup_command()
            self._poll_and_report_backup_status()
            self._check_nbd_and_kvm()
            self._finish_backup()
        except Exception as e:
            self.error = e
            self.logger.error(r' failed {}'.format(e), exc_info=True)
            self._clean_resource_when_failed()
        finally:
            self.__clean_temp_file()
            self._report_finish(self._is_task_successful())

    def _is_task_successful(self):
        """
        1. 已经同步了文件 判断标志 self._has_sync_files
        2. qemu-img文件存在且快照点存在
        :return:bool
        """
        if not self._has_sync_files:
            self.logger.warning('_is_task_successful False, not sync file')
            return False

        qcow_file, ident = self._backup_params['disksnapshots'][-1]['path'], self._backup_params['disksnapshots'][-1][
            'ident']
        self.logger.debug('start check qcow valid {} {}'.format(qcow_file, ident))
        if not os.path.exists(qcow_file):
            self.logger.warning('_is_task_successful False, not exists qcow file')
            return False

        '''
        [root@localhost ee49bfc175b844a8a23722e457b70f2a]# qemu-img snapshot 9e64e0d3161f4b5a8e7940b2445ed118.qcow -l
        Snapshot list:
        ID        TAG                 VM SIZE                DATE       VM CLOCK
        1         00x800000000         b3c8cf3e50f74ce5ab6ae7865a7ed793      0 2019-01-24 14:33:43   00:00:00.000
        2         10x800000000         b3c8cf3e50f74ce5ab6ae7865a7ed793      0 2019-01-24 14:35:22   00:00:00.000
        同样的名字出现2次，说明是正常的
        '''
        info = net_common.get_info_from_syscmd(r'qemu-img snapshot {} -l'.format(qcow_file))
        if info[0] == 0 and (info[1].count(ident) == 2):
            return True  # 确保 qcow文件中 快照点是2个
        else:
            self.logger.warning('_is_task_successful False, check qcow failed')
            return False

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
        ip_address = self._helper.config_gateway()
        runner_dir = self._helper.fetch_patch(ip_address)
        self._helper.start_logic(host_ip, FILE_BACKUP_LOGIC_START_TIMEOUTS_SECONDS, runner_dir)
        self._helper.begin_dropcache()
        self._is_host_online = True

    def _send_backup_command(self):
        self._helper.mount_nas({'nas_type': self._backup_params['nas_type'], 'mount_cmd': self._get_mount_cmd(),
                                'mount_path': NAS_MOUNT_PATH, 'timeouts_seconds': NAS_MOUNT_TIMEOUTS_SECONDS})
        self._helper.mount_backup({'mount_path': BACKUP_MOUNT_PATH})
        self._helper.backup({
            'excludes': self._backup_params['nas_excludes'],
            'skip_scan': True,
            'enum_threads': self._backup_params['enum_threads'],
            'enum_queue_maxsize': self._backup_params['enum_queue_maxsize'],
            'enum_level': self._backup_params['enum_level'],
            'sync_threads': self._backup_params['sync_threads'],
            'sync_queue_maxsize': self._backup_params['sync_queue_maxsize'],
            'dynamic_config_path': self._backup_params['dynamic_config_path'],
        })

    def _check_nfs_path(self):
        nas_path = self._backup_params['nas_path']
        processing_path = nas_path.split(':')
        processing_path[1] = '\"' + processing_path[1] + '\"'
        nas_path = ":".join(processing_path)
        _logger.info('nas_nfs_path is :{}'.format(nas_path))
        return nas_path

    def _get_mount_cmd(self):
        if self._backup_params['nas_type'].upper() == 'NFS':
            return r'mount -t nfs {} {} -o ro,soft,noatime,nodiratime,timeo=60'.format(
                self._check_nfs_path(), NAS_MOUNT_PATH)
        elif self._backup_params['nas_type'].upper() == 'CIFS':
            return r'mount -t cifs -o nomapposix,ro,soft,username="{}",password="{}"  "{}" "{}"'.format(
                self._backup_params['nas_user'], self._backup_params['nas_pwd'],
                self._backup_params['nas_path'].replace('\\', '/'), NAS_MOUNT_PATH)
        else:
            xlogging.raise_system_error(
                '内部错误，无效的NAS类型', 'invalid nas type : {}'.format(self._backup_params['nas_type']), 1)

    @xlogging.convert_exception_to_value(None)
    def _report_warning_info_when_successful(self, status):
        description, debug = status['finished_description'], status['finished_debug']
        if not description:
            return
        payload = {'status': 'warning_info', 'description': description, 'debug': debug}
        task_type, task_uuid = 'nas_file_backup', self._backup_params['task_uuid']
        return hostSession.http_report_task_status(task_type, task_uuid, payload)

    def _poll_and_report_backup_status(self):
        while True:
            self._check_nbd_and_kvm()
            time.sleep(10)
            status = self._helper.query_backup_status()
            if (not self._has_sync_files) and int(status['current_sync_files']) > 0:  # 更新self._has_sync_files  字段
                self._has_sync_files = True
            if status['step'][0] == 'step_sync':
                self._report_sync_percent(status)
            elif status['step'][0] == 'step_fin':
                if status['finished_successful']:
                    self._has_sync_files = True
                    return self._report_warning_info_when_successful(status)
                else:
                    self._helper.debug_when_backup_failed(status['finished_description'])
                    xlogging.raise_system_error(status['finished_description'], status['finished_debug'], 1)

    def _check_nbd_and_kvm(self):
        if not self.__linux_kvm_file_backup.nbd_alive():
            xlogging.raise_system_error('nbd组件异常退出', 'nbd not alive', 143)
        if not self.__linux_kvm_file_backup.kvm_alive():
            xlogging.raise_system_error('代理虚拟机异常退出', 'kvm not alive', 145)
        return True

    def _finish_backup(self):
        self.__umount_backup(True)
        self.__clean_resource_in_kvm()
        self.__clean_kvm_resource(True)

    def _clean_resource_when_failed(self):
        if self.__linux_kvm_file_backup is not None and self.__linux_kvm_file_backup.is_active():
            self.__umount_backup(False)
            self.__clean_resource_in_kvm()
            self.__clean_kvm_resource(False, 0)

    def __clean_temp_file(self):
        try:
            if not os.path.exists(r'/dev/shm/not_remove_boot_qcow_file_backup'):
                if os.path.exists(self._backup_params['temp_qcow']):
                    os.remove(self._backup_params['temp_qcow'])
            else:
                self.logger.info(r'do NOT clean file : {}'.format(self._backup_params['temp_qcow']))
        except Exception as e:
            self.logger.warning(r'clean file {} failed : {}'.format(self._backup_params.get('temp_qcow', 'None'), e))

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

    def __clean_resource_in_kvm(self):
        self._helper.umount_nas({'mount_path': NAS_MOUNT_PATH, 'timeouts_seconds': NAS_UMOUNT_TIMEOUTS_SECONDS})
        self._helper.package_log_files_and_fetch()
        self._helper.shutdown()

    def __umount_backup(self, raise_exception):
        try:
            self._helper.umount_backup({'mount_path': BACKUP_MOUNT_PATH})
        except Exception as e:
            if raise_exception:
                raise
            else:
                self.logger.warning(r'umount_backup failed : {}'.format(e), exc_info=True)

    @xlogging.convert_exception_to_value(None)
    def _report_sync_percent(self, rsync_status):
        percent_str = rsync_status['current_percent']
        return self.report_progress(100 * 100, int(percent_str[:-1]) * 100, rsync_status)

    @xlogging.convert_exception_to_value(None)
    def report_progress(self, total, index, rsync_status):
        payload = {'status': 'transfer_data', 'progressIndex': index, 'progressTotal': total,
                   'rsync_status': rsync_status}
        task_type, task_uuid = 'nas_file_backup', self._backup_params['task_uuid']
        return hostSession.http_report_task_status(task_type, task_uuid, payload)

    def _report_finish(self, successful):
        code = BoxLogic.BackupFinishCode.Successful if successful else BoxLogic.BackupFinishCode.Failed
        return hostSession.http_report_backup_finish(self._backup_params['host_ident'], code)

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
                self._helper.set_quit()
                self._helper.cancle_backup('{}')
            else:
                self.logger.warning('not alive, skip cancel')
        finally:
            with self._in_stopping_locker:
                self._in_stopping = False

    def end_transfer_data(self):
        """
        通知rsync尽快结束，并上报状态为“成功”
        """
        self._helper.cancle_backup('{}')

    def set_nas_dynamic_params(self, nas_dynamic):
        """
        将NAS动态参数写入kvm文件：dynamic_config_path
        """
        global dynamic_config_path
        if not self._is_host_online:
            return None
        nas_dynamic = json.dumps(nas_dynamic).replace('"', '\\"')  # 命令文本：echo "{\"age\": 21}" > "tst.json"
        self._helper.run_on_remote('echo "{}" > "{}"'.format(nas_dynamic, dynamic_config_path))
        return 'ok'


class DBBackup(threading.Thread):

    def __init__(self, backup_params):
        """
        :param backup_params:
        {
            'name': self._task_name,
            'disksnapshots': list(),
            'temp_qcow': '',
            'diskbytes': -1,
            'host_ident': uuid,
            'aio_server_ip': '172.29.16.2',
            'task_uuid': uuid,
            'vga':std,
            'cores':'',
            'sockets':'',
            'memory_mbytes':''
        }
        """
        self._backup_params = backup_params
        super(DBBackup, self).__init__(name='DBBackup_{}'.format(self._backup_params['name']))
        self.name = 'DBBackup_{}'.format(self._backup_params['name'])
        self.logger = LoggerAdapter(_logger, {'prefix': self.name})
        self.__linux_kvm_file_backup = None
        self.error = None
        self._helper = None
        self._proxy = None
        self._has_sync_files = False
        self._deploy_mod = self._backup_params.get('deploy_mod', os.path.exists('/dev/shm/db_backup_deploy'))

        self._in_stopping = False
        self._in_stopping_locker = threading.RLock()
        self._quit_flag = False
        self._quit_flag_locker = threading.RLock()
        self._guest_ip = None

    def run(self):
        self.logger.info('start logic, {}'.format(self._backup_params))
        try:
            self._do_work()
        finally:
            self.logger.info('end logic, {}'.format(self._backup_params))

    def _do_work(self):
        try:
            self.__linux_kvm_file_backup = db_backup_logic.KvmDBBackup(self._backup_params)
            self.__linux_kvm_file_backup.start()
            self._guest_ip, _guest_mac = self.__linux_kvm_file_backup.get_ip_and_mac()
            if self._deploy_mod:
                self.logger.info('模式：部署模式')
                self._waite_kvm()
            else:
                self.logger.info('模式：备份模式')
                self._report_info({'status': ('report_mac_info', 'report_mac_info'), 'mac': _guest_mac})
                self._report_info({'status': ('初始化备份代理', 'start_kvm')})
                self._wait_host_online(self._guest_ip)
                self._report_info({'status': ('初始化远端备份代理', 'notify_remote_connect')})
                self._notify_remote_connect_begin(self._guest_ip)  # 让远端连入kvm
                self._send_backup_command()
                self._poll_and_report_backup_status()
                self._check_nbd_and_kvm()
                self._finish_backup()
        except Exception as e:
            self.error = e
            self.logger.error(r' failed {}'.format(e), exc_info=True)
            self._pause_in_debug_mod('before _clean_resource_when_failed')
            self._clean_resource_when_failed()
        finally:
            self._report_finish(self._is_task_successful())

    @xlogging.convert_exception_to_value(None)
    def _pause_in_debug_mod(self, msg):
        if not os.path.exists(DB_BACKUP_DEBUG_FILE):
            return
        file_name = '/tmp/pause_db_backup_{}'.format(time.time())
        with open(file_name, 'w'):
            pass
        while os.path.exists(file_name):
            self.logger.warning('{} pause until {} removed!'.format(msg, file_name))
            time.sleep(5)

    def _notify_remote_connect_begin(self, _guest_ip):
        master_ident = self._backup_params['db_backup_params']['master_ident']
        data = json.dumps({'kvm_ip': _guest_ip, 'type': 'start_kvm_channel', 'remote_ident': master_ident})
        self.logger.info('begin _notify_remote_connect {}'.format(data))
        count = 120  # 1分钟
        while count > 0:
            self.check_quit()
            try:
                logicService.JsonFuncV2(master_ident, data, bytes())
            except Exception as e:
                if count % 2 == 0:
                    _logger.error('_notify_remote_connect_begin JsonFuncV2 error:{}'.format(e), exc_info=True)
                time.sleep(5)
                count -= 1
            else:
                break
        else:
            xlogging.raise_system_error('启动远端备份代理程序失败',
                                        '_notify_remote_connect_begin failed:{}'.format(data),
                                        1140, self.logger)
        self.logger.info('end _notify_remote_connect {}'.format(data))

    @xlogging.convert_exception_to_value(None)
    def _notify_remote_connect_end(self):
        data = json.dumps({'type': 'stop_kvm_channel'})
        master_ident = self._backup_params['db_backup_params']['master_ident']
        try:
            logicService.JsonFuncV2(master_ident, data, bytes())
        except Exception as e:
            _logger.warning('_notify_remote_connect_end error:{}'.format(e))

    def _waite_kvm(self):
        while True:
            self.check_quit()
            if self.__linux_kvm_file_backup and self.__linux_kvm_file_backup.is_active():
                time.sleep(10)
                continue
            else:
                break
        if self.__linux_kvm_file_backup:
            self.__linux_kvm_file_backup.join()
            self.__linux_kvm_file_backup = None

    def _wait_host_online(self, _guest_ip):
        self.logger.info('_wait_host_online begin')
        self._proxy = remote_helper.RemoteProxy(_guest_ip, logicService.get_communicator(), self.logger,
                                                self.check_quit).create()
        self.logger.info('_wait_host_online end')

    def _send_backup_command(self):
        args_dict = dict()
        args_dict['db_backup_params'] = self._backup_params['db_backup_params']
        args_dict['in_debug_mod'] = os.path.exists(DB_BACKUP_DEBUG_FILE)
        args_dict['kvm_ip_info'] = self._backup_params['kvm_ip_info']
        for disk in self._backup_params['disksnapshots']:
            if disk['type'] == 'cache_disk':
                args_dict.setdefault('lvm_config', {'disks': list()})
                args_dict['lvm_config']['disks'].append(
                    {
                        'disk_bytes': disk['disk_bytes']
                    }
                )
        for net in self._backup_params['nets']:
            if net['con_type'] == 'bond':
                args_dict['kvm_ip_info']['mac'] = net['mac']
                break
        self.logger.info('init db_backup_logic MainLogic {}'.format(args_dict))
        self._helper = remote_helper.ModuleMapper('db_backup_logic', 'MainLogic', self._proxy, self.logger, args_dict)
        self._helper.execute('start_backup', {'name': 'xiao ming'})

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

    def _stop_kvm(self):
        if self.__linux_kvm_file_backup is not None:
            self.__linux_kvm_file_backup.kill()

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

    @xlogging.convert_exception_to_value(None)
    def _clean_resource_when_failed(self):
        self._notify_remote_connect_end()
        if self.__linux_kvm_file_backup is not None and self.__linux_kvm_file_backup.is_active():
            if self._proxy:
                _call_proxy = remote_helper.FunctionMapper(self._proxy, self.logger)
                _call_proxy.execute('common_funcs', 'shutdown', {'logic': self._backup_params['logic']})
            # self.__umount_backup(False)
            # self.__clean_resource_in_kvm()
        self.__clean_kvm_resource(False, 0)

    def _finish_backup(self):
        self._notify_remote_connect_end()
        if self.__linux_kvm_file_backup is not None and self.__linux_kvm_file_backup.is_active():
            if self._proxy:
                _call_proxy = remote_helper.FunctionMapper(self._proxy, self.logger)
                _call_proxy.execute('common_funcs', 'shutdown', {'logic': self._backup_params['logic']})
            # self.__umount_backup(True)
            # self.__clean_resource_in_kvm()
        self.__clean_kvm_resource(True)

    def _is_task_successful(self):
        """
        2. qemu-img文件存在且快照点存在
        :return:bool

        """
        if not self._deploy_mod:
            if not self._has_sync_files:  # 自动模式下，没有同步文件，认为任务失败
                return False

        for disk_info in self._backup_params['disksnapshots']:
            qcow_file, ident = disk_info['images'][-1]['path'], disk_info['images'][-1]['ident']
            self.logger.debug('start check qcow valid {} {}'.format(qcow_file, ident))
            if not os.path.exists(qcow_file):
                self.logger.warning('_is_task_successful False, not exists qcow file')
                return False

            '''
            [root@localhost ee49bfc175b844a8a23722e457b70f2a]# qemu-img snapshot 9e64e0d3161f4b5a8e7940b2445ed118.qcow -l
            Snapshot list:
            ID        TAG                 VM SIZE                DATE       VM CLOCK
            1         00x800000000         b3c8cf3e50f74ce5ab6ae7865a7ed793      0 2019-01-24 14:33:43   00:00:00.000
            2         10x800000000         b3c8cf3e50f74ce5ab6ae7865a7ed793      0 2019-01-24 14:35:22   00:00:00.000
            同样的名字出现2次，说明是正常的
            '''
            info = net_common.get_info_from_syscmd(r'qemu-img snapshot {} -l'.format(qcow_file))
            if info[0] == 0 and (info[1].count(ident) == 2):
                pass  # 确保 qcow文件中 快照点是2个
            else:
                self.logger.warning('_is_task_successful False, check qcow failed')
                return False
        return True

    def _report_finish(self, successful):
        self._report_info({'status': ('report_finish', 'report_finish'), 'successful': successful})

    def _report_info(self, payload):
        self.logger.debug('_report_info {}'.format(payload))
        task_type, task_uuid = 'db_backup', self._backup_params['task_uuid']
        ret = hostSession.http_report_task_status(task_type, task_uuid, payload)
        assert ret['rev'] == 0

    def _poll_and_report_backup_status(self):
        while True:
            self._check_nbd_and_kvm()
            time.sleep(10)
            try:
                status_str, _ = self._helper.execute('poll')
            except Exception as e:
                self.logger.warning('poll status error:{}'.format(e))
                continue
            status = json.loads(status_str)
            if (not self._has_sync_files) and int(status['progressIndex']) > 0:  # 更新self._has_sync_files  字段
                self._has_sync_files = True
            if status['finished']:
                if status['successful']:
                    self._has_sync_files = True
                    self._pause_in_debug_mod('任务成功了^_^o')
                    return
                else:
                    error_msg = status['error_msg']
                    if error_msg and len(error_msg) == 3:
                        xlogging.raise_system_error(error_msg[0], error_msg[1], error_msg[2])
                    xlogging.raise_system_error('备份失败', 'unknown error', 2525)
            self._report_info(status)

    def _check_nbd_and_kvm(self):
        if not self.__linux_kvm_file_backup.nbd_alive():
            xlogging.raise_system_error('nbd组件异常退出', 'nbd not alive', 143)
        if not self.__linux_kvm_file_backup.kvm_alive():
            xlogging.raise_system_error('代理虚拟机异常退出', 'kvm not alive', 145)
        return True

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
                with self._quit_flag_locker:
                    self._quit_flag = True
                if self._helper:
                    self._helper.execute('stop_backup')  # 通知远端停止备份
            else:
                self.logger.warning('not alive, skip cancel')
        finally:
            with self._in_stopping_locker:
                self._in_stopping = False

    def check_quit(self):
        with self._quit_flag_locker:
            if self._quit_flag:
                xlogging.raise_system_error(r'用户取消操作', 'self._quit', 1, logger=self.logger)

    def end_transfer_data(self):
        self._helper.execute('stop_backup')


class FileSync(threading.Thread):

    def __init__(self, backup_params):
        """
        backup_params = {
            'name': '任务名称',
            'task_uuid': 'uuid',
            'target_host_ident': 'xx'
            'aio_ip':''
            'kvm_used_params': {  # 启动kvm使用的参数
                'logic': 'linux',
                ‘disk_ctl_type’:'scsi-hd',
                'aio_server_ip': '172.29.16.2',
                'disksnapshots': [
                    {
                        'images': [
                            {
                                'path': '/home/mnt/nodes/b7f1e05d286d4aad933fd49ff8eeceb9/images/caafc820558645198cf01ef30a27c8cb/f39e736f6abf45ae9f8d8cc36bf2287b.qcow',
                                'ident': 'e26d469412ef464ea22fcc5f39a00dce'}
                        ],
                        'nbd_type': 'gznbd'  # gznbd or nbdrw,
                        'scsi_id': xxxxx
                    }
                ],
                'qcow_files': {
                    {
                        'base': '/home/kvm_rpc/Clerware-7-x86_64-1611.mini.loader.qcow2',
                        'new': '/tmp/tmp_qcow/mtest.qcow2',
                        'qcow_type': 'with_base' #
                    }
                }
            },
            'mount_file_system_params': {
                'mount_root': 'some root',
                'read_only': True,
                'others'
            },
            'samba_params': {
                'username': 'zbtest',
                'userpwd': '123456',
                'hostname': 'e26d469412ef464ea22fcc5f39a00dce',
                'read_only': True
            },
            'sync_params': {
                'target_dir': '',  # 同步目标的目录, 每次任务不同   ClwData201907031423
            }
        }
        """
        self._backup_params = backup_params
        super(FileSync, self).__init__(name='FileSync_{}'.format(self._backup_params['name']))
        self.name = 'FileSync_{}'.format(self._backup_params['name'])
        self.logger = LoggerAdapter(_logger, {'prefix': self.name})
        self._share_logic = None
        self.error = None
        self._helper = None
        self._proxy = None
        self._has_sync_files = False
        self._deploy_mod = self._backup_params.get('deploy_mod', os.path.exists('/dev/shm/db_backup_deploy'))

        self._in_stopping = False
        self._in_stopping_locker = threading.RLock()
        self._quit_flag = False
        self._quit_flag_locker = threading.RLock()
        self._guest_ip = None
        self._samba_user = None
        self._samba_mount_handle = None

    def run(self):
        self.logger.info('start logic, {}'.format(self._backup_params))
        try:
            self._do_work()
        finally:
            self.logger.info('end logic, {}'.format(self._backup_params))

    def _do_work(self):
        try:
            self.logger.debug("========================samba===============================")
            self._share_logic = samba.AddShareLogic(self._backup_params['kvm_used_params'],
                                                    self._backup_params['mount_file_system_params'],
                                                    self._backup_params['samba_params'],
                                                    check_fun=self.check_quit,
                                                    logger=self.logger)
            self.logger.debug("========================_share_logic===============================")
            self._share_logic.share()
            self.logger.debug("========================get_ip_and_mac===============================")
            self._guest_ip, _ = self._share_logic.get_ip_and_mac()
            self.logger.debug("========================get_proxy===============================")
            self._proxy = self._share_logic.get_proxy()
            self._report_info({'status': ('启动远端代理', 'notify_remote_connect')})
            self.logger.debug("========================_notify_remote_connect_begin===============================")
            self._notify_remote_connect_begin(self._guest_ip)  # 让远端连入kvm
            self._report_info({'status': ('发送同步指令', 'send sync cmd')})
            self.logger.debug("========================send_sync_command===============================")
            self._send_sync_command()
            self.logger.debug("========================_poll_and_report_sync_status===============================")
            self._poll_and_report_sync_status()
        except Exception as e:
            self.error = e
            self.logger.error(r' failed {}'.format(e), exc_info=True)
            self._pause_in_debug_mod('before _clean_resource_when_failed')
            self.logger.debug("========================_clean!!!!!!!!!!===============================")
        finally:
            self.logger.debug("========================_clean_resource===============================")
            self._clean_resource()
            self.logger.debug("========================_report_finish===============================")
            self._report_finish(self._is_task_successful())

    def _mount_file_system_2(self):
        pass

    def _clean_resource(self):
        if self._share_logic:
            self._share_logic.end()
            self._share_logic = None

    @xlogging.convert_exception_to_value(None)
    def _pause_in_debug_mod(self, msg):
        if not os.path.exists(DB_BACKUP_DEBUG_FILE):
            return
        file_name = '/tmp/pause_db_backup_{}'.format(time.time())
        with open(file_name, 'w'):
            pass
        while os.path.exists(file_name):
            self.logger.warning('{} pause until {} removed!'.format(msg, file_name))
            time.sleep(5)

    def _notify_remote_connect_begin(self, _guest_ip):
        master_ident = self._backup_params['target_host_ident']
        if os.path.exists('/dev/shm/_tmp_fsync001'):
            app_path, work_dir = 'd:\\Python36\\python.exe', 'd:\\code\\agent_application'
        else:
            app_path = '|current|\\Python36\\python.exe'
            work_dir = '|current|\\agent_application'

        flag_path = 'app_outs.txt'
        event_name = 'Global\\FileSyncEvent{}'.format(self._backup_params['task_uuid'])
        app_params = ('{script_path}'
                      ' --without_agent'
                      ' --aio_ip {aio_ip}'
                      ' --ip_in_kvm {kvm_ip}'
                      ' --flag_path {flag_path}'
                      ' --ident {ident}'
                      ' --event_name {event_name}').format(
            script_path='application_main.py',
            aio_ip=self._backup_params['sync_params']['aio_ip'],
            kvm_ip=_guest_ip,
            flag_path=flag_path,
            ident=self._backup_params['task_uuid'],
            event_name=event_name
        )
        data = {
            'exec_and_wait': {
                'app_path': app_path,
                'params': app_params,
                'work_dir': work_dir,
                'output_path': flag_path,
                'event_name': event_name
            }
        }
        data = json.dumps(data)
        self.logger.info('begin _notify_remote_connect {} {}'.format(master_ident, data))
        count = 120  # 1分钟
        while count > 0:
            self.check_quit()
            try:
                logicService.JsonFunc(master_ident, data)
            except Exception as e:
                if count % 2 == 0:
                    _logger.error('_notify_remote_connect_begin JsonFuncV2 error:{}'.format(e), exc_info=True)
                time.sleep(5)
                count -= 1
            else:
                break
        else:
            xlogging.raise_system_error('启动远端备份代理程序失败',
                                        '_notify_remote_connect_begin failed:{}'.format(data),
                                        1140, self.logger)
        # self._pause_in_debug_mod('等待远端客户端连入(kvm ip {})'.format(_guest_ip))
        self.logger.info('end _notify_remote_connect {}'.format(data))

    @xlogging.convert_exception_to_value(None)
    def _notify_remote_connect_end(self):
        data = json.dumps({'type': 'stop_kvm_channel'})
        master_ident = self._backup_params['target_host_ident']
        try:
            logicService.JsonFuncV2(master_ident, data, bytes())
        except Exception as e:
            _logger.warning('_notify_remote_connect_end error:{}'.format(e))

    def _waite_kvm(self):
        while True:
            self.check_quit()
            if self._share_logic and self._share_logic.is_active():
                time.sleep(10)
                continue
            else:
                break
        if self._share_logic:
            self._share_logic.join()
            self._share_logic = None

    def _send_sync_command(self):
        """
        args_dict = {
            'samba_params':{
                'username':'test',
                'password':'f',
                'root_url':'\\172.16.1.3\share\aio',
                'drive_letter_and_sub_url_list':[['Y', r'\\172.16.1.3\share\aio\目录y']],
            },
            'vdisks':[{
                'file_vhd':'Y:\\d1\d2.vhdx',
                'part_num_and_drive_letter_list':[[3, 'D']]
            }],
            'sync_source':['D:\\d1\file1.txt', 'D:\\d1\dir1']
            'sync_destination': 'd:\\clw20190708\'
        }
        """
        args_dict = dict()
        self._generate_samba_params(args_dict)
        args_dict['ident'] = self._backup_params['task_uuid']
        args_dict['vdisks'] = self._backup_params['sync_params']['vdisks']
        args_dict['sync_source'] = self._backup_params['sync_params']['sync_source']
        args_dict['sync_destination'] = self._backup_params['sync_params']['sync_destination']
        args_dict['in_debug_mod'] = os.path.exists(DB_BACKUP_DEBUG_FILE)

        self.logger.info('_send_sync_command {}'.format(args_dict))
        self._helper = remote_helper.ModuleMapper('file_sync_logic_local', 'MainLogic', self._proxy, self.logger,
                                                  args_dict)
        self._helper.execute('start_sync')

    def _generate_samba_params(self, args_dict):
        def _fill_partition_info():
            v_name = partition['VolumeLabel']
            l_name = partition['Letter']
            if v_name and l_name:
                _letter2name[l_name.upper()] = self.get_name(partition)

        args_dict['samba_params'] = {
            'username': self._backup_params['samba_params']['username'],
            'password': self._backup_params['samba_params']['userpwd'],
            'root_url': r'\\{}\{}\{}'.format(self._backup_params['sync_params']['aio_ip'],
                                             self._backup_params['samba_params']['username'],
                                             self._backup_params['samba_params']['hostname']),
            'drive_letter_and_sub_url_list': list()
        }
        _letter2name = dict()  # 获取所有需要的卷标

        for include_range in self._backup_params['mount_file_system_params']['include_ranges']:  # todo 支持linux
            for partition in include_range['ranges']:
                _fill_partition_info()
        for partition in self._backup_params['mount_file_system_params']['windows_volumes']:
            _fill_partition_info()

        for letter, vol_name in _letter2name.items():
            if letter == 'C':
                letter = 'Z'
            args_dict['samba_params']['drive_letter_and_sub_url_list'].append(
                (letter, args_dict['samba_params']['root_url'] + '\\' + vol_name)
            )

    @staticmethod
    def get_name(partition):
        v_name = partition['VolumeLabel']
        l_name = partition['Letter']
        if v_name and l_name:
            return "{}({})".format(v_name, l_name)
        elif v_name:
            return "{}".format(v_name)
        elif l_name:
            return "{}".format(l_name)
        else:
            return 'volume{}'.format(uuid.uuid4().hex)

    def _is_task_successful(self):
        if not self._has_sync_files:  # 自动模式下，没有同步文件，认为任务失败
            return False
        else:
            return True

    def _report_finish(self, successful):
        self._report_info({'status': ('report_finish', 'report_finish'), 'successful': successful})

    def _report_info(self, payload):
        self.logger.debug('_report_info {}'.format(payload))
        task_type, task_uuid = 'file_sync', self._backup_params['task_uuid']
        ret = hostSession.http_report_task_status(task_type, task_uuid, payload)
        assert ret['rev'] == 0

    def _poll_and_report_sync_status(self):
        while True:
            self._check_nbd_and_kvm()
            time.sleep(10)
            try:
                status_str, _ = self._helper.execute('poll')
            except Exception as e:
                self.logger.warning('poll status error:{}'.format(e))
                continue
            status = json.loads(status_str)
            if (not self._has_sync_files) and int(status['progressIndex']) > 0:  # 更新self._has_sync_files  字段
                self._has_sync_files = True
            if status['finished']:
                if status['successful']:
                    self._has_sync_files = True
                    self._pause_in_debug_mod('任务成功了^_^o')
                    return
                else:
                    error_msg = status['error_msg']
                    if error_msg and len(error_msg) == 3:
                        xlogging.raise_system_error(error_msg[0], error_msg[1], error_msg[2])
                    xlogging.raise_system_error('备份失败', 'unknown error', 2525)
            self._report_info(status)

    def _check_nbd_and_kvm(self):
        if not self._share_logic.nbd_alive():
            xlogging.raise_system_error('nbd组件异常退出', 'nbd not alive', 143)
        if not self._share_logic.kvm_alive():
            xlogging.raise_system_error('代理虚拟机异常退出', 'kvm not alive', 145)
        return True

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
                with self._quit_flag_locker:
                    self._quit_flag = True
            else:
                self.logger.warning('not alive, skip cancel')
        finally:
            with self._in_stopping_locker:
                self._in_stopping = False

    def check_quit(self):
        with self._quit_flag_locker:
            if self._quit_flag:
                xlogging.raise_system_error(r'用户取消操作', 'self._quit', 1, logger=self.logger)


class FileBackupManager(object):

    def __init__(self):
        self._instance = dict()
        self._locker = threading.RLock()

    def new(self, key, params):
        global dynamic_config_path
        params.update({'dynamic_config_path': dynamic_config_path})
        task_type = params.pop('task_type', 'file_backup')
        ins = self._fetch(key)
        if ins:
            _logger.warning('FileBackupManager new fail, key:{} is already in'.format(key))
        else:
            with self._locker:
                if task_type == 'file_backup':
                    t = FileBackup(params)
                elif task_type == 'db_backup':
                    t = DBBackup(params)
                elif task_type == 'file_sync':
                    t = FileSync(params)
                else:
                    xlogging.raise_system_error('未知的任务类型', 'unknown task type', 436)
                    return
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

    def end_transfer_data(self, key, params):
        ins = self._fetch(key)
        if not ins:
            return
        ins.end_transfer_data()

    def set_nas_dynamic_params(self, key, params):
        ins = self._fetch(key)
        if not ins:
            return None
        return ins.set_nas_dynamic_params(params)

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


file_backup_mgr = FileBackupManager()

if __name__ == '__main__':
    import logging
    import nbd
    import Ice
    import logicService
    import sys

    nbd.init(100)

    initData = Ice.InitializationData()
    initData.properties = Ice.createProperties()
    initData.properties.setProperty(r'Ice.LogFile', r'/var/log/aio/logic_service_ice.log')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.Size', r'8')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.SizeMax', r'64')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.StackSize', r'8388608')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.Size', r'8')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.SizeMax', r'64')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.StackSize', r'8388608')
    initData.properties.setProperty(r'Ice.Default.Host', r'localhost')
    initData.properties.setProperty(r'Ice.Warn.Connections', r'1')
    initData.properties.setProperty(r'Ice.ACM.Heartbeat', r'3')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.ThreadIdleTime', r'0')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.ThreadIdleTime', r'0')

    _communicator = Ice.initialize(sys.argv, initData)
    logicService._g = type('X', (object,), {'communicator': _communicator})
    backup_params = {
        'name': '任务名称',
        'task_uuid': 'e26d469412ef464ea22fcc5f39a00dce',
        'kvm_used_params': {  # 启动kvm使用的参数
            'logic': 'linux',
            'disk_ctl_type': 'scsi-hd',
            'aio_server_ip': '172.29.16.2',
            'ip_prefix': '172.29.140',
            'tap_name_prefix': 'filesync',
            'disksnapshots': [
                {
                    'images': [
                        {
                            'path': '/home/mnt/nodes/b7f1e05d286d4aad933fd49ff8eeceb9/images/caafc820558645198cf01ef30a27c8cb/f39e736f6abf45ae9f8d8cc36bf2287b.qcow',
                            'ident': 'e26d469412ef464ea22fcc5f39a00dce'}
                    ],
                    'nbd_type': 'gznbd',
                    'scsi_id': 'e26d469412ef464ea22fcc5f39a00dce'
                }
            ],
            'qcow_files': [
                {
                    'base': '/home/kvm_rpc/Clerware-7-x86_64-1611.mini.loader.qcow2',
                    'new': '/tmp/tmp_qcow/mtest.qcow2',
                    'qcow_type': 'with_base'
                }
            ]
        },
        'samba_params': {
            'username': 'zbtest',
            'userpwd': '123456',
            'hostname': 'e26d469412ef464ea22fcc5f39a00dce',
            'read_only': True
        },
        'mount_file_system_params': {
            'read_only': True,
            "windows_volumes": [
                {
                    "Letter": "C",
                    "Extents": [
                        {
                            "ExtentLength": "42947575808",
                            "DiskNumber": "0",
                            "StartingOffset": "1048576"
                        }
                    ],
                    "FreeBytesAvailable": "25185017856",
                    "VolumeName": "\\\\\\\\?\\\\Volume{a4156760-8d1b-11e7-a8a2-806e6f6e6963}\\\\",
                    "mountpoints": [],
                    "TotalNumberOfFreeBytes": "25185017856",
                    "VolumeSerialNumber": "2726297047",
                    "FileSystem": "NTFS",
                    "VolumeLabel": "SVR2008",
                    "TotalNumberOfBytes": "42947571712"
                }
            ],
            "include_ranges": [
                {
                    "ranges": [
                        {
                            "Letter": "C",
                            "Style": "mbr",
                            "FileSystem": "NTFS",
                            "VolumeName": "\\\\\\\\?\\\\Volume{a4156760-8d1b-11e7-a8a2-806e6f6e6963}\\\\",
                            "PartitionOffset": "1048576",
                            "VolumeSize": "42947571712",
                            "FreeSize": "25185017856",
                            "VolumeLabel": "SVR2008",
                            "Index": "1",
                            "PartitionSize": "42947575808"
                        }
                    ],
                    "diskIndex": 0,
                    "diskSnapshot": "e26d469412ef464ea22fcc5f39a00dce",
                    "diskIdent": "35b9cfd12c504ae9aaeb7509cd896466",
                    "diskNativeGUID": "{B407C1D1-0000-0000-0000-000000000000}"
                }
            ],
            "linux_storage": "",
            "ostype": "windows",
            "disklist": [
                {
                    "diskid": 0,
                    'nbd_uuid': 'e26d469412ef464ea22fcc5f39a00dce'
                }
            ]
        },
        'sync_file_params': {
            'target_dir': '',  # 同步目标的目录, 每次任务不同   ClwData201907031423
        }
    }
    file_sync_ins = FileSync(backup_params)
    file_sync_ins.setDaemon(True)
    file_sync_ins.start()
    file_sync_ins.join()
