import json
import os
import threading
import time
from datetime import datetime

import logicService
import xlogging

_logger = xlogging.getLogger(__name__)

import FileBackup
import CustomizedOS

MSG_MAP = {
    'mount_nas': '发送挂载NAS目录指令失败',
    'mount_backup': '发送备份准备指令失败',
    'umount_backup': '发送备份校验指令失败',
    'backup': '发送备份指令失败',
    'cancle_backup': '发送取消备份指令失败',
    'query_backup_status': '查询备份进度失败',
    'config_gateway': '配置备份代理网络参数失败',
    'fetch_patch': '配置备份代理失败',
    'start_logic': '启动备份代理失败',
}


class FileBackupHelper(object):
    def __init__(self, name, logger):
        self._quit = False
        self.name = name
        self.logger = logger
        self._prx = None
        self._loader_prx = None
        xlogging.TraceDecorator(logger=self.logger).decorate()
        xlogging.IceExceptionToSystemErrorDecorator(MSG_MAP, logger=self.logger).decorate()
        self._nas_mounted = False
        self._backup_mounted = False
        self._backup_logic_running = False
        self._ip = None
        self._locker = threading.Lock()

    def _set_flag_with_lock(self, flag_name):
        with self._locker:
            setattr(self, flag_name, True)

    def _get_and_clean_flag(self, flag_name):
        with self._locker:
            v = getattr(self, flag_name)
            if v:
                setattr(self, flag_name, False)
                return True
            else:
                return False

    def _get_flag(self, flag_name):
        with self._locker:
            return getattr(self, flag_name)

    def _get_loader_prx(self, ip=None):
        if self._loader_prx is None and ip:
            self._loader_prx = CustomizedOS.MiniLoaderPrx.checkedCast(
                logicService.get_communicator().stringToProxy('loader : tcp -h {} -p 10000'.format(ip)))
        assert self._loader_prx
        return self._loader_prx

    def _get_prx(self, ip=None):
        if self._prx is None and ip:
            self._prx = FileBackup.LogicPrx.checkedCast(
                logicService.get_communicator().stringToProxy('fileBackupLogic : tcp -h {} -p 21201'.format(ip)))
        assert self._prx
        return self._prx

    def _check_connct(self, ip, timeout_seconds, check_fn, change_name):
        end_time = time.time() + timeout_seconds
        last_e = None
        loop_count = 1

        while time.time() < end_time:
            loop_count += 1
            time.sleep(1)
            try:
                check_fn(ip)
                if change_name:
                    self.name = '{} {}'.format(self.name, ip)
                return
            except Exception as e:
                last_e = r'{} connect {} failed {} will retry : {}'.format(self.name, ip, e,
                                                                           int(end_time - time.time()))
                if loop_count % 10 == 0:
                    self.logger.debug(last_e)

        xlogging.raise_system_error(r'启动备份代理超时', last_e, 1, logger=self.logger)

    def connect(self, ip, timeout_seconds):
        self._check_quit()
        self._check_connct(ip, timeout_seconds, self._get_loader_prx, True)
        self._ip = ip

    def config_gateway(self):
        self._check_quit()
        prx = self._get_loader_prx()
        connection = prx.ice_getConnection()
        connection_info = connection.getInfo()
        ip_address = connection_info.localAddress

        cmd = 'ip route del default ; ip route add default via {}'.format(ip_address)
        self.logger.info('config_gateway cmd : {}'.format(cmd))
        try:
            rc = json.loads(prx.popen(json.dumps({
                'async': False, 'shell': True, 'cmd': cmd, 'work_dir': None, 'timeouts_seconds': 60 * 2
            })))
        except Exception as e:
            xlogging.raise_system_error(r'配置备份代理网络参数失败', 'config_gateway {}'.format(e), 1, logger=self.logger)
            raise  # fix pycharm warn

        logger_msg = r'config_gateway rc : {}'.format(rc)
        if rc['returned_code'] != 0:
            xlogging.raise_system_error(r'配置备份代理网络参数失败', logger_msg, 1, logger=self.logger)
        else:
            self.logger.info(logger_msg)

        return ip_address

    def fetch_patch(self, ip_address):
        self._check_quit()
        runner_dir = '/opt/runner'
        cmd = r'mkdir -p {runner_dir} ; cd {runner_dir} ; ' \
              r'/usr/bin/icepatch2client -t' \
              r' --IcePatch2Client.Proxy="IcePatch2/server:tcp -h {ip_address} -p 20090"' \
              r' .'.format(ip_address=ip_address, runner_dir=runner_dir)

        self.logger.info('fetch_patch cmd : {}'.format(cmd))
        try:
            rc = json.loads(self._get_loader_prx().popen(json.dumps({
                'async': False, 'shell': True, 'cmd': cmd, 'work_dir': None, 'timeouts_seconds': 60 * 2
            })))
        except Exception as e:
            xlogging.raise_system_error(r'配置备份代理失败', 'fetch_patch {}'.format(e), 1, logger=self.logger)
            raise  # fix pycharm warn

        logger_msg = r'fetch_patch rc : {}'.format(rc)

        if rc['returned_code'] != 0:
            xlogging.raise_system_error(r'配置备份代理失败', logger_msg, 1, logger=self.logger)
        else:
            self.logger.info(logger_msg)

        return runner_dir

    def start_logic(self, ip, timeout_seconds, runner_dir):
        self._check_quit()
        work_dir = os.path.join(runner_dir, 'FileBackupLogic')
        cmd = r'/usr/bin/python3 FileBackupLogicMain.py'
        self.logger.info('fetch_patch cmd : {}       work_dir : {}'.format(cmd, work_dir))

        try:
            rc = json.loads(self._get_loader_prx().popen(json.dumps({
                'async': True, 'shell': False, 'cmd': cmd, 'work_dir': work_dir, 'timeouts_seconds': None
            })))
        except Exception as e:
            xlogging.raise_system_error(r'启动备份代理失败', 'start_logic {}'.format(e), 1, logger=self.logger)
            raise  # fix pycharm warn

        logger_msg = r'start_logic rc : {}'.format(rc)
        if not rc['pid']:
            xlogging.raise_system_error(r'启动备份代理失败', logger_msg, 1, logger=self.logger)
        else:
            self.logger.info(logger_msg)

        self._check_connct(ip, timeout_seconds, self._get_prx, False)
        self._set_flag_with_lock('_backup_logic_running')

    def begin_dropcache(self):
        self._check_quit()
        cmd = r'while : ;do echo 3 > /proc/sys/vm/drop_caches; sleep 8h; done;'
        try:
            rc = json.loads(self._get_loader_prx().popen(json.dumps({
                'async': True, 'shell': True, 'cmd': cmd, 'work_dir': None, 'timeouts_seconds': None
            })))
        except Exception as e:
            self.logger.error(r'begin_dropcache failed : {}'.format(e), exc_info=True)
            return
        self.logger.info(r'begin_dropcache rc : {}'.format(rc))

    def mount_nas(self, params):
        self._check_quit()
        self._get_prx().MountNas(json.dumps(params))
        self._set_flag_with_lock('_nas_mounted')

    @xlogging.convert_exception_to_value(False)
    def umount_nas(self, params):
        if self._get_and_clean_flag('_nas_mounted'):  # always call umount once
            return self._get_prx().UmountNas(json.dumps(params))
        else:
            self.logger.info('nas NOT mounted. skip umount_nas')

    def mount_backup(self, params):
        self._check_quit()
        self._get_prx().MountBackup(json.dumps(params))
        self._set_flag_with_lock('_backup_mounted')

    @xlogging.convert_exception_to_value(None)
    def run_on_remote(self, cmd, work_dir=None, timeouts=None):
        self._get_loader_prx().popen(json.dumps({
            'async': False, 'shell': True, 'cmd': cmd, 'work_dir': work_dir, 'timeouts_seconds': timeouts
        }))

    def umount_backup(self, params):
        if self._get_and_clean_flag('_backup_mounted'):  # always call umount once
            if os.path.exists(r'/dev/shm/file_backup_log'):
                file_name = time.strftime("%Y-%m-%d-%H_%M_%S.tgz", time.localtime(time.time()))
                dir_path = '/mnt/backup/clw'
                self.run_on_remote(r'mkdir -p "{}"'.format(dir_path))
                self.run_on_remote(r'tar zcf "{}" /var/log/*'.format(os.path.join(dir_path, file_name)))
                self.run_on_remote(r'sync')
            self._get_prx().UmountBackup(json.dumps(params))
        else:
            self.logger.info('backup NOT mounted. skip umount_backup')

    def backup(self, params):
        try:
            self._check_quit()
            self._get_prx().Backup(json.dumps(params))
            self._check_quit()
        except Exception as e:
            self.debug_when_backup_failed(e)
            raise

    def debug_when_backup_failed(self, e):
        if os.path.exists(r'/dev/shm/file_backup_pause_when_failed'):
            loop_number = 0
            pause_dir_path = r'/dev/shm/file_backup_pause_' + self._ip
            os.makedirs(pause_dir_path, exist_ok=True)
            while os.path.exists(pause_dir_path):
                if loop_number % 60 == 0:
                    self.logger.info('backup failed {}.\n    pause until rm {}'.format(e, pause_dir_path))
                loop_number += 1
                time.sleep(1)

    def set_quit(self):
        with self._locker:
            self._quit = True

    def _check_quit(self):
        with self._locker:
            if self._quit:
                xlogging.raise_system_error(r'用户取消操作', 'self._quit', 1, logger=self.logger)

    def cancle_backup(self, params):
        if self._get_flag('_backup_logic_running'):
            return self._get_prx().CancleBackup(json.dumps(params))

    def query_backup_status(self):
        r = self._get_prx().QueryBackupStatus()
        return json.loads(r)

    def _rw_file_in_kvm(self, inputJson, inputBs=None):
        r, b = self._get_loader_prx().rwFile(json.dumps(inputJson), inputBs)
        return json.loads(r), b

    @xlogging.convert_exception_to_value(None)
    def package_log_files_and_fetch(self):
        kvm_log_file = '/tmp/{}'.format(time.time())
        self.run_on_remote(r'tar -czf "{}" /var/log/clw*'.format(kvm_log_file))
        r_json, _ = self._rw_file_in_kvm({'type': 'get_size', 'path': kvm_log_file})
        total_bytes = int(r_json['Bytes'], 16)

        now = datetime.fromtimestamp(time.time()).strftime('%Y_%m_%d-%H_%M_%S.%f')
        aio_log_dir = '/var/log/aio/file_backup'
        aio_log_path = os.path.join(aio_log_dir, '{}.tar.gz'.format(now))
        os.makedirs(aio_log_dir, exist_ok=True)

        cur_index, chunk_bytes = 0, 1 * 1024 * 1024  # 1MB
        with open(aio_log_path, 'wb') as f:
            while True:
                if cur_index >= total_bytes:
                    break
                elif cur_index + chunk_bytes >= total_bytes:
                    read_bytes = total_bytes - cur_index
                else:
                    read_bytes = chunk_bytes

                _, fetch_data = self._rw_file_in_kvm({
                    'type': 'read_exist', 'path': kvm_log_file,
                    'byteOffset': hex(cur_index), 'bytes': hex(read_bytes)
                })
                f.seek(cur_index)
                f.write(fetch_data)
                cur_index = cur_index + chunk_bytes

        self._nas_kvm_log_throttling()
        _logger.debug('end package_log_files_and_fetch, {}'.format(aio_log_path))

    @xlogging.convert_exception_to_value(False)
    def _nas_kvm_log_throttling(self):
        """
        控制日志数量（50个）、大小（150MB），避免占用过多空间
        """
        remain_bytes, remain_cnt = 150 * 1024 ** 2, 50
        aio_log_dir = '/var/log/aio/file_backup'
        if not os.path.exists(aio_log_dir):
            return

        keep_logs = list()
        logs = [name for name in os.listdir(aio_log_dir) if name.endswith('.tar.gz')]
        logs.sort(reverse=True)
        logs = [os.path.join(aio_log_dir, log) for log in logs]  # abs_path
        for log_path in logs:
            log_size = os.path.getsize(log_path)
            if remain_bytes < log_size:
                break
            if remain_cnt < 1:
                break
            keep_logs.append(log_path)
            remain_bytes = remain_bytes - log_size
            remain_cnt = remain_cnt - 1
        else:
            return

        del_logs = [e for e in logs if e not in keep_logs]
        for log_path in del_logs:
            os.remove(log_path)
        if del_logs:
            _logger.warning('_nas_kvm_log_throttling removed: {}'.format(del_logs))

    @xlogging.convert_exception_to_value(False)
    def shutdown(self):
        if self._get_and_clean_flag('_backup_logic_running'):  # always call once
            while os.path.exists(r'/dev/shm/not_shutdown_file_backup'):
                time.sleep(1)
            return self._get_prx().Shutdown()
        else:
            self.logger.info(r'_backup_logic_running False, skip shutdown')
