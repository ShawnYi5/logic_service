import json
import os
import threading
import time
from datetime import datetime
import logicService
import xlogging

_logger = xlogging.getLogger(__name__)

import CustomizedOS


class KVMServerHelper(object):
    def __init__(self, name, logger, logic):
        self._quit = False
        self.name = name
        self.logger = logger
        self._prx = None
        self._loader_prx = None
        self._logic = logic
        if self._logic == 'windows':
            self.patch_dir = r'%SYSTEMDRIVE%\patch'
        else:
            self.patch_dir = '/home/patch'
        xlogging.TraceDecorator(logger=self.logger).decorate()
        self._ip = None

    def _get_loader_prx(self, ip=None):
        if self._loader_prx is None and ip:
            self._loader_prx = CustomizedOS.MiniLoaderPrx.checkedCast(
                logicService.get_communicator().stringToProxy('loader : tcp -h {} -p 10000'.format(ip)))
        assert self._loader_prx
        return self._loader_prx

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
        self._check_connct(ip, timeout_seconds, self._get_loader_prx, True)
        self._ip = ip

    def create_patch_dir(self):
        if self._logic == 'windows':
            cmd = r'rd /s /q {}'.format(self.patch_dir)
        else:
            cmd = 'rm -rf ' + self.patch_dir + '/*'
        try:
            rc = json.loads(self._get_loader_prx().popen(json.dumps({
                'async': False, 'shell': True, 'cmd': cmd, 'work_dir': None, 'timeouts_seconds': 60 * 2
            })))
            self.logger.info(r'create_patch_dir {} rc : {}'.format(cmd, rc))
        except Exception as e:
            self.logger.info('create_patch_dir cmd={},e={}'.format(cmd, e))

        if self._logic == 'windows':
            cmd = r'md {}'.format(self.patch_dir)
        else:
            cmd = 'todo'
        try:
            rc = json.loads(self._get_loader_prx().popen(json.dumps({
                'async': False, 'shell': True, 'cmd': cmd, 'work_dir': None, 'timeouts_seconds': 60 * 2
            })))
            self.logger.info(r'create_patch_dir {} rc : {}'.format(cmd, rc))
        except Exception as e:
            self.logger.info('create_patch_dir cmd={},e={}'.format(cmd, e))

    def fetch_patch(self, ip_address):
        self.create_patch_dir()
        if self._logic == 'windows':
            icepatch2client = r'%SYSTEMDRIVE%\icepatch2\icepatch2client'
        else:
            icepatch2client = r'/usr/bin/icepatch2client'
        cmd = r'{icepatch2client} -t' \
              r' --IcePatch2Client.Proxy="IcePatch2/server:tcp -h {ip_address} -p 20090"' \
              r' {patch_dir}'.format(icepatch2client=icepatch2client, ip_address=ip_address, patch_dir=self.patch_dir)

        self.logger.info('fetch_patch cmd : {}'.format(cmd))
        try:
            json.loads(self._get_loader_prx().popen(json.dumps({
                'async': False, 'shell': True, 'cmd': cmd, 'work_dir': None, 'timeouts_seconds': 60 * 2
            })))
        except Exception as e:
            self.logger.info('fetch_patch Failed. cmd={},e={}'.format(cmd, e))
            xlogging.raise_system_error(r'配置备份代理失败', 'fetch_patch {}'.format(e), 1, logger=self.logger)
            raise

    @xlogging.convert_exception_to_value(None)
    def run_on_remote(self, cmd, work_dir=None, timeouts=None):
        rc = json.loads(self._get_loader_prx().popen(json.dumps({
            'async': False, 'shell': True, 'cmd': cmd, 'work_dir': work_dir, 'timeouts_seconds': timeouts
        })))
        return rc

    @xlogging.convert_exception_to_value(False)
    def shutdown(self):
        if self._logic == 'windows':
            cmd = 'start wpeutil shutdown'
        else:
            # shutdown之前的命令是用来清除缓存的
            cmd = 'sync && echo 3 > /proc/sys/vm/drop_caches;shutdown -h now'
        self._get_loader_prx().popen(json.dumps({
            'async': False, 'shell': True, 'cmd': cmd, 'work_dir': None, 'timeouts_seconds': None
        }))

    def _rw_file_in_kvm(self, inputJson, inputBs=None):
        r, b = self._get_loader_prx().rwFile(json.dumps(inputJson), inputBs)
        return json.loads(r), b
