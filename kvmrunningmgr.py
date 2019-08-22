import os
import subprocess
import time
import shlex

import all_big_mm
import xlogging
import kvmcmdmgr
import threading

_logger = xlogging.getLogger(__name__)


class KvmRunningThread(object):

    def __init__(self, kvm_cmd_mgr):
        self.__kvm_cmd_mgr = kvm_cmd_mgr
        self._process = None

    def join(self):
        _logger.info('KvmRunningThread start join _process:{}'.format(self._process))
        if self._process:
            code = self._process.returncode
            stdout, stderr = self._process.communicate()
            _logger.info('KvmRunningThread join exit code:{} stdout:{}, stderr:{}'.format(code, stdout, stderr))
        else:
            _logger.info('KvmRunningThread join exit NO process!!')
            code = None
            stdout, stderr = None, None
        return code, stdout, stderr

    def start(self):
        self._run_kvm()

    def _run_kvm(self):

        kvm_cmd = self.__kvm_cmd_mgr.generate_kvm_cmd_line()

        alloc_success = False
        while not alloc_success:
            alloc_success = all_big_mm.CAllocBigMM.try_alloc(self.__kvm_cmd_mgr.get_memory_mbyte())
            if not alloc_success:
                _logger.warning(r'alloc mem for kvm failed,will retry')

        if self.__kvm_cmd_mgr.is_aio_sys_vt_valid():
            cwd = None
        else:
            cwd = r'/sbin/aio/qemu-nokvm'  # 非vt下需要指定工作路径 否则出错

        # shlex.split(kvm_cmd)
        # use exec will not create two process
        self._process = subprocess.Popen('exec ' + kvm_cmd, cwd=cwd, shell=True, stderr=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         universal_newlines=True)
        if self._process.poll() is None:
            _logger.info('KvmHandle start kvm PID:{} {}'.format(self._process.pid, kvm_cmd))
        else:
            msg = 'start kvm error {}|{}|{}'.format(self._process.returncode, *self._process.communicate())
            xlogging.raise_system_error('启动虚拟机失败', msg, 1111)

    def is_active(self):
        return self._process and (self._process.poll() is None)

    # def end(self):
    def kill(self):
        _logger.info('KvmRunningThread start kill:{}'.format(self._process))
        while self._process and (self._process.poll() is None):
            _logger.info('KvmRunningThread kill {} {}'.format(self._process.pid, 9))
            os.kill(self._process.pid, 9)
            time.sleep(1)


if __name__ == "__main__":
    pass
