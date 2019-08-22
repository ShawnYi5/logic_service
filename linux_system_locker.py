import os
import time

import xlogging

_logger = xlogging.getLogger(__name__)


class LinuxSystemLocker(object):
    """
    系统全局锁
    必须使用with语法调用
    如果timeout>=0，那么可以通过locked属性判断是否进入锁空间
    """
    def __init__(self, filename, timeout=-1, debug_log=True):
        self.__filename = filename
        self.__timeout = timeout
        self.__debug_log = debug_log
        self.locked = False

    def __enter__(self):
        _debug_busy = True
        while True:
            try:
                tfd = os.open(self.__filename, os.O_CREAT | os.O_EXCL)
                os.close(tfd)
                if self.__debug_log:
                    _logger.debug('linux_system_locker({}) lock'.format(self.__filename))
                self.locked = True
                break
            except OSError:
                if self.__debug_log and _debug_busy:
                    _debug_busy = False
                    _logger.debug("linux_system_locker({}) busy!".format(self.__filename))

            if self.__timeout < 0:
                time.sleep(0.01)
                continue

            if self.__timeout >= 0.01:
                self.__timeout -= 0.01
                time.sleep(0.01)
            else:
                _logger.info("linux_system_locker({}) timeout!".format(self.__filename))
                self.locked = False
                break

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.locked:
            self.locked = False
            os.remove(self.__filename)
            if self.__debug_log:
                _logger.debug('linux_system_locker({}) unlock'.format(self.__filename))
