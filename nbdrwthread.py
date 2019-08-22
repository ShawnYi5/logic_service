import threading

import nbd
import xlogging

_logger = xlogging.getLogger(__name__)


# 这个类负责挂载一个可以自动建立快照的nbd.，即nbdrw的功能说明。
# 一个实例只支持一个硬盘。


class NbdReadWriteThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.__mount_cmd = None
        self.__umount_cmd = None
        self.new_nbd = nbd.nbd_wrapper(nbd.nbd_wrapper_disable_lvm_allocator(nbd.nbd_wrapper_local_device_allocator()))
        self.device_path = self.new_nbd.device_path
        self.scsi_id = None
        _logger.debug('nbd init,device_path {}'.format(self.device_path))

    def run(self):
        try:
            self.new_nbd.mount_with_input_cmd(self.__mount_cmd, self.__umount_cmd)
            _logger.info("cmd {} exit".format(self.__mount_cmd))
        except Exception as e:
            _logger.error("cmd {} except {}".format(self.__mount_cmd, e), exc_info=True)
        finally:
            self.new_nbd.is_thread_alive = False

    def set_scsi_id(self, scsi_id):
        self.scsi_id = scsi_id

    def start_and_wait_ready(self, mount_cmd, umount_cmd):
        self.__mount_cmd = mount_cmd
        self.__umount_cmd = umount_cmd

        self.new_nbd.is_thread_alive = True

        try:
            super(NbdReadWriteThread, self).start()
        except Exception as e:
            _logger.error(r'!!!~~!!! start thread failed {}'.format(e), exc_info=True)
            self.new_nbd.is_thread_alive = False
            raise

        try:
            nbd.nbd_wrapper.wait_nbd_read_ok(self.new_nbd)
        except Exception as e:
            _logger.error('NbdThread cmd {} Exception:{}'.format(self.__mount_cmd, e))
            raise

    def get_nbd_number(self):
        _nbd_number = self.device_path.replace(r'/dev/nbd', r'')
        _nbd_number.strip()
        if len(_nbd_number) > 0:
            return int(_nbd_number)
        return 999

    def get_nbd_device_name(self):
        return self.device_path, self.get_nbd_number()

    def join(self, timeout=None):
        self.new_nbd.wait_no_mounting()
        self.new_nbd.set_no_longer_used()
        self.new_nbd = None
        _logger.info("nbd: {} umount".format(self.device_path))

    def umount(self):
        self.new_nbd.unmount()


if __name__ == '__main__':
    # NbdReadWriteThread
    pass
