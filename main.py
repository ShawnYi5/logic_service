import logicService
import net_base
import samba
import xdebug
import xlogging
import kvm
import net_common
import psutil

_logger = xlogging.getLogger(__name__)
_x_debug_helper = None


def _start_x_debug_helper():
    global _x_debug_helper
    _x_debug_helper = xdebug.XDebugHelper()
    _x_debug_helper.setDaemon(True)
    _x_debug_helper.start()


def _net_base_init():
    retval = net_base.net_init()
    if retval != 0:
        _logger.error('net init failed,ret value {}'.format(retval))


def _kill_exceptional_kvm():
    kvm.kvm_max_minutes_worker = kvm.kvm_max_minutes()
    kvm.kvm_max_minutes_worker.setDaemon(True)
    kvm.kvm_max_minutes_worker.start()


@xlogging.convert_exception_to_value(None)
def _del_tap():
    info = psutil.net_if_addrs()
    for k, v in info.items():
        if k.startswith('db') or k.startswith('filesync'):  # 数据库相关的tap口
            net_common.get_info_from_syscmd('ip link del {}'.format(k), 10)


_start_x_debug_helper()

_net_base_init()

samba.smb_init()

_kill_exceptional_kvm()

_del_tap()

logicService.run()
