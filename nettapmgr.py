import psutil
import net_common
import xlogging
import copy
import media.filelock

_logger = xlogging.getLogger(__name__)


def _is_adpter_name_exist(name):
    info = psutil.net_if_addrs()
    for k, v in info.items():
        if k == name:
            return True
    return False


class NetTapMgr(object):

    def __init__(self, aio_server_ip, tap_name_prefix, base_ip_addr, mac_address=None):
        self.__aio_server_ip = copy.copy(aio_server_ip)
        self.__tap_name_prefix = copy.copy(tap_name_prefix)
        self.__base_ip_addr = copy.copy(base_ip_addr)
        self.tap_name = None
        self.bond_ip = None
        self._mac_address = mac_address
        pass

    def get_ip_address(self):
        return self.bond_ip

    def get_tap_name(self):
        return self.tap_name

    def get_mac_address(self):
        if self._mac_address:
            return self._mac_address
        split_ip = self.bond_ip.strip().split('.')
        if len(split_ip) != 4:
            raise Exception("split ip address:{} error:{}".format(self.bond_ip, split_ip))

        _mac_address = r'cc:cc:{:02x}:{:02x}:{:02x}:{:02x}'.format(
            int(split_ip[0]), int(split_ip[1]), int(split_ip[2]), int(split_ip[3]))

        return _mac_address

    def start(self):

        _locker = media.filelock.file_ex_lock(r'/run/{}_lock'.format(self.__tap_name_prefix))
        while True:
            if _locker.try_lock():
                break
            _logger.info("tapmgr lock failed")

        try:
            self.tap_name, self.bond_ip = self._get_unused_tap()
            if not self.tap_name:
                xlogging.raise_system_error('网络资源耗尽', 'no more nettap', 125)
            self._create_br()
            self._create_tap()
        except Exception:  # 抛异常不会导致 __del__ 触发
            self.stop()
            raise

    def _create_br(self):
        name = 'takeoverbr0'
        if _is_adpter_name_exist(name):
            return
        net_common.get_info_from_syscmd(r'ip link add takeoverbr0 type bridge')
        # net_common.get_info_from_syscmd(r'ifconfig takeoverbr0 0.0.0.0 promisc up')
        net_common.get_info_from_syscmd(r'ifconfig takeoverbr0 {} up'.format(self.__aio_server_ip))

    def _create_tap(self):
        rev = net_common.get_info_from_syscmd('ip tuntap add {} mode tap'.format(self.tap_name))
        if rev[0] != 0:
            xlogging.raise_system_error('NetTap add tap fail', 'NetTap add tap fail', 131)
        rev = net_common.get_info_from_syscmd('ip link set {} master takeoverbr0'.format(self.tap_name))
        if rev[0] != 0:
            xlogging.raise_system_error('NetTap add tap fail', 'NetTap add tap fail', 132)
        rev = net_common.get_info_from_syscmd('ifconfig {} 0.0.0.0 up'.format(self.tap_name))
        if rev[0] != 0:
            xlogging.raise_system_error('NetTap add tap fail', 'NetTap add tap fail', 133)

    def _get_unused_tap(self):
        for i in range(1, 255):
            name = r'{}{}'.format(self.__tap_name_prefix, i)
            if not _is_adpter_name_exist(name):
                return name, '{}.{}'.format(self.__base_ip_addr, i)
        return None, None

    def stop(self):
        if self.tap_name:
            net_common.get_info_from_syscmd('ip tuntap del {} mode tap'.format(self.tap_name))
            self.tap_name = None

    def __del__(self):
        self.stop()


class NetMacVTapMgr(object):

    def __init__(self, tap_name_prefix, physical_nic_name, mac_address):
        self._tap_name_prefix = tap_name_prefix
        self._physical_nic_name = physical_nic_name
        self._mac_address = mac_address
        self.tap_name = None

    def get_tap_name(self):
        return self.tap_name

    def get_ifindex(self):
        with open(r'/sys/class/net/{macvtap}/ifindex'.format(macvtap=self.get_tap_name()), 'r') as fout:
            ifindex = fout.read()
            ifindex = ifindex.strip()
        return ifindex

    def get_mac_address(self):
        return self._mac_address

    def start(self):

        _locker = media.filelock.file_ex_lock(r'/run/{}_lock'.format(self._tap_name_prefix))
        while True:
            if _locker.try_lock():
                break
            _logger.info("tapmgr lock failed")

        try:
            self.tap_name = self._get_unused_tap()
            if not self.tap_name:
                xlogging.raise_system_error('网络资源耗尽', 'no more macvtap', 126)
            self._create_macvtap()
        except Exception:
            self.stop()
            raise

    def _get_unused_tap(self):
        for i in range(1, 255):
            name = r'{}{}'.format(self._tap_name_prefix, i)
            if not _is_adpter_name_exist(name):
                return name
        return None

    def _create_macvtap(self):
        rev = net_common.get_info_from_syscmd(
            'ip link add link {} name {} address {} type macvtap mode bridge'.format(self._physical_nic_name,
                                                                                     self.tap_name, self._mac_address))
        if rev[0] != 0:
            xlogging.raise_system_error('NetMacVTapMgr add tap fail', 'NetMacVTapMgr add tap fail', 131)
        rev = net_common.get_info_from_syscmd('ip link set dev {} up'.format(self.tap_name))
        if rev[0] != 0:
            xlogging.raise_system_error('NetTap add tap fail', 'NetTap add tap fail', 132)

    def stop(self):
        if self.tap_name:
            net_common.get_info_from_syscmd('ip link del {}'.format(self.tap_name))
            self.tap_name = None

    def __del__(self):
        self.stop()


if __name__ == "__main__":
    _mvtap_mgr = NetMacVTapMgr('macvtap', 'bond0', 'cc:c1:c2:c3:c4:c5')
    _mvtap_mgr.start()
