import os
import re
import threading
import time
import uuid
from copy import deepcopy

import net_common
import xdefine
import xlogging

_logger = xlogging.getLogger(__name__)

lock_all_mount = threading.Lock()
lock_writable_mount = threading.Lock()

_lvm_lv_root = r'/dev/mapper'
_tmp_mount_path = r'/mnt/tmp'
_config_path = r'/etc/aio/logic_service.cfg'


def _get_info_from_syscmd_timeout_very_short(cmd):
    return net_common.get_info_from_syscmd(cmd)


def _get_info_from_syscmd_timeout_short(cmd):
    return net_common.get_info_from_syscmd(cmd, 60 * 5)


def _get_info_from_syscmd_timeout_middle(cmd):
    return net_common.get_info_from_syscmd(cmd, 60 * 15)


def _get_info_from_syscmd_timeout_long(cmd):
    return net_common.get_info_from_syscmd(cmd, 60 * 30)


class MountNbdLinux(object):
    # nbds = [{'snapshot_disk_index': 0, 'device_path': '/dev/nbd9'},
    #         {'snapshot_disk_index': 1, 'device_path'： '/dev/nbd10'}]
    #      snapshot_disk_index 为备份时候的磁盘序号
    # storage
    #       来自系统信息中"Storage"字段
    # mount_dir = '/mnt/share/xxxxx'
    #       mount的目标文件夹，调用者保证可用，析构时不删除
    # read_only = true
    #       是否只读，注意：只读mount可同时存在多个，可写mount将仅能同时mount单个，后续请求需要抢夺临界锁
    # include_ranges
    #       来自host_snapshot信息中的“include_ranges”字段
    def __init__(self, nbds, storage, mount_dir, read_only, include_ranges):
        self._nbds = nbds
        self._storage = deepcopy(storage)
        self._mount_dir = mount_dir
        self._read_only = read_only
        self._mounted = False
        self.mount_point = list()
        self._include_ranges = include_ranges
        # self.rescan_partitions()
        self.norm_swap_dev_name = dict()
        self.norm_swap_dev_label = dict()
        self.mnt_opt = 'rw,async,relatime,noatime,nodiratime'
        self.rmv_opt = 'ro'

    def __del__(self):
        self.umount_all()

    @staticmethod
    def is_debug_model():
        if not os.path.exists(_config_path):
            return False
        with open(_config_path, 'rt') as fin:
            return 'Logic.LinuxNbdMount.Logic=debug' in fin.read()

    def rescan_partitions(self):
        # 一体机中不需要加载 lvm信息，但是要加载分区信息，因为修复swap分区需要
        for nbd in self._nbds:
            _get_info_from_syscmd_timeout_short(r'partx -d {}'.format(nbd['device_path']))
            _get_info_from_syscmd_timeout_short(r'partx -a {}'.format(nbd['device_path']))

        _get_info_from_syscmd_timeout_short(r'pvscan --cache')
        _get_info_from_syscmd_timeout_short(r'pvscan')
        _get_info_from_syscmd_timeout_short(r'vgscan --cache')
        _get_info_from_syscmd_timeout_short(r'vgscan')
        _get_info_from_syscmd_timeout_short(r'parted -l')

    def get_nbd_device(self, disk_index):
        for nbd in self._nbds:
            if nbd['snapshot_disk_index'] == disk_index:
                return nbd['device_path']
        return None

    def generate_mount_point(self, path):
        if path == r'/':
            return self._mount_dir
        else:
            return self._mount_dir + path

    def analyze_mount_params(self):
        mount_params = list()
        pvs = list()
        swap_devices = list()
        include_mount_points = list()
        _device2nbd_maps = dict()  # {'device_name':'nbd_device_name'}

        for include_range in self._include_ranges:
            for r in include_range['ranges']:
                if r['MountPoint']:
                    include_mount_points.append(r['MountPoint'])

        for disk in self._storage["disks"]:
            nbd_device = self.get_nbd_device(disk["index"])
            if nbd_device is None:
                continue
            # 整个磁盘是一个PV情况下，没有partitions
            if not disk['partitions']:
                _logger.warning('analyze_mount_params found no partitions, disk:{}'.format(disk))
                _device2nbd_maps[disk['device']] = nbd_device
                continue
            for partition in disk["partitions"]:
                partition_device_path = nbd_device if (partition["device"] == disk["device"]) else \
                    r'{}p{}'.format(nbd_device, partition["index"])
                _device2nbd_maps[partition['device']] = partition_device_path
                mount_point_in_snapshot = partition.get("mountPoint", None)
                if mount_point_in_snapshot and (
                        (not self._read_only) or (mount_point_in_snapshot in include_mount_points)):
                    mount_params.append({
                        'mountPoint': self.generate_mount_point(mount_point_in_snapshot),
                        'device': partition_device_path,
                        'fileSystem': partition["fileSystem"],
                        'btrfsmntopt': partition.get("btrfsmntopt"),
                        'orgmntpoint': mount_point_in_snapshot
                    })
                elif (partition.get("fileSystem", None) is not None) and ('linux-swap' in partition["fileSystem"]):
                    swap_devices.append(partition_device_path)
                    self.norm_swap_dev_name[partition_device_path] = partition['device']
                else:
                    _logger.warning(r'skip partition : {}'.format(partition))
        _logger.info('analyze_mount_params device2nbd_maps:{}'.format(_device2nbd_maps))
        for vg in self._storage["vgs"]:
            for lv in vg["lvs"]:
                lv_device_path = r'{}/{}-{}'.format(_lvm_lv_root, vg["name"].replace('-', '--'),
                                                    lv["name"].replace('-', '--'))
                mount_point_in_snapshot = lv["mountPoint"]
                if mount_point_in_snapshot and (
                        (not self._read_only) or mount_point_in_snapshot in include_mount_points):
                    mount_params.append({
                        'mountPoint': self.generate_mount_point(mount_point_in_snapshot),
                        'device': lv_device_path,
                        'fileSystem': lv["fileSystem"],
                        'btrfsmntopt': lv.get("btrfsmntopt"),
                        'orgmntpoint': mount_point_in_snapshot
                    })
                elif (lv.get("fileSystem", None) is not None) and ('linux-swap' in lv["fileSystem"]):
                    swap_devices.append(lv_device_path)
                else:
                    _logger.warning(r'skip lv : {}'.format(lv))

            for pv in vg["pvs"]:
                if pv['name'] in _device2nbd_maps:
                    pvs.append(_device2nbd_maps[pv['name']])
                else:
                    _logger.warning(r'skip pv : {}'.format(pv))

        result = sorted(mount_params, key=(lambda x: len(x['mountPoint'])))
        _logger.info('mount_params : {}\n\t\t{}\n\t\t{}'.format(result, pvs, swap_devices))
        return result, pvs, swap_devices

    def analyze_mount_paramsv2(self):
        swap_devices = list()
        include_mount_points = list()
        _device2nbd_maps = dict()  # {'device_name':'nbd_device_name'}

        for include_range in self._include_ranges:
            for r in include_range['ranges']:
                if r['MountPoint']:
                    include_mount_points.append(r['MountPoint'])

        for disk in self._storage["disks"]:
            nbd_device = self.get_nbd_device(disk["index"])
            if nbd_device is None:
                continue
            # 整个磁盘是一个PV情况下，没有partitions
            if not disk['partitions']:
                _logger.warning('analyze_mount_params found no partitions, disk:{}'.format(disk))
                _device2nbd_maps[disk['device']] = nbd_device
                continue
            for partition in disk["partitions"]:
                partition_device_path = nbd_device if (partition["device"] == disk["device"]) else \
                    r'{}p{}'.format(nbd_device, partition["index"])
                _device2nbd_maps[partition['device']] = partition_device_path
                if (partition.get("fileSystem", None) is not None) and ('linux-swap' in partition["fileSystem"]):
                    swap_devices.append(partition_device_path)
                    self.norm_swap_dev_name[partition_device_path] = partition['device']
                else:
                    _logger.warning(r'skip partition : {}'.format(partition))
        _logger.info('analyze_mount_params device2nbd_maps:{}'.format(_device2nbd_maps))
        for vg in self._storage["vgs"]:
            for lv in vg["lvs"]:
                lv_device_path = r'{}/{}-{}'.format(_lvm_lv_root, vg["name"].replace('-', '--'),
                                                    lv["name"].replace('-', '--'))
                if (lv.get("fileSystem", None) is not None) and ('linux-swap' in lv["fileSystem"]):
                    swap_devices.append(lv_device_path)
                else:
                    _logger.warning(r'skip lv : {}'.format(lv))

        _logger.info('mount_params : {}'.format(swap_devices))
        return swap_devices

    def format_mnt_opt(self, add, rmv, org):
        add_list = add.split(",")
        rmv_list = rmv.split(",")
        org_list = org.split(",")

        new_list = list()
        tmp_list = add_list + org_list

        for i in tmp_list:
            if i in new_list:
                continue
            elif i in rmv_list:
                continue

            new_list.append(i)

        last = ",".join(new_list)

        _logger.info("[format_mnt_opt] add={} rmv={} org={} last={}".format(add, rmv, org, last))
        return last

    def mount_btrfs_subvol(self, mnttask):

        volume = mnttask["device"]
        btrfsmntopts = mnttask["btrfsmntopt"]
        curmntpoint = mnttask["mountPoint"]
        orgmntpoint = mnttask["orgmntpoint"]

        for mntopt in btrfsmntopts:
            opt = mntopt["opt"]
            path = mntopt["path"]
            if path == orgmntpoint:
                continue

            if path[0] == '/':
                subpath = path[1:]
            else:
                subpath = path

            full = os.path.join(curmntpoint, subpath)

            mountopt = self.format_mnt_opt(opt, self.rmv_opt, self.mnt_opt)
            cmd = "mount -o {} {} {}".format(mountopt, volume, full)

            _logger.info("[mount_btrfs_subvol] cmd={}".format(cmd))
            retval = _get_info_from_syscmd_timeout_long(cmd)
            if retval[0] == 0:
                _logger.info("[mount_btrfs_subvol] mount subvolume success")
                self.mount_point.append(full)
            else:
                _logger.info("[mount_btrfs_subvol] mount subvolume failed")

    def get_mount_option(self, org_param, mnttask):
        btrfsmntopts = mnttask.get("btrfsmntopt")
        if not btrfsmntopts:
            return org_param

        orgmntpoint = mnttask["orgmntpoint"]

        for mntopt in btrfsmntopts:
            opt = mntopt["opt"]
            path = mntopt["path"]
            if path == orgmntpoint:
                mountopt = self.format_mnt_opt(opt, self.rmv_opt, self.mnt_opt)
                return mountopt

        return org_param

    def mount_all(self, mount_params):
        # org_param = 'rw,async,relatime,noatime,nodiratime'
        valid_mount_points = 0

        for mount_task in mount_params:
            mnt_succ = False
            if self._read_only:
                _get_info_from_syscmd_timeout_very_short(r'mkdir -p "{}"'.format(mount_task['mountPoint']))
            else:
                if mount_task.get('fileSystem', '').upper() == 'EXT4':
                    _logger.info(r'force fsck.ext4 begin : {}'.format(mount_task["device"]))
                    r = _get_info_from_syscmd_timeout_long(r'fsck.ext4 -y "{}"'.format(mount_task["device"]))
                    _logger.info(r'force fsck.ext4 end : {} {}'.format(mount_task["device"], r))

            self.mount_point.append(mount_task['mountPoint'])

            o_param = self.get_mount_option(self.mnt_opt, mount_task)
            _logger.info(
                "[mount_all] opt={} dev={} mntpoint={}".format(o_param, mount_task['device'], mount_task['mountPoint']))

            if mount_task['mountPoint'].endswith(xdefine.CLW_BOOT_REDIRECT_GPT_LINUX_MOUNT_PATH):
                os.mkdir(mount_task['mountPoint'])

            r = _get_info_from_syscmd_timeout_long(r'mount -v -o {} {} "{}"'.format(
                o_param, mount_task['device'], mount_task['mountPoint']))
            if r[0] == 0:
                _logger.info(r'mount {} ok'.format(mount_task['mountPoint']))
                valid_mount_points += 1
                mnt_succ = True
            elif not self._read_only and mount_task.get('fileSystem', '').upper() == 'XFS' and r[0] != -2:
                _get_info_from_syscmd_timeout_long(r'xfs_repair -L {}'.format(mount_task["device"]))
                time.sleep(0.5)
                r = _get_info_from_syscmd_timeout_long(r'mount -v -o {} {} "{}"'.format(
                    o_param, mount_task['device'], mount_task['mountPoint']))
                if r[0] == 0:
                    _logger.info(r'mount {} ok'.format(mount_task['mountPoint']))
                    valid_mount_points += 1
                    mnt_succ = True
            elif r[0] == -2:
                _get_info_from_syscmd_timeout_short(r'umount -v "{}"'.format(mount_task['mountPoint']))
                _get_info_from_syscmd_timeout_short(r'umount -v -l "{}"'.format(mount_task['mountPoint']))

            btrfsmntopt = mount_task.get("btrfsmntopt")
            _logger.info(r'[mount_all] mmt_succ={} btrfsmntopt={}'.format(mnt_succ, btrfsmntopt))
            if mnt_succ and btrfsmntopt:
                self.mount_btrfs_subvol(mount_task)

        if valid_mount_points == 0:
            xlogging.raise_system_error(r'无法加载备份快照中的文件系统', r'mount_all failed', 0)

    @staticmethod
    def is_one_mount(mount_point):
        r = _get_info_from_syscmd_timeout_middle(r'mount')
        if r[0] != 0:
            _logger.warning('list mount failed. {}'.format(r))
            return False
        return mount_point in r[1]

    def umount_one(self, mount_point):
        _get_info_from_syscmd_timeout_very_short(r'fuser -k "{}"'.format(mount_point))
        _get_info_from_syscmd_timeout_very_short(r'fuser -k "{}"'.format(mount_point))
        _get_info_from_syscmd_timeout_very_short(r'fuser -k "{}"'.format(mount_point))
        _get_info_from_syscmd_timeout_middle(r'umount "{}"'.format(mount_point))
        time.sleep(0.1)
        while self.is_one_mount(mount_point):
            r = _get_info_from_syscmd_timeout_middle(r'umount "{}"'.format(mount_point))
            if r[0] != 0:
                _get_info_from_syscmd_timeout_very_short(r'fuser -k "{}"'.format(mount_point))
                time.sleep(0.1)

    def umount_all(self):
        if not self._mounted:
            return

        self._mounted = False

        self.mount_point.reverse()
        for mount_point in self.mount_point:
            self.umount_one(mount_point)
            if mount_point.endswith(xdefine.CLW_BOOT_REDIRECT_GPT_LINUX_MOUNT_PATH):
                os.rmdir(mount_point)

        if not self._read_only:
            _get_info_from_syscmd_timeout_middle(r'sync')
            time.sleep(10)  # 经验值，仅仅是不信任umount一定刷完所有数据

        self.deactivate_lvm()

        for nbd in self._nbds:
            _get_info_from_syscmd_timeout_short(r'partx -d {}'.format(nbd['device_path']))

    def mount(self):
        if self._mounted:
            xlogging.raise_system_error(r'内部异常，多次挂载', r'MountNbdLinux mount failed', 1)
        else:
            self._mounted = True

        if self._read_only:
            self.change_gpt_guid()
            self.change_vgs_name_and_uuid()

        mount_params, pvs, swap_devices = self.analyze_mount_params()

        if self._read_only:
            self.change_pvs_uuid(pvs)

        self.activate_lvm()

        if self._read_only:
            self.change_xfs_uuid(mount_params)
            self.change_ext_uuid(mount_params)
            self.change_btrfs_uuid(mount_params)

        self.mount_all(mount_params)

        if self._read_only:
            self.change_chmod_only_read()
        else:
            self.fix_swap(swap_devices)

    def fix_swapv2(self):
        if self._read_only:
            pass
        else:
            # 不真正的修正，只是获取参数， 真正的修正在kvm里面
            swap_devices = self.analyze_mount_paramsv2()
            for device in swap_devices:
                swap_label, swap_uuid = self.get_swap_dev_label_and_uuid_from_src(device)
                _logger.info('get_swap_dev_label_uuid_from_src: {} {} {}'.format(device, swap_label, swap_uuid))

                if device in self.norm_swap_dev_name and swap_label:  # 存在label, 非LVM的Swap设备: 记录dev_name:label映射关系
                    self.norm_swap_dev_label[self.norm_swap_dev_name[device]] = swap_label

            _logger.info('swaps_nbd_name_or_origi_name: {}'.format(swap_devices))
            _logger.info('norm_swap_dev_name: {}'.format(self.norm_swap_dev_name))
            _logger.info('norm_swap_dev_label: {}'.format(self.norm_swap_dev_label))

    @staticmethod
    def _pause_when_vgrename_unsuccessful(r):
        flag_path = '/tmp/LinuxVgrenamePause'
        os.makedirs(flag_path, exist_ok=True)
        while os.path.exists(flag_path):
            _logger.warning(
                'pause! change_vgs_name_and_uuid failed. debug: {0}\r\ndel {1} will go on running'.format(r, flag_path))
            time.sleep(10)

    def deactivate_lvm(self):
        for vg in self._storage["vgs"]:
            for lv in vg["lvs"]:
                _get_info_from_syscmd_timeout_short(r'lvchange -an /dev/{}/{}'.format(vg["name"], lv["name"]))
            time.sleep(0.5)  # 经验值
            _get_info_from_syscmd_timeout_short(r'vgchange -an {}'.format(vg["name"]))
            time.sleep(0.5)  # 经验值
            for lv in vg["lvs"]:
                _get_info_from_syscmd_timeout_short(r'dmsetup remove "{}-{}"'.format(
                    vg["name"].replace('-', '--'), lv["name"].replace('-', '--')))

    def activate_lvm(self):
        _get_info_from_syscmd_timeout_short(r'pvscan --cache')
        _get_info_from_syscmd_timeout_short(r'pvscan')
        _get_info_from_syscmd_timeout_short(r'vgscan --cache')
        _get_info_from_syscmd_timeout_short(r'vgscan')

        for vg in self._storage["vgs"]:
            r = _get_info_from_syscmd_timeout_middle(r'vgchange -ay {}'.format(vg["name"]))
            if r[0] == 0:
                continue

            for lv in vg["lvs"]:
                _get_info_from_syscmd_timeout_short(r'dmsetup remove "{}-{}"'.format(
                    vg["name"].replace('-', '--'), lv["name"].replace('-', '--')))
            time.sleep(0.5)  # 经验值
            _get_info_from_syscmd_timeout_middle(r'vgchange -ay {} --activationmode partial'.format(vg["name"]))

    def change_vgs_name_and_uuid(self):
        for vg in self._storage["vgs"]:
            vg_new_name = uuid.uuid4().hex
            _logger.info('change vg name : {} --> {}'.format(vg["name"], vg_new_name))
            r = _get_info_from_syscmd_timeout_short(r'vgrename {} {}'.format(vg["name"], vg_new_name))
            if r[0] != 0:
                _get_info_from_syscmd_timeout_short(r'vgreduce --removemissing {}'.format(vg["name"]))
                r = _get_info_from_syscmd_timeout_short(r'vgrename {} {}'.format(vg["name"], vg_new_name))
                if r[0] != 0 and self.is_debug_model():
                    self._pause_when_vgrename_unsuccessful(r)

            vg["name"] = vg_new_name
            time.sleep(0.5)  # 经验值
            _get_info_from_syscmd_timeout_short(r'vgchange -an {}'.format(vg["name"]))
            time.sleep(0.5)  # 经验值
            _get_info_from_syscmd_timeout_short(r'vgchange -u {}'.format(vg["name"]))
        time.sleep(0.5)  # 经验值

    @staticmethod
    def change_pvs_uuid(pvs):
        for pv in pvs:
            _get_info_from_syscmd_timeout_short(r'pvchange -u {}'.format(pv))

    @staticmethod
    def change_btrfs_uuid(mount_params):
        for mount_param in mount_params:
            if mount_param.get('fileSystem', '').upper() != 'BTRFS':
                continue

            retval = _get_info_from_syscmd_timeout_middle(r'blkid {}'.format(mount_param["device"]))
            _logger.info("[change_btrfs_uuid] before = {}".format(retval))

            retval = _get_info_from_syscmd_timeout_middle(r'btrfstune -f -u {}'.format(mount_param["device"]))
            _logger.info("[change_btrfs_uuid] change retval = {}".format(retval))

            retval = _get_info_from_syscmd_timeout_middle(r'blkid {}'.format(mount_param["device"]))
            _logger.info("[change_btrfs_uuid] after = {}".format(retval))

    @staticmethod
    def change_xfs_uuid(mount_params):
        for mount_param in mount_params:
            if mount_param.get('fileSystem', '').upper() != 'XFS':
                continue

            os.makedirs(_tmp_mount_path, exist_ok=True)
            _get_info_from_syscmd_timeout_middle(r'mount -v {} {}'.format(mount_param["device"], _tmp_mount_path))
            time.sleep(2)  # 等待一小会儿，立马umount可能死锁
            _get_info_from_syscmd_timeout_short(r'umount {}'.format(_tmp_mount_path))
            time.sleep(0.5)
            _get_info_from_syscmd_timeout_middle(r'xfs_repair -L {}'.format(mount_param["device"]))
            time.sleep(0.5)
            _get_info_from_syscmd_timeout_short(r'xfs_admin -U generate {}'.format(mount_param["device"]))

    @staticmethod
    def change_ext_uuid(mount_params):
        for mount_param in mount_params:
            if mount_param.get('fileSystem', '').upper() not in ['EXT2', 'EXT3', 'EXT4', ]:
                continue

            _get_info_from_syscmd_timeout_middle(r'tune2fs -U time {}'.format(mount_param["device"]))

    def change_chmod_only_read(self):
        _get_info_from_syscmd_timeout_middle(r'chmod -R a-wx,a+rX "{}"'.format(self._mount_dir))

    @staticmethod
    def _get_sub_str_from_str_info(sub_mode, line_str):
        m = re.findall(pattern=sub_mode, string=line_str)
        return m[0] if m else None

    def get_swap_dev_label_uuid_from_cmd(self, swap_dev):
        cmd_str = r'swaplabel {}'.format(swap_dev)
        code, str_info, _ = _get_info_from_syscmd_timeout_short(cmd_str)
        if code == 0 and str_info:
            swap_uuid = self._get_sub_str_from_str_info(r'UUID:\s+\S+\s+', str_info)
            swap_label = self._get_sub_str_from_str_info(r'LABEL:\s+\S+\s+', str_info)

            if swap_label:
                swap_label = swap_label.split(r'LABEL:')[-1].strip()
            if swap_uuid:
                swap_uuid = swap_uuid.split(r'UUID:')[-1].strip()

            return swap_label, swap_uuid

        return None, None

    def get_swap_dev_label_and_uuid_from_src(self, device):
        if device in self.norm_swap_dev_name:
            origi_swap = self.norm_swap_dev_name[device]  # device为nbd形式(一体机设备名)
        else:
            origi_swap = device  # device为源机设备名

        if 'disk_alias' not in self._storage:
            return None, None

        disk_alias = self._storage['disk_alias']
        _logger.info('query src disk_alias: {}'.format(disk_alias))
        swap_uuid_alias, swap_label_alias = None, None
        for alias in disk_alias:
            if alias['alias_type'] == r'by-swap-uuid':
                swap_uuid_alias = alias
            if alias['alias_type'] == r'by-swap-label':
                swap_label_alias = alias

        if not any([swap_uuid_alias, swap_label_alias]):
            return None, None

        swap_uuid, swap_label = None, None
        for item in swap_uuid_alias['alias_items']:
            if item['target'] == origi_swap:
                swap_uuid = item['name']

        for item in swap_label_alias['alias_items']:
            if item['target'] == origi_swap:
                swap_label = item['name']

        return swap_label, swap_uuid

    def fix_swap(self, devices):
        for device in devices:
            swap_label, swap_uuid = self.get_swap_dev_label_and_uuid_from_src(device)
            _logger.info('get_swap_dev_label_uuid_from_src: {} {} {}'.format(device, swap_label, swap_uuid))

            if device in self.norm_swap_dev_name and swap_label:  # 存在label, 非LVM的Swap设备: 记录dev_name:label映射关系
                self.norm_swap_dev_label[self.norm_swap_dev_name[device]] = swap_label

            # 1.存在label, swap为norm/lvm
            if swap_label:
                if swap_uuid:
                    cmd_str = r'mkswap -L {} -U {} {}'.format(swap_label, swap_uuid, device)
                else:
                    cmd_str = r'mkswap -L {} {}'.format(swap_label, device)
                _get_info_from_syscmd_timeout_short(cmd_str)
                continue

            # 2.不存在label, swap为norm, 按规则生成label
            if device in self.norm_swap_dev_name:
                swap_label = self.norm_swap_dev_name[device].lstrip(r'/').replace(r'/', r'-')
                if swap_uuid:
                    cmd_str = r'mkswap -L {} -U {} {}'.format(swap_label, swap_uuid, device)
                else:
                    cmd_str = r'mkswap -L {} {}'.format(swap_label, device)
                _get_info_from_syscmd_timeout_short(cmd_str)
                continue

            # 3.不存在label, swap为lvm
            if swap_uuid:
                cmd_str = r'mkswap -U {} {}'.format(swap_uuid, device)
            else:
                cmd_str = r'mkswap {}'.format(device)
            _get_info_from_syscmd_timeout_short(cmd_str)

        _logger.info('swaps_nbd_name_or_origi_name: {}'.format(devices))
        _logger.info('norm_swap_dev_name: {}'.format(self.norm_swap_dev_name))
        _logger.info('norm_swap_dev_label: {}'.format(self.norm_swap_dev_label))

    def change_gpt_guid(self):
        for disk in self._storage['disks']:
            if disk['style'] != 'gpt':
                continue
            nbd_device = self.get_nbd_device(disk["index"])
            if nbd_device is None:
                continue

            _get_info_from_syscmd_timeout_short(r'sgdisk -G {}'.format(nbd_device))
            time.sleep(0.2)
            _get_info_from_syscmd_timeout_short(r'partx -d {}'.format(nbd_device))
            time.sleep(0.2)
            _get_info_from_syscmd_timeout_short(r'partx -a {}'.format(nbd_device))

        time.sleep(0.5)
        _get_info_from_syscmd_timeout_short(r'pvscan --cache')
        _get_info_from_syscmd_timeout_short(r'pvscan')
        _get_info_from_syscmd_timeout_short(r'vgscan --cache')
        _get_info_from_syscmd_timeout_short(r'vgscan')
        _get_info_from_syscmd_timeout_short(r'parted -l')

#############################################################################################
# "Storage": {
#     "disks": [
#         {
#             "index": 0,
#             "device": "/dev/sda",
#             "style": "mbr",
#             "bytes": 64424509440,
#             "partitions": [
#                 {
#                     "index": 1,
#                     "bytesStart": 1048576,
#                     "bytesEnd": 525336064,
#                     "fileSystem": "xfs",
#                     "device": "/dev/sda1",
#                     "mountPoint": "/boot",
#                     "bytesLength": 524288000,
#                     "type": "native"
#                 },
#                 {
#                     "index": 2,
#                     "uuid": "JfCKrg-CrCf-23CX-YkFJ-Mo0x-y71w-hvKZID",
#                     "bytesStart": 525336576,
#                     "bytesEnd": 64424508928,
#                     "vg_name": "centos",
#                     "device": "/dev/sda2",
#                     "bytesLength": 63899172864,
#                     "type": "lvm"
#                 }
#             ]
#         }
#     ],
#     "vgs": [
#         {
#             "name": "centos",
#             "uuid": "c64131-6cb9-5049-8f9c-6769-1ae2-0b8ee3",
#             "lvs": [
#                 {
#                     "mountPoint": null,
#                     "fileSystem": null,
#                     "name": "swap",
#                     "uuid": "gCWqGR-JY4x-w4Zi-ABl4-a9V4-Ln59-ftRGlN"
#                 },
#                 {
#                     "mountPoint": "/",
#                     "fileSystem": "xfs",
#                     "name": "root",
#                     "uuid": "ceGodB-8N4R-rc1T-y9xq-eF7l-IONV-rkps9U"
#                 }
#             ],
#            "pvs": [
#                 {
#                     "name": "/dev/sda2",
#                     "uuid": "JfCKrg-CrCf-23CX-YkFJ-Mo0x-y71w-hvKZID"
#                 }
#             ]
#         }
#     ]
# }
