import os
import time
import traceback

import net_common
import xlogging

_logger = xlogging.getLogger(__name__)


class CMountNbd:
    def __init__(self, dev_path, mount_dir, partition_info):
        try:
            self.mount_dev_list = list()
            self.dev_path = dev_path
            self.mount_dir = mount_dir
            self.parttion_info = partition_info
            #
            # cmd_line = "parted -l".format(dev_path)
            # _logger.debug("part cmd line {}".format(cmd_line))
            # with os.popen(cmd_line) as out_put:
            #     out_put_lines = out_put.readlines()
            #     can_sear_my_dev = False
            #     for one_line in out_put_lines:
            #         _logger.debug(one_line)
            #         if -1 != one_line.find(dev_path):
            #             _logger.debug('can_sear_my_dev = True')
            #             can_sear_my_dev = True
            #         else:
            #             if -1 != one_line.find('/dev/'):
            #                 _logger.debug('can_sear_my_dev = False')
            #                 can_sear_my_dev = False
            #         if can_sear_my_dev:
            #             if -1 != one_line.find('ntfs'):
            #                 _logger.debug('mount_ntfs')
            #                 self.mount_ntfs(dev_path, one_line)
            #             if -1 != one_line.find('fat16'):
            #                 _logger.debug('mount_fat 16')
            #                 self.mount_fat(dev_path, one_line)
            #             if -1 != one_line.find('fat32'):
            #                 _logger.debug('mount_fat 32')
            #                 self.mount_fat(dev_path, one_line)

        except Exception as e:
            _logger.error('except {}'.format(traceback.format_exc()))

    def mount(self):
        try:
            cmd_line = "partx -d {};partx -a {}".format(self.dev_path, self.dev_path)
            net_common.get_info_from_syscmd(cmd_line)
            cmd_line = 'ls {}p*'.format(self.dev_path)
            ret = net_common.get_info_from_syscmd(cmd_line)
            _logger.debug('cmd {} ret {}'.format(cmd_line, ret))
            if ret[0] != 0:
                _logger.error('cmd {} failed'.format(cmd_line))
            else:
                mstr = '{}p'.format(self.dev_path)
                linelist = ret[1].strip(' ').split('\n')
                devlist = list()
                for lineone in linelist:
                    lineone = lineone.strip(' ')
                    if lineone.startswith(mstr):
                        if not os.path.exists(lineone):
                            _logger.error('nbd part {} not exist'.format(lineone))
                            continue
                        devlist.append(lineone)
                        _logger.debug('get one part {}'.format(lineone))
                dev_partition2offset_dict = self.get_dev_detail(self.dev_path)
                _logger.debug('dev:{} partition info:{}'.format(self.dev_path, dev_partition2offset_dict))
                for partition in self.parttion_info:
                    dev_str = dev_partition2offset_dict.get(str(partition['PartitionOffset']), None)
                    vol_name = self.get_name(partition)
                    if not dev_str:
                        _logger.warning(
                            'get vol:[{},offset:{}] dev fail'.format(vol_name, partition['PartitionOffset']))
                        continue
                    des_path = os.path.join(self.mount_dir, '{}'.format(vol_name))

                    # str mount with fat
                    cmd_line = 'mkdir -p "{}"'.format(des_path)
                    ret = net_common.get_info_from_syscmd(cmd_line)
                    if ret[0] != 0:
                        _logger.error('create mount dir {} failed'.format(des_path))
                        continue
                    cmd_line = 'mount -o ro,iocharset=utf8,codepage=936 "{}" "{}"'.format(dev_str, des_path)
                    _logger.debug('mount cmd {}'.format(cmd_line))
                    ret = net_common.get_info_from_syscmd(cmd_line)
                    if ret[0] == 0:
                        self.mount_dev_list.append([dev_str, des_path])
                        _logger.debug('{} mount nofs on {} success'.format(dev_str, des_path))
                        continue
                    # str mount with ntfs-3g
                    cmd_line = 'mount -t ntfs-3g "{}" "{}" -o ro'.format(dev_str, des_path)
                    _logger.debug('mount cmd {}'.format(cmd_line))
                    ret = net_common.get_info_from_syscmd(cmd_line)
                    if ret[0] == 0:
                        self.mount_dev_list.append([dev_str, des_path])
                        _logger.debug('{} mount ntfs-3g on {} success'.format(dev_str, des_path))
                        continue
                    net_common.get_info_from_syscmd('rm -rf "{}"'.format(des_path))
                    _logger.error('{} mount on {} failed'.format(dev_str, des_path))
        except Exception as e:
            _logger.error('except {}'.format(traceback.format_exc()))

    def mount_ntfs(self, dev_path, one_line):
        try:
            dev_str = dev_path + 'p' + one_line[:5].strip()
            if not os.path.exists(dev_str):
                _logger.error('dev {} file not exist'.format(dev_str))
            else:
                # 创建目标目录
                # des_path = self.mount_dir + '/' + os.path.basename(dev_str)
                des_path = self.mount_dir + '/' + 'volume' + one_line[:5].strip()
                cmd_line = 'mkdir -p "{}";mount -t ntfs-3g "{}" "{}" -o ro'.format(des_path, dev_str, des_path)
                _logger.debug('mount cmd {}'.format(cmd_line))
                ret = net_common.get_info_from_syscmd(cmd_line)
                if ret[0] == 0:
                    self.mount_dev_list.append(dev_str)
                else:
                    _logger.debug('cmd {} failed,ret {}'.format(cmd_line, ret))
        except Exception as e:
            _logger.error('except {}'.format(traceback.format_exc()))

    def mount_fat(self, dev_path, one_line):
        try:
            dev_str = dev_path + 'p' + one_line[:5].strip()
            if not os.path.exists(dev_str):
                _logger.error('dev {} file not exist'.format(dev_str))
            else:
                # 创建目标目录
                # des_path = self.mount_dir + '/' + os.path.basename(dev_str)
                des_path = self.mount_dir + '/' + 'volume' + one_line[:5].strip()
                cmd_line = 'mkdir -p "{}";mount -o ro,iocharset=utf8,codepage=936 "{}" "{}"'.format(des_path, dev_str,
                                                                                                    des_path)
                _logger.debug('mount cmd {}'.format(cmd_line))
                ret = net_common.get_info_from_syscmd(cmd_line)
                if ret[0] == 0:
                    self.mount_dev_list.append(dev_str)
                else:
                    _logger.debug('cmd {} failed,ret {}'.format(cmd_line, ret))
        except Exception as e:
            _logger.error('except {}'.format(traceback.format_exc()))

    @staticmethod
    def is_one_mount(mount_point):
        r = net_common.get_info_from_syscmd(r'mount')
        if r[0] != 0:
            _logger.warning('list mount failed. {}'.format(r))
            return False
        return mount_point in r[1]

    def umount_one(self, mount_point):
        net_common.get_info_from_syscmd(r'fuser -k "{}"'.format(mount_point))
        net_common.get_info_from_syscmd(r'fuser -k "{}"'.format(mount_point))
        net_common.get_info_from_syscmd(r'fuser -k "{}"'.format(mount_point))
        net_common.get_info_from_syscmd(r'umount "{}"'.format(mount_point))
        time.sleep(0.1)
        while self.is_one_mount(mount_point):
            r = net_common.get_info_from_syscmd(r'umount "{}"'.format(mount_point))
            if r[0] != 0:
                net_common.get_info_from_syscmd(r'fuser -k "{}"'.format(mount_point))
                time.sleep(0.1)

    def UnMount(self):
        try:
            for one_dev in self.mount_dev_list:
                self.umount_one(one_dev[1])
            self.mount_dev_list.clear()
        except Exception as e:
            _logger.error('except {}'.format(traceback.format_exc()))

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
            return 'volume{}'.format(partition['Index'])

    @staticmethod
    def get_dev_detail(dev_path):
        rs = dict()
        if not os.path.exists(dev_path):
            _logger.warning('DevDetail get_dict fail, dev:{} is not found'.format(dev_path))
            return rs

        cmd = r"partx -o NR,START {} |grep -v NR".format(dev_path)
        ret = net_common.get_info_from_syscmd(cmd)
        if ret[0] == 0:
            for line in ret[1].splitlines():
                item_list = line.strip().split()
                if len(item_list) == 2:
                    offset = str(int(item_list[1]) * 512)
                    rs[offset] = "{}p{}".format(dev_path, item_list[0])
        else:
            _logger.error('get DevDetail fail:{}'.format(ret[2]))
        return rs

    def __del__(self):
        _logger.debug('mount nbd destroy,dev_path {} mount list {}'.format(self.dev_path, self.mount_dev_list))
        self.UnMount()


if __name__ == "__main__":
    nbd_class = CMountNbd("/dev/nbd0", "/mnt", [])
