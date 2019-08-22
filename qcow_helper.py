import os
import json
import operator

import logicService
import bitmap

import IMG
import xlogging

_logger = xlogging.getLogger(__name__)
DISK_OFFSET_GETTER = operator.itemgetter(0)
QCOW_FILE_OFFSET_GETTER = operator.itemgetter(1)
LENGTH_GETTER = operator.itemgetter(2)


# 需要修正最后长度，因为最后一个很可能超
def get_length(offset, length, maxsize):
    # map 文件最后一行的磁盘偏移可能大于磁盘大小，需要修正
    if (offset + length) > maxsize:
        if (maxsize - offset) <= 0:  # 已经读完了
            return -1
        else:
            return maxsize - offset
    else:
        return length


class ReadMapFile(object):
    def __init__(self, map_path):
        self._map_path = map_path
        self._handle = None

    def _open(self, map_path):
        if map_path is None:
            return None
        else:
            return open(map_path)

    def __enter__(self):
        self._handle = self._open(self._map_path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __iter__(self):
        if self._handle:
            self._handle.seek(0)
        return self

    def __next__(self):
        if self._handle is None:
            raise StopIteration
        value = next(self._handle)
        itemlist = value.strip('\n').split(':')
        return (
            int(DISK_OFFSET_GETTER(itemlist), 16),
            int(QCOW_FILE_OFFSET_GETTER(itemlist), 16),
            int(LENGTH_GETTER(itemlist)) * 512
        )

    def close(self):
        if self._handle is None:
            return None
        else:
            self._handle.close()
            self._handle = None


class ReadQcow(object):
    def __init__(self, snapshots, flag, read_org=False):
        self._handle = None
        self._snapshots = snapshots
        self._flag = flag

        self._max_size_pre = 64 * 1024 ** 2
        if read_org:
            self.read_func = logicService.readNormalDiskSnapshotEx  # 读出来没有解压
        else:
            self.read_func = logicService.readNormalDiskSnapshot  # 读出来解压了的

    def _open(self, snapshots, flag):
        return logicService.openDiskSnapshot(snapshots, flag)

    def read(self, offset, size):
        """
        请确保offset + size <= disk size， 否则readNormalDiskSnapshotEx会报错
        :param offset: bytes offset
        :param size: bytes content
        :return:
        """
        data = b''
        while size > 0:
            if size > self._max_size_pre:
                read_size = self._max_size_pre
            else:
                read_size = size

            data += self.read_func(self._handle, offset, read_size)
            offset += read_size
            size -= read_size
        return data

    def close(self):
        logicService.closeNormalDiskSnapshot(self._handle, True)
        self._handle = None

    def __enter__(self):
        self._handle = self._open(self._snapshots, self._flag)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class WriteQcow(object):
    def __init__(self, write_handle):
        self._write_handle = write_handle

    def write(self, offset, content):
        logicService.write2NormalDiskSnapshot(self._write_handle, offset, content)

    def close(self, successful):
        logicService.closeNormalDiskSnapshot(self._write_handle, successful)
        self._write_handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close(exc_type is None)
        return False


class MergeQcowFileHandle(object):
    def __init__(self, json_args):
        self._input_args = json.loads(json_args)
        self._new_snapshot = None
        self._current_snapshot = None
        self._prev_disk_snapshots = None
        self._disk_size = None
        self._map_path = None
        self._read_size = 8 * 1024 * 1024
        self._flag = None

    def work(self):
        try:
            self._check_and_init_input_args()
            self._del_snapshot()
            with WriteQcow(self._create_snapshot()) as write_object:
                self._merge_qcow(write_object)
        except Exception as e:
            _logger.error('MergeQcowFileHandle error:{}'.format(e), exc_info=True)
            raise e

    def _check_and_init_input_args(self):
        _logger.info('_check_and_init_input_args _input_args:{}'.format(self._input_args))
        self._new_snapshot = self._get_snapshot_ice_object(self._input_args['new_snapshot_qcow_file'],
                                                           self._input_args['new_snapshot_qcow_ident']
                                                           )
        self._flag = r'PiD{:x} BoxDashboard|MergeQcowFileHandle {}'.format(os.getpid(), self._new_snapshot.snapshot)
        self._current_snapshot = self._get_snapshot_ice_object(self._input_args['current_snapshot_qcow_file'],
                                                               self._input_args['current_snapshot_qcow_ident']
                                                               )
        self._prev_disk_snapshots = [self._get_snapshot_ice_object(item['path'], item['ident']) for item in
                                     self._input_args['prev_disk_snapshots']]
        self._disk_size = int(self._input_args['disk_bytes'])
        self._map_path = self._get_map_path_from_snapshot()

    def _get_map_path_from_snapshot(self):
        map_path = '{}_{}.map'.format(self._current_snapshot.path, self._current_snapshot.snapshot)
        if os.path.exists(map_path):
            return map_path
        else:
            if not os.path.exists(self._current_snapshot.path):
                xlogging.raise_system_error('快照文件不存在', 'either map and qcow file not exists !', 111)
            else:
                if os.stat(self._current_snapshot.path).st_size <= 10 * 1024 * 1024:
                    _logger.warning(
                        'MergeQcowFileHandle map file not exists and qcow size is smaller than 10M, start create empty '
                        'qcow!')
                    return None
                else:
                    xlogging.raise_system_error('快照文件大于10M', 'map file not exists but qcow size is bigger than 10M!',
                                                112)

    def _get_snapshot_ice_object(self, path, ident):
        return IMG.ImageSnapshotIdent(path, ident)

    def _merge_qcow(self, write_object):
        _flag = r'PiD{:x} BoxDashboard|MergeQcowFileHandle {}'.format(os.getpid(), self._current_snapshot.snapshot)
        with ReadQcow([self._current_snapshot], _flag) as read_object:
            with ReadMapFile(self._map_path) as read_map_object:
                ReadAndWriteHandle(read_object, read_map_object, write_object, self._read_size,
                                   self._disk_size).work()

    def _del_snapshot(self):
        logicService.delNormalDiskSnapshot(self._new_snapshot)

    def _create_snapshot(self):
        return logicService.createNormalDiskSnapshot(self._new_snapshot, self._prev_disk_snapshots,
                                                     self._disk_size,
                                                     self._flag)


class ReadAndWriteHandle(object):
    def __init__(self, read_object, read_map_object, write_object, read_size, disk_size):
        self._read_size = read_size
        self._read_map_object = read_map_object
        self._read_object = read_object
        self._write_object = write_object
        self._disk_size = disk_size

    def work(self):
        for offset, _, or_length in self._read_map_object:
            length = get_length(offset, or_length, self._disk_size)
            if length == -1:
                return
            current_read_offset = offset
            current_write_offset = offset
            while current_read_offset < (offset + length):
                if current_read_offset + self._read_size >= offset + length:
                    data = self._read_object.read(current_read_offset, offset + length - current_read_offset)
                    self._write_object.write(current_write_offset, data)
                    current_write_offset += offset + length - current_read_offset
                else:
                    data = self._read_object.read(current_read_offset, self._read_size)
                    self._write_object.write(current_write_offset, data)
                    current_write_offset += self._read_size
                current_read_offset += self._read_size


class GenerateBitMapFromMaps(object):
    BLOCK = 64 * 1024

    def __init__(self, maps, bit_map_path, nbytes):
        self._map_paths = maps
        self._bit_map_path = bit_map_path
        self._bit_map = bitmap.BitMap((nbytes + self.BLOCK - 1) // self.BLOCK)

    @staticmethod
    def get_map_paths_from_qcow2file(qcow_file_path):
        rs = list()
        dir_name, qcow_file_name = os.path.split(qcow_file_path)
        for file_name in os.listdir(dir_name):
            if file_name.startswith(qcow_file_name) and file_name.endswith('.map'):
                rs.append(os.path.join(dir_name, file_name))
        return rs

    @staticmethod
    def get_qcow_file_size(qcow_file_path):
        map_files = GenerateBitMapFromMaps.get_map_paths_from_qcow2file(qcow_file_path)
        size = 0
        for map_file in map_files:
            max_size_tmp = GenerateBitMapFromMaps.from_map_get_qcow_max_size(map_file)
            if max_size_tmp > size:
                size = max_size_tmp
        return size

    @staticmethod
    def from_map_get_qcow_max_size(map_path):
        size = 0
        with ReadMapFile(map_path) as f:
            for _, offset, length in f:
                if (offset + length) > size:
                    size = offset + length
        return size

    def work(self):
        for map_path in self._map_paths:
            with ReadMapFile(map_path) as rf:
                for _, byte_offset, byte_length in rf:
                    self._set_bits(byte_offset, byte_length)

        with open(self._bit_map_path, 'wb') as f:
            f.write(self._bit_map.bitmap)

    def _set_bits(self, offset, length):
        std_blk = offset // self.BLOCK
        end_blk = (offset + length + self.BLOCK - 1) // self.BLOCK
        for pos in range(std_blk, end_blk):
            self._bit_map.set(pos)


if __name__ == '__main__':
    class readobject(object):
        def read(self, offset, size):
            print('read offset:{}, size:{}'.format(offset, size))
            return '1' * size


    class writeobject(object):
        def write(self, offset, content):
            print('write offset:{}, content:{}'.format(offset, content))


    read_map_object_fake = [(0, 0, 100), (103, 103, 50), (200, 200, 80), (400, 400, 90)]
    size = 80

    ReadAndWriteHandle(readobject(), read_map_object_fake, writeobject(), size, 320).work()

    current_dir = os.path.dirname(os.path.abspath(__file__))
    with ReadMapFile(os.path.join(current_dir, 'test.map')) as f:
        for i, j, k in f:
            print(i, j, k)

        for i, j, k in f:
            print(i, j, k)

    with ReadMapFile(None) as f:
        for i, j, k in f:
            print(i, j, k)

    size = GenerateBitMapFromMaps.get_qcow_file_size(
        '/home/mnt/nodes/120f06bf4c564f31a7e2e6592663d308/images/46fc980c98744e919a790ed6a86a7f63/3148fe0f3e844a908df3c5c63b292c05.qcow')

    print(size)
