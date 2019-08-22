import os
import tempfile
import json
import ctypes
import uuid
import copy
import datetime
import time
import errno

import nbd
import merge_hash_core
import xlogging
import hostSession
import logicService
from media import media_objects
from qcow_helper import ReadQcow

try:
    import IMG
except ImportError:
    pass

_logger = xlogging.getLogger(__name__)
_archive_helper = ctypes.cdll.LoadLibrary(r'/sbin/aio/archive_helper.so')
BLK_SIZE = 64 * 1024


def int2bytes(num, size):
    return num.to_bytes(size, byteorder='big')


def bytes2int(org_bytes):
    return int.from_bytes(org_bytes, byteorder='big')


class IterIntervalFile(object):
    """
    迭代线段树文件,每次最多换回指定块个数，文件格式例如：
        0, 3000
        3003, 6000

    返回值   (0, 2048)
            (2048, 952)
            (3003, 2048)
            (5051, 2048)
            (7099, 1904)
    """

    def __init__(self, path, max_length):
        self._max_length = max_length
        assert self._max_length > 0
        self._handle = open(path)
        self._iter = self._iter_blk()

        self._last_blk = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._handle.close()

    def __iter__(self):
        return self

    def __next__(self):
        if self._last_blk is not None:
            offset = self._last_blk
            self._last_blk = None
        else:
            offset = next(self._iter)
        length = 1

        while length < self._max_length:
            try:
                blk = next(self._iter)
            except StopIteration:
                break

            if (offset + length) == blk:
                length += 1
            else:
                self._last_blk = blk
                break

        return offset, length

    def _iter_blk(self):
        for line in self._handle:
            offset_str, length_str = line.split(',')
            offset = int(offset_str.strip())
            length = int(length_str.strip())
            for blk in range(offset, offset + length):
                yield blk

    @staticmethod
    def m_test():
        f = tempfile.NamedTemporaryFile(mode='wt', delete=False)
        f.write('0, 3000\n')
        f.write('3003, 6000\n')
        f.close()
        with IterIntervalFile(f.name, 2048) as intervals:
            for interval in intervals:
                print(interval)
                """
                (0, 2048)
                (2048, 952)
                (3003, 2048)
                (5051, 2048)
                (7099, 1904)
                """
        os.unlink(f.name)


class Block(object):
    flag_bytes = int2bytes(0x11223344, 4)
    type_bytes = b'0'  # 1字节
    length_bytes = b''  # 4字节 整个块长度
    content_bytes = b''

    def to_bytes(self):
        content_bytes = self._get_content_bytes()
        length_bytes = int2bytes(len(self.flag_bytes) + len(self.type_bytes) + 4 + len(content_bytes), 4)

        return self.flag_bytes + self.type_bytes + length_bytes + self._get_content_bytes()

    def _get_content_bytes(self):
        raise NotImplementedError

    def _sub_fixed_length(self):
        raise NotImplementedError

    def fixed_length(self):
        return 4 + 1 + 4 + self._sub_fixed_length()  # flag(4) + type(1) + length(4)

    @classmethod
    def get_instance(cls, data):
        raise NotImplementedError


class MetaBlock(Block):
    type_bytes = int2bytes(1, 1)

    def __init__(self, og_data):
        self.og_data = og_data

    def _get_content_bytes(self):
        return json.dumps(self.og_data, ensure_ascii=False).encode('utf-8')

    def reverse(self):
        pass

    def _sub_fixed_length(self):
        return 0

    @classmethod
    def get_instance(cls, body_data):
        return cls(json.loads(body_data.decode('utf-8')))

    @staticmethod
    def m_test():
        c = {'content': '123'}
        b = MetaBlock(c).to_bytes()
        print(b)


class EndBlock(Block):
    type_bytes = int2bytes(3, 1)

    def _get_content_bytes(self):
        return b'just end'

    def _sub_fixed_length(self):
        return 0

    @classmethod
    def get_instance(cls, body_data):
        return cls()

    @staticmethod
    def m_test():
        b = EndBlock().to_bytes()
        print(b)


class DataBlock(Block):
    """
    同一块磁盘且是连续的数据
    disk_index 1bytes
    offset 4bytes 起始偏移
    blocks 4bytes # 一共多少块
    stat 1bytes|length1 3bytes # 压缩状态|压缩后的长度
    stat 1bytes|length2 3bytes # 压缩状态|压缩后的长度
    stat 1bytes|length3 3bytes # 压缩状态|压缩后的长度
    data1|data2|data3
    """
    type_bytes = int2bytes(2, 1)

    def __init__(self, disk_index, offset, blocks):
        self.disk_index = disk_index
        self.offset = offset
        self.blocks = blocks

        self._org_data = b''  # 原始数据
        self._processed_data = b''  # 处理后的数据部分，不包括头和头部索引

        self.index_info = list()

    def _sub_fixed_length(self):
        return 1 + 4 + 4  # disk_index(1), offset(4) + blocks(4)

    def add_disk_indexs(self, index_infos):
        self.index_info.extend(index_infos)

    def set_org_data(self, org_data):
        if self._org_data:
            xlogging.raise_system_error('内部错误，数据被重复添加', '_org_data is not None', 3303)
        self._org_data = org_data

    def set_processed_data(self, processed_data):
        if self._processed_data:
            xlogging.raise_system_error('内部错误，数据被重复添加', '_processed_data is not None', 3304)
        self._processed_data = processed_data

    def _get_content_bytes(self):
        if not self._processed_data:
            data_cmp, blocks_len, cmp_stat = self.compress(self._org_data, self.blocks)
            self.add_disk_indexs(zip(cmp_stat, blocks_len))
            self.set_processed_data(self.encrypt_data(data_cmp))

        _disk_index_bytes = int2bytes(self.disk_index, 1)
        _offset_bytes = int2bytes(self.offset, 4)
        _blocks_bytes = int2bytes(self.blocks, 4)

        rs = _disk_index_bytes + _offset_bytes + _blocks_bytes

        for cmp_stat, length in self.index_info:
            rs += int2bytes(cmp_stat, 1)
            rs += int2bytes(length, 3)

        rs += self._processed_data

        return rs

    @staticmethod
    def compress(org_data, blocks):
        """
        int qlz_mblk_compress(char *blk_buffer, char *out_buffer, int blocks_len[], int cmp_stat[], int size, int orgSize)
        """
        out_buffer = ctypes.create_string_buffer((blocks + 1) * BLK_SIZE)
        blocks_len = (ctypes.c_int * blocks)()
        cmp_stat = (ctypes.c_int * blocks)()
        rev = _archive_helper.qlz_mblk_compress(org_data,
                                                out_buffer,
                                                blocks_len,
                                                cmp_stat,
                                                blocks,
                                                BLK_SIZE)
        assert rev == 0
        return out_buffer[:sum(blocks_len)], blocks_len, cmp_stat

    @staticmethod
    def decompress(org_data, blocks, blocks_len, cmp_stat):
        """
        int qlz_mblk_decompress(char *blk_buffer, char *out_buffer, int blocks_len[], int cmp_stat[], int size, int orgSize)
        """
        out_buffer = ctypes.create_string_buffer((blocks + 1) * BLK_SIZE)
        blocks_len_c = (ctypes.c_int * blocks)(*blocks_len)
        cmp_stat_c = (ctypes.c_int * blocks)(*cmp_stat)
        rev = _archive_helper.qlz_mblk_decompress(org_data,
                                                  out_buffer,
                                                  blocks_len_c,
                                                  cmp_stat_c,
                                                  blocks,
                                                  BLK_SIZE)
        assert rev == 0
        return out_buffer[:blocks * BLK_SIZE]

    @staticmethod
    def encrypt_data(data):
        return data

    @staticmethod
    def decrypt_data(data):
        return data

    # 从 sp位置分片，分成2个block, 保证left_block 大小小于等于 sp
    def split_by_bytes(self, sp):
        if sp < (self.fixed_length() + 64 * 1024 + 4):
            return False, None, None
        else:
            size = self.fixed_length()
            data_length = 0
            blocks = 0
            for _, _blk_length in self.index_info:
                size += (4 + _blk_length)
                if size > sp:
                    break
                data_length += _blk_length
                blocks += 1
            else:
                raise Exception('invalid params:{}'.format(sp, self.blocks))
            assert blocks > 0
            left_block = DataBlock(self.disk_index, self.offset, blocks)
            left_block.add_disk_indexs(self.index_info[:blocks])
            left_block.set_org_data(self._org_data[:blocks * BLK_SIZE])
            left_block.set_processed_data(self._processed_data[:data_length])

            right_block = DataBlock(self.disk_index, self.offset + blocks, self.blocks - blocks)
            right_block.add_disk_indexs(self.index_info[blocks:])
            right_block.set_org_data(self._org_data[blocks * BLK_SIZE:])
            right_block.set_processed_data(self._processed_data[data_length:])

            return True, left_block, right_block

    @classmethod
    def get_instance(cls, body_data):
        disk_index = bytes2int(body_data[0:1])
        offset = bytes2int(body_data[1:5])
        blocks = bytes2int(body_data[5:9])

        blocks_len, cmp_stat = list(), list()
        for index in range(blocks):
            i = 9 + (index * 4)
            cmp_stat.append(bytes2int(body_data[i:i + 1]))
            blocks_len.append(bytes2int(body_data[i + 1:i + 4]))

        processed_data = body_data[9 + blocks * 4:]
        org_data = DataBlock.decompress(DataBlock.decrypt_data(processed_data), blocks, blocks_len, cmp_stat)

        datablock = cls(disk_index, offset, blocks)
        datablock.set_org_data(org_data)
        datablock.set_processed_data(processed_data)
        datablock.add_disk_indexs(zip(cmp_stat, blocks_len))
        return datablock

    @staticmethod
    def m_test():
        d = DataBlock(1, 100, 3)
        d.add_disk_indexs([(1, 100), (1, 200), (0, 64 * 1024)])
        d.set_org_data(bytes(64 * 1024 + 300))
        print(d.to_bytes())

    def __str__(self):
        return '<DataBlock index:{} blocks:{}>'.format(self.disk_index, self.blocks)


class ExportSnapshotsLogic(object):

    def __init__(self, info):
        self._info = info
        self._meta_data = self._info['meta_data']
        self._media = media_objects.get(self._info['media_uuid'])
        if not self._media:
            xlogging.raise_system_error('获取介质失败', 'get media fail', 138)
        self._logger = merge_hash_core.LoggerAdapter(_logger,
                                                     {'prefix': 'ExportSnapshotsLogic_{}'.format(uuid.uuid4().hex[-6:])})

    @xlogging.convert_exception_to_value(None)
    def report_progress(self, total, index):
        payload = {'status': 'transfer_data', 'progressIndex': index, 'progressTotal': total}
        return hostSession.http_report_task_status('export_snapshot', self._info['task_uuid'], payload)

    def work(self):
        self._logger.info('logic start , info：{}'.format(self._info))
        try:
            self.start_task()
            total_blocks = self._info['total_blocks']
            self.report_progress(total_blocks, 0)
            is_retry = False
            _last_data, _last_blocks = None, None
            with GeneratorDataHandle(self._info['meta_data'], self._info['disk_snapshots'],
                                     self._media.align_size) as gen_data:
                vol_index = 0
                while total_blocks > 0:
                    handle, size = self._media.get_write_handle(
                        '{}.media.clw'.format(uuid.uuid4().hex))
                    if handle == -1:
                        xlogging.raise_system_error('写入数据失败，目标介质无可用空间', 'no more space', 376)
                    self._logger.info('get write handle {} size {}'.format(handle, size))
                    if is_retry:
                        data, blocks = _last_data, _last_blocks
                        is_retry = False
                        _last_data, _last_blocks = None, None
                    else:
                        data, blocks = gen_data.gen_vol(vol_index,
                                                        min(size, 256 * 1024 ** 2))  # 生成min(256MB, size) 大小的数据
                    status, errorinfo = self._media.write(handle, data)
                    self._logger.info('write num {} bytes to handle {}'.format(len(data), handle))
                    self._media.close(handle)
                    if status == 0:
                        vol_index += 1
                        total_blocks -= blocks
                        self.report_progress(self._info['total_blocks'], self._info['total_blocks'] - total_blocks)
                    elif status == errno.ENOSPC:
                        is_retry = True
                        _last_data = data
                        _last_blocks = blocks
                        self._logger.warning('write error, no more space, retry')
                    else:
                        xlogging.raise_system_error('写入数据失败', 'write error:{}'.format(errorinfo), 136)
        except Exception as e:
            self._media.finish_task(False)
            raise e
        else:
            file_infos = self._media.finish_task(True)
            return file_infos

    def start_task(self):
        while True:
            rev, info = self._media.start_task(
                {'task_uuid': uuid.uuid4().hex,
                 'task_date': datetime.datetime.strptime(self._meta_data['task_date'], '%Y_%m_%dT%H_%M_%S'),
                 'size': self._info['total_blocks'] * BLK_SIZE})
            if rev == 0:
                break
            else:
                time.sleep(5)


class GeneratorDataHandle(object):

    def __init__(self, meta_data, disk_snapshots, align_size):
        self._meta_data = meta_data
        self._disk_snapshots = disk_snapshots
        self._align_size = align_size  # 对齐大小

        self._generator = self._block_generator_func()
        self._last_block = None
        self._logger = merge_hash_core.LoggerAdapter(_logger,
                                                     {'prefix': 'GeneratorDataHandle_{}'.format(uuid.uuid4().hex[-6:])})

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def gen_vol(self, vol_index, size):
        """
        获取小于等于size的数据
        :param vol_index: 卷索引
        :param size: 最大大小
        :return: 数据，块个数
        """
        meta_data = copy.deepcopy(self._meta_data)
        meta_data['vol_index'] = vol_index
        head = MetaBlock(meta_data).to_bytes()
        tail = EndBlock().to_bytes()
        body = b''
        blocks = 0

        c_size = len(head) + len(tail) + self._align_size  # 预留字节做对齐
        while c_size < size:
            if self._last_block:
                data_block = self._last_block
                self._last_block = None
            else:
                try:
                    data_block = next(self._generator)
                except StopIteration:
                    break
            data_bytes = data_block.to_bytes()
            _c_blocks = data_block.blocks

            # 剩余空间小于块大小
            if (size - c_size) < len(data_bytes):
                self._last_block = data_block
                break
            else:
                self._last_block = None

            c_size += len(data_bytes)
            body += data_bytes
            blocks += _c_blocks

        #  处理对齐部分
        org_data = head + body + tail
        if len(org_data) > size:
            raise Exception('len(org_data) > size {} {}'.format(len(org_data), size))

        rs = org_data + bytes(self._align_size - len(org_data) % self._align_size)
        return rs, blocks

    def _block_generator_func(self):
        for disk_info in self._disk_snapshots:
            _flag = r'PiD{:x} logicService|archive_export disk {}'.format(os.getpid(), disk_info['disk_index'])
            with ReadQcow([IMG.ImageSnapshotIdent(snapshot['path'], snapshot['ident']) for snapshot in
                           disk_info['snapshots']], _flag) as read_qcow:
                with IterIntervalFile(disk_info['intervals_file'], 2048) as iter_intervals:
                    for offset, blocks in iter_intervals:  # 每次迭代产生最多2048块线段 [[st,blocks], [st2, blocks]]
                        # 确保读不超过磁盘大小
                        if (offset + blocks) * BLK_SIZE > disk_info['disk_bytes']:
                            data = read_qcow.read(offset * BLK_SIZE, disk_info['disk_bytes'] - offset * BLK_SIZE)
                            data += bytes((offset + blocks) * BLK_SIZE - disk_info['disk_bytes'])
                        else:
                            data = read_qcow.read(offset * BLK_SIZE, blocks * BLK_SIZE)
                        block = DataBlock(disk_info['disk_index'], offset, blocks)
                        block.set_org_data(data)
                        yield block


class AnalyseArchiveFile(object):

    def __init__(self, archive_file):
        self._archive_file = archive_file
        self._check_file()

    def _check_file(self):
        with open(self._archive_file, 'rb') as f:
            data = f.read(4)
        if data != Block.flag_bytes:
            xlogging.raise_system_error('数据校验出错', 'invalid flag:{}'.format(data), 3301)
        return None

    def __enter__(self):
        self._fd = open(self._archive_file, 'rb')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._fd.close()

    def get_meta_data(self):
        with open(self._archive_file, 'rb') as f:
            block = self._fetch_one_block(f)
            assert isinstance(block, MetaBlock)
        return block.og_data

    @staticmethod
    def _fetch_one_block(fd):
        data = fd.read(9)
        flag_bytes, type_bytes, length_bytes = data[:4], data[4:5], data[5:]  # common header
        assert flag_bytes == Block.flag_bytes
        body_bytes = fd.read(bytes2int(length_bytes) - 9)
        if type_bytes == MetaBlock.type_bytes:
            return MetaBlock.get_instance(body_bytes)
        elif type_bytes == DataBlock.type_bytes:
            return DataBlock.get_instance(body_bytes)
        elif type_bytes == EndBlock.type_bytes:
            return EndBlock.get_instance(body_bytes)
        else:
            xlogging.raise_system_error('解析数据块出错, 未知类型', 'invalid type', 3302)

    def __iter__(self):
        return self

    def __next__(self):
        """
        :return: data Object
        """
        while True:
            block = self._fetch_one_block(self._fd)
            if isinstance(block, EndBlock):
                raise StopIteration
            elif isinstance(block, MetaBlock):
                continue
            elif isinstance(block, DataBlock):
                return block


class AnalyseArchiveMeidaFile(object):
    # 只能with语法调用
    def __init__(self, media_infos):
        self._logger = merge_hash_core.LoggerAdapter(_logger,
                                                     {'prefix': 'AnalyseArchiveMeidaFile_{}'.format(uuid.uuid4().hex[-6:])})
        self.file_info = media_infos['file_info']
        media_uuid = media_infos['media_uuid']
        self._media = media_objects.get(media_uuid)
        self._read_handle = None

    def _get_read_handle(self):
        while True:
            _read_handle, _ = self._media.get_read_handle(self.file_info)
            if _read_handle == -1:
                time.sleep(5)
                self._logger.info(
                    'AnalyseArchiveMeidaFile __init__ get_read_handle Failed.ignore seleep 1S. try again.')
            else:
                return _read_handle

    def __del__(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._media.close(self._read_handle)

    def get_meta_data(self):
        self._read_handle = self._get_read_handle()
        block = self._fetch_one_block()
        assert isinstance(block, MetaBlock)
        return block.og_data

    def _fetch_one_block(self):
        _, data = self._media.read(self._read_handle, 9)
        flag_bytes, type_bytes, length_bytes = data[:4], data[4:5], data[5:]  # common header
        assert flag_bytes == Block.flag_bytes
        length = bytes2int(length_bytes) - 9
        _, body_bytes = self._media.read(self._read_handle, length)
        if type_bytes == MetaBlock.type_bytes:
            return MetaBlock.get_instance(body_bytes)
        elif type_bytes == DataBlock.type_bytes:
            return DataBlock.get_instance(body_bytes)
        elif type_bytes == EndBlock.type_bytes:
            return EndBlock.get_instance(body_bytes)
        else:
            xlogging.raise_system_error('_fetch_one_block 解析数据块出错, 未知类型', 'invalid type', 3302)

    def __iter__(self):
        self._read_handle = self._get_read_handle()
        return self

    def __next__(self):
        """
        :return: data Object
        """
        while True:
            block = self._fetch_one_block()
            if isinstance(block, EndBlock):
                raise StopIteration
            elif isinstance(block, MetaBlock):
                continue
            elif isinstance(block, DataBlock):
                return block


class WriteArchiveQcowFile(object):
    def __init__(self, task_uuid):
        self._task_uuid = task_uuid
        self._logger = merge_hash_core.LoggerAdapter(_logger,
                                                     {'prefix': 'WriteArchiveQcowFile_{}'.format(uuid.uuid4().hex[-6:])})

    def _fun_create_snapshot(self, qcow2_path, snapshot_ident, qcow2_bytes):
        self._logger.info('_fun_create_snapshot({},{},{})'.format(qcow2_path, snapshot_ident, qcow2_bytes))
        _new_snapshot = IMG.ImageSnapshotIdent(qcow2_path, snapshot_ident)
        _prev_disk_snapshots = list()
        _disk_size = qcow2_bytes
        _flag = r'PiD{:x} LogicService|ArchiveQcowFileHandle {}'.format(os.getpid(), snapshot_ident)
        return logicService.createNormalDiskSnapshot(_new_snapshot, _prev_disk_snapshots, _disk_size, _flag)

    @xlogging.convert_exception_to_value(None)
    def report_progress(self, total, index):
        payload = {'status': 'transfer_data', 'progressIndex': index, 'progressTotal': total}
        return hostSession.http_report_task_status('import_snapshot', self._task_uuid, payload)

    def genArchiveQcowFile(self, qcow_file_parameter):
        self._logger.info('genArchiveQcowFile({})'.format(qcow_file_parameter))
        target_disklist = dict()
        total_src_blocks = 0
        total_writed_blkcount = 0

        # 初始化目标硬盘信息。
        for dst in qcow_file_parameter['dst']:
            self._logger.info('init target disk({},{},{})'.format(dst['path'], dst['snapshot'], dst['bytes']))
            _target_disk = dict()
            _target_disk['path'] = dst['path']
            _target_disk['snapshot'] = dst['snapshot']
            _target_disk['bytes'] = dst['bytes']
            _target_disk['writed_blocks'] = 0
            _target_disk['src_blocks'] = 0
            _target_disk['handle'] = -1
            target_disklist[dst['native_guid']] = _target_disk

        for source_data in qcow_file_parameter['source_data']:
            _src_all_disk = source_data['disk_info']
            for _one_src_disk in _src_all_disk:
                if _one_src_disk['native_guid'] not in target_disklist:
                    continue
                target_disklist[_one_src_disk['native_guid']]['src_blocks'] += _one_src_disk['blocks']
                total_src_blocks += _one_src_disk['blocks']

        self._logger.info('genArchiveQcowFile_target_disk:{}'.format(target_disklist))

        try:
            successful = False
            for _k, _target_disk in target_disklist.items():
                _target_disk['handle'] = self._fun_create_snapshot(_target_disk['path'],
                                                                   _target_disk['snapshot'], _target_disk['bytes'])
            # fixme 建立句柄失败了会不会异常？

            self.report_progress(total_src_blocks, 0)
            for source_data in qcow_file_parameter['source_data']:

                _disk_index_2_guid = dict()
                _src_all_disk = source_data['disk_info']
                for _one in _src_all_disk:
                    _disk_index_2_guid[_one['disk_index']] = _one['native_guid']

                file_media_infos = sorted(list(source_data['file_media_infos'].values()), key=lambda x: x['fdIndex'])
                media_uuid = source_data['media_uuid']
                for file_media_info in file_media_infos:
                    media_infos = {'file_info': file_media_info, 'media_uuid': media_uuid}
                    self._logger.info('media_infos:({})'.format(media_infos))
                    with AnalyseArchiveMeidaFile(media_infos) as f:
                        for datablock in f:
                            if datablock.disk_index not in _disk_index_2_guid:
                                self._logger.info('lost disk_index:({})'.format(datablock.disk_index))
                                continue
                            # 能找到目标硬盘了
                            _target_disk = target_disklist[_disk_index_2_guid[datablock.disk_index]]
                            _target_disk['writed_blocks'] += datablock.blocks
                            total_writed_blkcount += datablock.blocks

                            if datablock.offset * BLK_SIZE + len(datablock._org_data) > _target_disk['bytes']:
                                data_length = _target_disk['bytes'] - datablock.offset * BLK_SIZE
                                logicService.write2NormalDiskSnapshot(_target_disk['handle'],
                                                                      datablock.offset * BLK_SIZE,
                                                                      datablock._org_data[:data_length])
                            else:
                                logicService.write2NormalDiskSnapshot(_target_disk['handle'],
                                                                      datablock.offset * BLK_SIZE, datablock._org_data)
                    self.report_progress(total_src_blocks, total_writed_blkcount)

            if total_src_blocks == total_writed_blkcount:
                successful = True
            else:
                self._logger.info('genArchiveQcowFile_write blocks error! src：{} != dst:{}'.format(
                    total_src_blocks, total_writed_blkcount))
                self._logger.info('genArchiveQcowFile_end:{}'.format(target_disklist))
        finally:
            for _k, _v in target_disklist.items():
                if _v['handle'] != -1:
                    logicService.closeNormalDiskSnapshot(_v['handle'], successful)

        self._logger.info('genArchiveQcowFile_end:{}'.format(target_disklist))
        if successful:
            self._logger.info('genArchiveQcowFile OK')
        else:
            xlogging.raise_system_error('数据传输出错', 'total_src_blocks={},total_writed_blkcount={}'.format(
                total_src_blocks, total_writed_blkcount), 3309)


def m_test_import(src_dir):
    for file in os.listdir(src_dir):
        path = os.path.join(src_dir, file)
        print(path, AnalyseArchiveFile(path).get_meta_data())
        with AnalyseArchiveFile(path) as f:
            for datablock in f:
                print(datablock.disk_index, datablock.offset, datablock.blocks)


def m_test_export(all_info):
    _blocks = 0
    import random
    import shutil

    shutil.rmtree(all_info['out_dir'], ignore_errors=True)
    os.makedirs(all_info['out_dir'])

    with GeneratorDataHandle(all_info['meta_data'], all_info['disk_snapshots'], BLK_SIZE) as gen:
        vol = 0
        while _blocks < total_blocks:
            _data, c_blocks = gen.gen_vol(vol, random.randint(2, 6) * 100 * 1024 ** 2)
            _blocks += c_blocks
            with tempfile.NamedTemporaryFile('wb', delete=False, dir=all_info['out_dir']) as f:
                f.write(_data)
            vol += 1


if __name__ == '__main__':
    # IterIntervalFile.m_test()
    # MetaBlock.m_test()
    # EndBlock.m_test()
    # DataBlock.m_test()

    nbd.init(128)

    path = '/home/mnt/nodes/c8d45962e65d48f3827acf25e2441191/images/624c0b0776724d49ac67e0cddeea4fc9/fae1d59e006a447aa411f1cadae9f441.qcow'
    ident = 'db5c3c5b43ea403cb63b070c8a482847'
    disk_bytes = 31470806016
    total_blocks = 24551
    intervals_file = '/home/{}_intervals_file'.format(ident)
    all_info = {
        'meta_data': {'meta': 'meta data'},
        'max_bytes': 1 * 1024 ** 3,
        'prefix': 'test_archive',
        'out_dir': '/home/test_archive',
        'total_blocks': total_blocks,
        'disk_snapshots': [{
            'disk_index': 1,
            'disk_bytes': disk_bytes,
            'snapshots': [
                {
                    'path': path,
                    'ident': ident
                }
            ],
            'intervals_file': intervals_file
        }]
    }
    if not os.path.exists(intervals_file):
        merge_hash_core.Hash2Interval('/tmp/empty', '{}_{}.hash'.format(path, ident), intervals_file).work()

    # ExportSnapshotsLogic(all_info).work()

    m_test_export(all_info)

    # m_test_import(all_info['out_dir'])
