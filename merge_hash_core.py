#!/usr/bin/env python
# coding: utf-8

import argparse
import csv
import ctypes
import logging
import os
import re
import shutil
import threading
import time
import uuid
import sys

import logicService
import nbd
import xlogging
from bitmap import MmapBitMap, BitMap
from compare_aio_hash import fetch_changes
from net_common import get_info_from_syscmd
import qcow_helper
import queue

_hash_logger = xlogging.getLogger('hash_r')

import IMG

BLK_SIZE = 64 * 1024

index_file = re.compile('\d+')
hash_helper = ctypes.cdll.LoadLibrary(r'/sbin/aio/hash_helper.so')
_sort_locker = threading.Lock()

"""
hash 文件一行内容 lba(16进制，扇区偏移), length, hash_content 
例如：0x0,256,89b5ccfb65269ede9c52e5a235e3658530c1a5a8
"""


def _get_offset(_byte):
    n = 0
    while _byte:
        if _byte & 1:
            yield n
        _byte >>= 1
        n += 1


BYTE_OFFSETS_MAP = {i: list(_get_offset(i)) for i in range(256)} # {0:[], 1:[0], 2:[1], .., 255:[0..7]}
BYTE_OFFSETS_MAP.update(
    {i.to_bytes(1, byteorder=sys.byteorder): list(_get_offset(i)) for i in
     range(256)})  # from bitmap file, each is byte not int


def iter_bitmap(byte_array):
    for index, _byte in enumerate(byte_array):
        for offset in BYTE_OFFSETS_MAP[_byte]:
            yield index * 8 + offset


def iter_bitmap_interval(byte_array, max_length):
    """
    :param byte_array:
    :param max_length:
    :return: start_offset, length
    """
    assert max_length > 0
    res_offset, res_length = -1, -1
    for offset in iter_bitmap(byte_array):
        if res_offset == -1:
            res_offset, res_length = offset, 1
        else:
            if res_offset + res_length == offset:
                res_length += 1
            else:
                yield res_offset, res_length
                res_offset, res_length = offset, 1

        if res_length == max_length:
            yield res_offset, res_length
            res_offset, res_length = -1, -1
    if res_offset != -1:
        yield res_offset, res_length


def remove_exists(path):
    if os.path.exists(path):
        os.remove(path)
    else:
        pass


class MergeHash(object):
    def __init__(self, disk_bytes):
        bitmap_size = (disk_bytes + 64 * 1024 - 1) // (64 * 1024)
        self._disk_bytes = disk_bytes
        self.task_bitmap = MmapBitMap(bitmap_size)
        self._logger = LoggerAdapter(_hash_logger, {'prefix': 'MergeHash_{}'.format(uuid.uuid4().hex[-6:])})
        self._include_cdp = False
        self._snapshots = list()
        self._split_bits = (64 * 1024 ** 2) // 70  # 大约64MB一个文件，每一行70个字节
        self._clip_file_name = '%s/hashfile.%05d'  # 10000 * 64MB = 640GB，最大hash文件
        self._nbd_device = None
        self._tmp_dir = None

    def merge_one2other_hash(self, one_hash_path, other_hash_path):
        u"""将父级的hash 合并到已有的子级hash文件中去
        :param one_hash_path:
        :param other_hash_path:
        :return:
        """
        try:
            self._logger.debug('merge_one2other_hash start merge {} to {}'.format(one_hash_path, other_hash_path))
            self._check_file_path(one_hash_path)
            self._check_file_path(other_hash_path)
            merge_tmp = '{}.tmp_merge_one2other_hash'.format(other_hash_path)
            remove_exists(merge_tmp)
            shutil.copy(other_hash_path, merge_tmp)  # 写临时文件，防止写一半
            with open(merge_tmp, 'r') as cf:
                reader = csv.DictReader(cf, fieldnames=['offset', 'num', 'val'])
                for line in reader:
                    self.set_bitmap(int(line['offset'], 16) // 0x80)
            with open(merge_tmp, 'a') as cf:
                with open(one_hash_path, 'r') as pf:
                    reader = csv.DictReader(pf, fieldnames=['offset', 'num', 'val'])
                    for line in reader:
                        result = self.check_bitmap(int(line['offset'], 16) // 0x80)
                        if not result:
                            writer = csv.DictWriter(cf, fieldnames=['offset', 'num', 'val'], lineterminator='\n')
                            writer.writerow(line)
            shutil.move(merge_tmp, other_hash_path)
            self._logger.debug('merge_one2other_hash end merge!')
        except Exception as e:
            self._logger.error('merge_one2other_hash error:{}'.format(e), exc_info=True)
            raise
        return True

    def merge_one2other_hashv2(self, one_hash_path, other_hash_path):
        """
        将 one_hash_path 的hash 合入 other_hash_path 中
        """
        self._logger.info('merge_one2other_hashv2 start merge {} to {}'.format(one_hash_path, other_hash_path))
        self._check_file_path(one_hash_path)
        self._check_file_path(other_hash_path)
        other_hash_path_tmp = '{}.tmp_merge_one2other_hash'.format(other_hash_path)
        try:
            self.merge(other_hash_path_tmp, [other_hash_path, one_hash_path])
        except Exception as e:
            self._logger.error('merge_one2other_hashv2 error {}'.format(e), exc_info=True)
            remove_exists(other_hash_path_tmp)
            raise
        else:
            shutil.move(other_hash_path_tmp, other_hash_path)
        self._logger.info('merge_one2other_hashv2 merge {} to {} end'.format(one_hash_path, other_hash_path))

    def merge(self, _file_save_path, hash_files, include_cdp=False, snapshots=None):
        """
        文件合并,生成新的hash文件
        :param _file_save_path: 文件要保存的地址 , 传入格式 str
        :param hash_files: 要合并的文件 , 传入格式 [str,str..]
        :param include_cdp 默认False， 当为True时候，需要将cdp包含的数据转换成hash数据
        :param snapshots include_cdp==True 有效， 快照链
        :return:
        """
        self._include_cdp = include_cdp
        self._snapshots = list() if snapshots is None else snapshots
        self._tmp_dir = self._mktmp_dir(_file_save_path)
        self._logger.debug(
            'merge start file_save_path:{}, hash_files:{} tmp_dir:{}'.format(_file_save_path, hash_files,
                                                                             self._tmp_dir))
        try:
            clip_files = self._split_file(hash_files)
            self._sort_files()
            self._merge_file(['{}.sorted'.format(file) for file in clip_files], _file_save_path)
        except Exception as e:
            self._logger.error('merge fail:{}'.format(e), exc_info=True)
            raise
        finally:
            shutil.rmtree(self._tmp_dir)
        self._logger.debug('merge end ')
        return _file_save_path

    @staticmethod
    def _mktmp_dir(_file_save_path):
        base_dir = os.path.dirname(_file_save_path)
        tmp_dir = os.path.join(base_dir, 'sort_{}'.format(uuid.uuid4().hex))
        os.makedirs(tmp_dir)
        return tmp_dir

    def _split_file(self, hash_files):
        """
        :param hash_files: ['xxx.hash', 'cdp|cdp_path|timestamp']
        :return:
        """
        st = time.time()
        self._logger.debug('split_file start')
        hash_files = self._collect_cdp_files(hash_files)
        for hash_file in hash_files:
            if isinstance(hash_file, list):
                self.set_bit_by_cdp_files(hash_file)  # cdp位图置位
            else:
                self.set_bit_and_split(hash_file)  # 分成小文件

        def _sorted_key(file_name):
            return int(index_file.search(file_name).group(0))

        clip_files = [os.path.join(self._tmp_dir, file) for file in sorted(os.listdir(self._tmp_dir), key=_sorted_key)]
        self._logger.debug(
            'split_file end, clip_files num:{}, cost time:{:.1f}s'.format(len(clip_files), time.time() - st))
        return clip_files

    @staticmethod
    def _collect_cdp_files(hash_files):
        """
        :param hash_files:['xxx.hash', 'cdp|xxx.cdp|timestamp', 'cdp|xxx1.cdp|timestamp', 'xxx1.hash']
        :return:['xxx.hash', ['cdp|xxx.cdp|timestamp', 'cdp|xxx1.cdp|timestamp'], 'xxx1.hash']
        """
        rs = list()
        for hash_file in hash_files:
            if hash_file.startswith('cdp|'):
                if rs and isinstance(rs[-1], list):
                    rs[-1].append(hash_file)
                else:
                    rs.append([hash_file])
            else:
                rs.append(hash_file)
        return rs

    # 在多线程情况下，多进程会卡死
    @xlogging.LockDecorator(_sort_locker)
    def _sort_files(self):
        st = time.time()
        self._logger.debug('sort_files start')
        result = get_info_from_syscmd('python /sbin/aio/logic_service/merge_hash_helper.py {}'.format(self._tmp_dir),
                                      600)
        if result[0] != 0:
            xlogging.raise_system_error('生成hash去重文件失败', 'sort fail', 1111)
        self._logger.debug('sort_files end, cost time:{:.1f}s'.format(time.time() - st))

    def _merge_file(self, src_files, dst_file):
        st = time.time()
        self._logger.debug('merge_file start')
        dst_file_tmp = '{}.tmp_merge_file'.format(dst_file)
        try:
            with open(dst_file_tmp, 'wb') as wf:
                for file in src_files:
                    with open(file, 'rb') as rf:
                        while True:
                            data = rf.read(8 * 1024 ** 2)
                            if data:
                                wf.write(data)
                            else:
                                break
        except Exception:
            remove_exists(dst_file_tmp)
            raise
        shutil.move(dst_file_tmp, dst_file)
        self._logger.debug('merge_file end, cost time:{:.1f}s'.format(time.time() - st))

    def set_bit_and_split(self, hash_file):
        """
        将大的hash文件分成小文件，文件名具有顺序，并置位
        :param hash_file:
        :return:
        """
        self._logger.debug('start set_bit_and_split {}'.format(hash_file))
        rev = hash_helper.merge_hash_file(bytes(hash_file, encoding='utf-8'),
                                          bytes(self.task_bitmap.file_path, encoding='utf-8'),
                                          ctypes.c_int32(self.task_bitmap.nbytes),
                                          ctypes.c_int32(self._split_bits),
                                          bytes(self._clip_file_name, encoding='utf-8'),
                                          bytes(self._tmp_dir, encoding='utf-8'))
        assert rev == 0
        self._logger.debug('end set_bit_and_split {}'.format(hash_file))

    def set_bit_by_cdp_files(self, cdp_files):
        u""" 当文件为 cdp文件的时候，只进行块站位，不进行文件写入
        :param cdp_files: ['cdp|cdp_file_path|timestamp']
        :return:
        """
        self._logger.debug('start set_bit_by_cdp_files {}'.format(cdp_files))

        def _generate_snapshot(cdp_info):
            _, path, timestamp = cdp_info.split('|')
            return IMG.ImageSnapshotIdent(path, timestamp)

        cdp_idents = list(map(_generate_snapshot, cdp_files))
        flag = r'PiD{:x} LogicService|set_bit_by_cdp'.format(os.getpid())
        with logicService.SnapshotsUsedBitMap(cdp_idents, flag) as f:
            data = f.read()
        if self._include_cdp:
            hash_file = os.path.join(self._tmp_dir, '{}.hash'.format(uuid.uuid4().hex))
            self._generate_hash_data(data, hash_file)
            self.set_bit_and_split(hash_file)
            os.remove(hash_file)
        else:
            self.task_bitmap.set_bytes(data)
        self._logger.debug('end set_bit_by_cdp {}'.format(cdp_files))

    def _generate_hash_data(self, bits, hash_file):
        self._logger.info('start _generate_hash_data hash_file:{}'.format(hash_file))
        assert len(bits) == len(self.task_bitmap.bitmap), 'two map len not equal'
        bits = bytearray(
            map(lambda i: i[0] & ~i[1], zip(bits, bytearray(self.task_bitmap.bitmap))))  # bits 中多余的位去掉
        with open(hash_file, 'w') as wf:
            ReorganizeHashFile.generate_new(self._snapshots, bits, self._disk_bytes, wf, self._logger)
        self._logger.info('_generate_hash_data end, :{}'.format(hash_file))

    def check_bitmap(self, chunk_number):
        u"""检查是否可用
        :param chunk_number: 块号
        :return:
        """
        try:
            result = self.task_bitmap.test(chunk_number)
        except Exception as e:
            raise xlogging.raise_system_error(r'不可用', 'chunk_number Error:{} chunk_number:{}'.format(e, chunk_number),
                                              1)
        return result

    def set_bitmap(self, chunk_number):
        u"""设置此块号
        :param chunk_number:块号
        :return:
        """
        if not self.check_bitmap(chunk_number):
            self.task_bitmap.set(chunk_number)
            return True
        else:
            return False

    @staticmethod
    def _check_file_path(path):
        u"""文件路径检测
        :param path:
        :return:
        """
        if not os.path.exists(path):
            raise xlogging.raise_system_error(r'地址不可用', 'Path Error:{} is not existed'.format(path), 1)


class BitMapIter(object):
    """
    对bitmap进行迭代，每次迭代产生bit为1的块序号，下标从零开始
    =>for i in BitMapIter(iter(bytearray([1, 0, 0, 2, 3, 4, 5]))):
          print(i)
    =>0
    =>25
    =>32
    =>33
    =>42
    =>48
    =>50
    """

    def __init__(self, bitmap):
        self._bit_map = bitmap
        self._current_byte = 0
        self._offset = 0
        self._byte_offset = -1

    def __iter__(self):
        return self

    def __next__(self):
        while not self._current_byte:
            self._current_byte = next(self._bit_map)
            if isinstance(self._current_byte, bytes):
                self._current_byte = int.from_bytes(self._current_byte, sys.byteorder)
            self._byte_offset += 1
            if self._current_byte:
                self._offset = self._byte_offset * 8
                break

        while self._current_byte:
            v, off = self._current_byte & 1, self._offset
            self._current_byte >>= 1
            self._offset += 1
            if v:
                return off
            else:
                pass


class BitMapIterInterval(object):

    def __init__(self, bitmap, max_length):
        self._bit_map = BitMapIter(iter(bitmap))
        self._max_length = max_length

        self._last_blk = None

    def __iter__(self):
        return self

    def __next__(self):
        if self._last_blk is not None:
            offset = self._last_blk
            self._last_blk = None
        else:
            offset = next(self._bit_map)
        length = 1

        while length < self._max_length:
            try:
                blk = next(self._bit_map)
            except StopIteration:
                break

            if (offset + length) == blk:
                length += 1
            else:
                self._last_blk = blk
                break

        return offset, length


class LoggerAdapter(logging.LoggerAdapter):

    def process(self, msg, kwargs):
        return '[{}] {}'.format(self.extra['prefix'], msg), kwargs


class ReorganizeHashFilOldVer(object):
    """
    整理hash文件，以位图为准，hash_file_src中多余的块丢掉，没有的块重新生成
    生成结果是hash_file
    """

    def __init__(self, bit_map, snapshots, hash_file_dst, hash_file_src):
        self._hash_file_dst = hash_file_dst
        self._hash_file_dst_tmp = '{}.tmp_ReorganizeHashFilOldVer'.format(self._hash_file_dst)  # 先写临时文件，在改名
        self._hash_file_src = hash_file_src
        self._snapshots = snapshots
        self._bit_map = bit_map
        self._nbd_object = None
        self._logger = LoggerAdapter(_hash_logger,
                                     {'prefix': 'ReorganizeHashFilOldVer_{}'.format(uuid.uuid4().hex[-6:])})

    def work(self):
        try:
            self._logger.info('start logic {} {} {}'.format(self._snapshots, self._hash_file_dst, self._hash_file_src))
            remove_exists(self._hash_file_dst_tmp)
            self._generate_new_hash_file()
            self._logger.info('end logic')
        except Exception as e:
            self._logger.error('ReorganizeHashFilOldVer fail:{}'.format(e), exc_info=True)
            xlogging.raise_system_error('整理hash文件失败', 'ReorganizeHashFile fail:{}'.format(e), 1211)
        finally:
            self.unmount_nbd()

    # 生成新的hash文件
    def _generate_new_hash_file(self):
        self._logger.info('_generate_new_hash_file num bits:{}'.format(self._bit_map.count()))
        self._drop_redundant_hash()  # 删除hash文件中多余的hash
        self._logger.info(
            '_generate_new_hash_file num bits:{}, after _drop_redundant_hash'.format(self._bit_map.count()))
        self._generate_and_add_new_hash()  # 根据map生成指定块的hash

    def _drop_redundant_hash(self):
        if not os.path.exists(self._hash_file_src):
            self._logger.warning('_drop_redundant_hash file:{} not exists, do nothing'.format(self._hash_file_src))
            return
        with open(self._hash_file_src) as rf:
            with open(self._hash_file_dst_tmp, 'w') as wf:
                for line in rf:
                    blk_offset = int(line.split(',')[0], 16) // 0x80
                    if self.check_and_ignore_index_error(blk_offset):
                        self._bit_map.reset(blk_offset)
                        wf.write(line)
                    else:
                        self._logger.warning('drop line:{}'.format(line))

    def check_and_ignore_index_error(self, blk_offset):
        try:
            return self._bit_map.test(blk_offset)
        except IndexError:
            self._logger.warning('check_and_ignore_index_error index error, offset:{}'.format(blk_offset))
            return False

    def _generate_and_add_new_hash(self):
        with open(self._hash_file_dst_tmp, 'a') as wf:
            for line in self.generate_hash_iter(self._get_nbd_object().device_path, self._bit_map.bitmap):
                wf.write(line)
        shutil.move(self._hash_file_dst_tmp, self._hash_file_dst)

    @staticmethod
    def generate_hash_iter(nbd_device, bits, check_bits=None):  # todo 需要优化， 1.直接使用imgservice 2. 传多块
        hash_helper_old = ctypes.cdll.LoadLibrary(r'/sbin/aio/hash_helper_old.so')
        with open(nbd_device, 'rb') as rf:
            for blk_offset in BitMapIter(iter(bits)):
                if check_bits and check_bits.test(blk_offset):  # 已经置位，无须再算
                    continue
                rf.seek(blk_offset * BLK_SIZE)
                content = rf.read(BLK_SIZE)
                hash_bytes = 64
                hash_buffer = ctypes.create_string_buffer(hash_bytes)
                returned = hash_helper_old.hash_blk(
                    ctypes.c_int64(blk_offset * 0x80),
                    bytes(content),
                    ctypes.c_int32(len(content)),
                    hash_buffer,
                    ctypes.c_int32(hash_bytes))
                if returned != 0:
                    raise Exception('_generate_and_add_new_hash return != 0')
                else:
                    yield hash_buffer.raw.decode("utf-8").rstrip('\x00')

    def _get_nbd_object(self):
        if self._nbd_object:
            return self._nbd_object
        else:
            self._nbd_object = nbd.nbd_wrapper(
                nbd.nbd_wrapper_disable_lvm_allocator(nbd.nbd_wrapper_local_device_allocator()))
            nbd_thread = nbd.nbd_direct_images(self._nbd_object.device_name, self._nbd_object, self._snapshots)
            nbd_thread.start()
            nbd.nbd_wrapper.wait_nbd_read_ok(self._nbd_object)
            return self._nbd_object

    def unmount_nbd(self):
        if self._nbd_object:
            self._nbd_object.unmount()
            self._nbd_object.wait_no_mounting()
            self._nbd_object.set_no_longer_used()
            self._nbd_object = None
        else:
            pass


class ReorganizeHashFile(object):
    """
    整理hash文件，以位图为准，hash_file_src中多余的块丢掉，没有的块重新生成
    生成结果是hash_file
    """

    def __init__(self, bit_map, snapshots, hash_file_dst, hash_file_src, disk_bytes):
        self._hash_file_dst = hash_file_dst
        self._hash_file_dst_tmp = '{}.tmp_ReorganizeHashFile'.format(self._hash_file_dst)  # 先写临时文件，在改名
        self._hash_file_src = hash_file_src
        self._snapshots = snapshots
        self._bit_map = bit_map
        self._nbd_object = None
        self._disk_bytes = disk_bytes
        self._logger = LoggerAdapter(_hash_logger, {'prefix': 'ReorganizeHashFile_{}'.format(uuid.uuid4().hex[-6:])})

    def work(self):
        try:
            self._logger.info('start logic {} {} {}'.format(self._snapshots, self._hash_file_dst, self._hash_file_src))
            remove_exists(self._hash_file_dst_tmp)
            self._generate_new_hash_file()
            self._logger.info('end logic')
        except Exception as e:
            remove_exists(self._hash_file_dst_tmp)
            self._logger.error('ReorganizeHashFile fail:{}'.format(e), exc_info=True)
            xlogging.raise_system_error('整理hash文件失败', 'ReorganizeHashFile fail:{}'.format(e), 1211)

    # 生成新的hash文件
    def _generate_new_hash_file(self):
        with open(self._hash_file_dst_tmp, 'w') as wf:
            self._drop_redundant(wf)  # 删除hash文件中多余的hash
            self.generate_new(self._snapshots, self._bit_map.bitmap, self._disk_bytes, wf,
                              self._logger)  # 根据map生成指定块的hash
        shutil.move(self._hash_file_dst_tmp, self._hash_file_dst)

    def _drop_redundant(self, wf):
        if not os.path.exists(self._hash_file_src):
            self._logger.warning('_drop_redundant_hash file:{} not exists, do nothing'.format(self._hash_file_src))
            return
        with open(self._hash_file_src) as rf:
            for line in rf:
                blk_offset = int(line.split(',')[0], 16) // 0x80
                if self.check_and_ignore_index_error(blk_offset):
                    self._bit_map.reset(blk_offset)
                    wf.write(line)
                else:
                    self._logger.warning('drop line:{}'.format(line))

    def check_and_ignore_index_error(self, blk_offset):
        try:
            return self._bit_map.test(blk_offset)
        except IndexError:
            self._logger.warning('check_and_ignore_index_error index error, offset:{}'.format(blk_offset))
            return False

    @staticmethod
    def generate_new(snapshots, bit_map, disk_bytes, write_handle, logger):
        _flag = r'PiD{:x} logicService|generate hash'.format(os.getpid())
        with qcow_helper.ReadQcow([IMG.ImageSnapshotIdent(snapshot['path'], snapshot['ident']) for snapshot in
                                   snapshots], _flag, False) as read_handle:
            HashGenerate(read_handle, write_handle, bit_map, disk_bytes, logger).generate()


class Hash2Interval(object):
    """
    计算base_hash与parent_hash不同之处，存成线段
    """

    def __init__(self, base_hash, parent_hash, map_path):
        self._base_hash = base_hash
        self._parent_hash = parent_hash
        self._map_path = map_path
        self._logger = LoggerAdapter(_hash_logger,
                                     {'prefix': 'Hash2Interval_{}'.format(uuid.uuid4().hex[-6:])})
        self._blocks = set()

    def work(self):
        self._logger.debug('start work,  base_hash, parent_hash :{}|{}'.format(self._base_hash, self._parent_hash))
        fetch_changes(self._parent_hash, self._base_hash, '', self._diff_call_back, ',', 'cmp_hex_str')
        self._blocks = list(self._blocks)
        self._logger.debug('fetch {} different blocks'.format(len(self._blocks)))
        self._blocks.sort()
        inteavals = list()
        for block in self._blocks:
            if inteavals and isinstance(inteavals[-1], list):
                if block == (inteavals[-1][0] + inteavals[-1][1]):
                    inteavals[-1][1] += 1
                else:
                    inteavals.append([block, 1])
            else:
                inteavals.append([block, 1])
        with open('{}.tmp'.format(self._map_path), 'w') as f:
            f.write('\n'.join(['{},{}'.format(i[0], i[1]) for i in inteavals]))
        shutil.move('{}.tmp'.format(self._map_path), self._map_path)
        self._logger.debug('end work, num blocks:{}'.format(len(self._blocks)))
        return len(self._blocks)

    def _diff_call_back(self, search_dir, offset, change_type, oldline, newline):
        self._blocks.add(int(offset, 16) // 0x80)


class Counter(object):

    def __init__(self):
        self._lock = threading.Lock()
        self._counts = 0

    def inc(self, num=1):
        with self._lock:
            self._counts += num
        return num

    @property
    def count(self):
        with self._lock:
            return self._counts


class HashGenerate(object):

    def __init__(self, read_handle, write_handle, blk_bitmap, disk_bytes, logger):
        self._read_handle = read_handle
        self._write_handle = write_handle
        self._blk_bitmap = blk_bitmap
        self._disk_bytes = disk_bytes

        self._interval_queues = queue.Queue(maxsize=16)  # 线段队列
        self._content_queues = queue.Queue(maxsize=32)  # 读出的内容 队列
        self._hash_queues = queue.Queue(maxsize=16)  # 生成的hash的 队列

        self._end_flag = object()
        self._logger = logger

        if os.path.exists('/dev/shm/debug_generate_hash'):
            self._in_debug = True
        else:
            self._in_debug = False

        self._blk_counts = Counter()  # 总共块个数
        self._read_blk_counts = Counter()  # 读取块个数
        self._generate_hash_blk_counts = Counter()  # 生成hash块个数
        self._write_hash_blk_counts = Counter()  # 写hash块个数
        self._error = None

    def generate(self):
        """
        读取位图,产生线段放入线段队列interval_queues---> 读取线段队列，从ImageService读取对应内容，放入内容队列content_queues
        ---> 读取内容队列，计算hash,放入hash队列hash_queues---> 读取hash队列，写入最终文件
        """

        self._logger.info('start generate ...')
        st = time.time()
        read_works = 10
        per_read_blks = 8
        generate_works = 5
        self._logger.info(
            '{} read workers, per read {} blocks, {} generate hash workers'.format(read_works,
                                                                                   per_read_blks,
                                                                                   generate_works))

        # 产生线段线程
        generate_interval_ins = threading.Thread(target=self._work_read_bitmap,
                                                 args=(self._blk_bitmap, self._interval_queues, per_read_blks))
        generate_interval_ins.setDaemon(True)
        generate_interval_ins.start()

        # 读线程
        read_work_ins = list()
        for _ in range(read_works):
            rt = threading.Thread(target=self._work_read_content,
                                  args=(self._read_handle, self._interval_queues, self._content_queues))
            rt.setDaemon(True)
            rt.start()
            read_work_ins.append(rt)

        # 生成hash线程
        generate_work_ins = list()
        for _ in range(generate_works):
            rt = threading.Thread(target=self._work_generate_hash,
                                  args=(self._content_queues, self._hash_queues))
            rt.setDaemon(True)
            rt.start()
            generate_work_ins.append(rt)

        write_hash_ins = threading.Thread(target=self._work_write_hash, args=(self._write_handle, self._hash_queues))
        write_hash_ins.setDaemon(True)
        write_hash_ins.start()

        debug_ins = threading.Thread(target=self._work_debug,
                                     args=(self._interval_queues, self._content_queues, self._hash_queues))
        debug_ins.setDaemon(True)
        debug_ins.start()

        generate_interval_ins.join()
        self._interval_queues.join()
        for _ in read_work_ins:
            self._interval_queues.put(self._end_flag)
        for th in read_work_ins:
            th.join()

        self._content_queues.join()
        for _ in generate_work_ins:
            self._content_queues.put(self._end_flag)
        for th in generate_work_ins:
            th.join()

        self._hash_queues.join()
        self._hash_queues.put(self._end_flag)
        write_hash_ins.join()
        self._in_debug = False

        if self._error:
            raise self._error

        assert self._blk_counts.count == self._read_blk_counts.count == self._generate_hash_blk_counts.count == \
               self._write_hash_blk_counts.count, '生成hash数据不准确'

        blks = self._blk_counts.count
        cost_time = time.time() - st
        spend = (blks * BLK_SIZE) / (cost_time * 1024 ** 2)
        self._logger.info('generate {} blocks'.format(blks))
        self._logger.info('use {:.2f}s'.format(cost_time))
        self._logger.info('spend {:.2f}MB/s'.format(spend))
        self._logger.info('end generate')
        return None

    def _work_read_bitmap(self, blk_bitmap, interval_queues, per_read_blks):
        try:
            for offset, length in iter_bitmap_interval(blk_bitmap, max_length=per_read_blks):
                interval_queues.put((offset, length))
                self._blk_counts.inc(length)
        except Exception as e:
            self._error = e

    def _work_read_content(self, read_handle, interval_queues, content_queues):
        while not self._error:
            item = interval_queues.get()
            try:
                if item is self._end_flag:
                    break
                offset, length = item
                if (offset + length) * BLK_SIZE > self._disk_bytes:
                    size = self._disk_bytes - offset * BLK_SIZE
                else:
                    size = BLK_SIZE * length
                content_queues.put((offset, length, read_handle.read(offset * BLK_SIZE, size)))
                self._read_blk_counts.inc(length)
            except Exception as e:
                self._error = e
            finally:
                interval_queues.task_done()

    def _work_generate_hash(self, content_queues, hash_queues):
        while not self._error:
            item = content_queues.get()
            try:
                if item is self._end_flag:
                    break
                offset, length, content = item
                sector_offset = list()
                blk_lens = list()
                for num in range(length):
                    sector_offset.append((offset + num) * 0x80)
                    blk_lens.append(BLK_SIZE)
                if (offset + length) * BLK_SIZE > self._disk_bytes:
                    blk_lens[-1] = self._disk_bytes - (offset + length - 1) * BLK_SIZE

                sector_offset_c = (ctypes.c_ulonglong * length)(*sector_offset)
                blk_lens_c = (ctypes.c_int * length)(*blk_lens)

                hash_bytes = 64
                hash_buffer = ctypes.create_string_buffer(hash_bytes * length)
                returned = hash_helper.hash_blk_multi(
                    bytes(content),
                    sector_offset_c,
                    blk_lens_c,
                    ctypes.c_int32(length),
                    hash_buffer,
                    ctypes.c_int32(hash_bytes))
                if returned != 0:
                    raise Exception('hash_blk_multi return !=0')
                else:
                    hash_queues.put((length, hash_buffer.raw.decode("utf-8").rstrip('\x00')))
                    self._generate_hash_blk_counts.inc(length)
            except Exception as e:
                self._error = e
            finally:
                content_queues.task_done()

    def _work_write_hash(self, write_handle, hash_queues):
        while not self._error:
            item = hash_queues.get()
            try:
                if item is self._end_flag:
                    break
                length, content = item
                write_handle.write(content)
                self._write_hash_blk_counts.inc(length)
            except Exception as e:
                self._error = e
            finally:
                hash_queues.task_done()

    def _work_debug(self, interval_queues, content_queues, hash_queues):
        while self._in_debug and not self._error:
            time.sleep(2)
            self._logger.debug(
                'interval_queues_size {} content_queues_size {} hash_queues_size {}'.format(interval_queues.qsize(),
                                                                                            content_queues.qsize(),
                                                                                            hash_queues.qsize()
                                                                                            ))


if __name__ == '__main__':
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG)
    sh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    _hash_logger.addHandler(sh)


    # 获取命令行参数
    def get_cmd_args():
        args_parser = argparse.ArgumentParser(
            description="python merge_hash_core.py --size size --new_path path --mer_paths paths")
        args_parser.add_argument("--size", help="bitmap size")
        args_parser.add_argument("--new_path", help="New address to save")
        args_parser.add_argument("--mer_paths", help="will go merged dirs who splited by ',' of str ")
        cmd_args = args_parser.parse_args()
        return cmd_args


    def my_random(*ranges):
        from itertools import product, chain
        all_items = product(range(min(chain(*ranges)), max(chain(*ranges)) + 1), repeat=len(ranges))
        rs = list()
        for item in all_items:
            for index, _range in enumerate(ranges):
                if item[index] not in _range:
                    break
            else:
                rs.append(item)
        return rs


    def test_reorganize_hash_file():
        nbd.init(128)
        logicService._g = logicService._logic_service()
        # for i in BitMapIter(iter(bytearray([1, 0, 0, 2, 3, 4, 5]))):
        #     print(i)
        with open('/tmp/test.bitmap', 'rb') as f:
            _bit_map = f.read()

        bit_map = BitMap()
        bit_map.bitmap = bytearray(_bit_map)
        snapshots = [{
            "path": "/home/mnt/nodes/ffccc08f7d5e40119e0440fd5845259c/images/c152ad459f4c4b39897bf0127c760f66/d3632a55450d4692a5d3021727975edf.qcow",
            "ident": 'a3a1debbbe6f4c969fb0fe630d111199'}
        ]
        disk_bytes = 105066964992
        hash_name = '/tmp/hash.new'
        # import os
        # os.system('echo 3 > /proc/sys/vm/drop_caches;echo 3 > /proc/sys/vm/drop_caches')

        ReorganizeHashFile(bit_map, snapshots, hash_name, hash_name + '.tmp', disk_bytes).work()
        MergeHash(disk_bytes).merge(hash_name + '.reg', [hash_name])

        # for read_counts, blk_counts, generate_counts in my_random((8, 9, 10), (2, 4, 8, 16), (5, 6, 7, 8, 9, 10)):
        #     read_works = read_counts
        #     per_read_blks = blk_counts
        #     generate_works = generate_counts
        #     import os
        #     os.system('echo 3 > /proc/sys/vm/drop_caches;echo 3 > /proc/sys/vm/drop_caches')
        #     with open(hash_name, 'w') as wf:
        #         ReorganizeHashFile.generate_new(snapshots, bit_map.bitmap, 21474836480, wf, _hash_logger,
        #                                         )
        #
        # global time_costs
        # time_costs.sort(key=lambda x: x[0], reverse=True)
        # for i in time_costs:
        #     print(i)


    def test_collect_cdp_files():
        assert MergeHash._collect_cdp_files(['1', 'cdp|', 'cdp|', '2']) == ['1', ['cdp|', 'cdp|'], '2']


    def test_merge_hash():
        line = '0x{:x},256,38f35d3e29a39cb038b6195cffaea26dfd29a401\n'

        def _generate_hash_file(blocks, file_name):
            with open(file_name, 'w') as f:
                for block in blocks:
                    f.write(line.format(block * 0x80))

        disk_size = 1024 ** 4  # 1 T
        blocks = disk_size // BLK_SIZE
        current_hash = '/tmp/test_merge_hash/bighash_current'
        parent_hash = '/tmp/test_merge_hash/bighash_parent'
        if not os.path.exists(current_hash):
            print('start generate big hash {}'.format(current_hash))
            _generate_hash_file(range(0, blocks, 2), current_hash)

        if not os.path.exists(parent_hash):
            print('start generate big hash {}'.format(parent_hash))
            _generate_hash_file(range(1, blocks, 2), parent_hash)

        current_old = '{}_old'.format(current_hash)
        current_new = '{}_new'.format(current_hash)
        shutil.copy(current_hash, current_old)
        shutil.copy(current_hash, current_new)
        MergeHash(disk_size).merge_one2other_hash(parent_hash, current_old)
        MergeHash(disk_size).merge(current_old + '.reg', [current_old])
        MergeHash(disk_size).merge_one2other_hashv2(parent_hash, current_new)


    def test_bitmap_time():
        _disk_bytes = 1 * 1024 ** 4  # 1T
        _test_bytes = bytearray([0] * (_disk_bytes // BLK_SIZE // 8))
        _hash_logger.debug('start test iter bitmap len {}'.format(len(_test_bytes)))
        st = time.time()
        list(BitMapIter(iter(_test_bytes)))
        _hash_logger.debug('end BitMapIter cost {:.2f}s'.format(time.time() - st))
        st = time.time()
        list(BitMapIterInterval(_test_bytes, 8))
        _hash_logger.debug('end BitMapIterInterval cost {:.2f}s'.format(time.time() - st))
        st = time.time()
        list(iter_bitmap_interval(_test_bytes, 8))
        _hash_logger.debug('end iter_bitmap_interval cost {:.2f}s'.format(time.time() - st))
        st = time.time()
        list(iter_bitmap(_test_bytes))
        _hash_logger.debug('end iter_bitmap cost {:.2f}s'.format(time.time() - st))
        """
        2019-07-01 14:29:41,377 - DEBUG - start test iter bitmap len 2097152
        2019-07-01 14:29:43,822 - DEBUG - end BitMapIter cost 2.44s
        2019-07-01 14:29:46,235 - DEBUG - end BitMapIterInterval cost 2.41s
        2019-07-01 14:29:46,647 - DEBUG - end iter_bitmap_interval cost 0.41s
        2019-07-01 14:29:47,052 - DEBUG - end iter_bitmap cost 0.40s
        """


    def compare_new_old_version():
        _disk_bytes = 1 * 1024 ** 4  # 1T
        _test_bytes = bytearray([8] * (_disk_bytes // BLK_SIZE // 8))
        _hash_logger.debug('start compare_new_old_version bitmap len {}'.format(len(_test_bytes)))
        assert list(BitMapIter(iter(_test_bytes))) == list(iter_bitmap(_test_bytes))
        assert list(BitMapIterInterval(_test_bytes, 8)) == list(iter_bitmap_interval(_test_bytes, 8))
        _hash_logger.debug('end compare_new_old_version')


    # args = get_cmd_args()
    # set_bitmap_size = int(args.size)
    # file_save_path = args.new_path
    # filepath = args.mer_paths.split(',')
    # testy = MergeHash(set_bitmap_size)
    # testy.merge(file_save_path, filepath)
    # test_reorganize_hash_file()
    # test_collect_cdp_files()
    # Hash2Interval('/tmp/old.hash', '/tmp/new.hash', '/tmp/intervals').work()
    # MergeHash(21474836480).merge('/tmp/hash.old.reg', ['/tmp/hash.old'])
    # MergeHash(21474836480).merge('/tmp/test.hashv2.reg', ['/tmp/test.hashv2'])
    # test_merge_hash()

    test_bitmap_time()
    compare_new_old_version()
