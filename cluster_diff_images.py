import ctypes
import hashlib
import itertools
import operator
import os
import queue
import threading
import zlib

import compare_aio_hash
import logicService
import nbd
import xlogging

_logger = xlogging.getLogger(__name__)

import IMG

hash_helper = ctypes.cdll.LoadLibrary(r'/sbin/aio/hash_helper.so')

DIFF_HOST_IDENT = operator.itemgetter(0)
DISK_INDEX = operator.itemgetter(1)
SECTOR_OFFSET = operator.itemgetter(2)
IMAGE_HANDLE = operator.itemgetter(3)
HASH_FILE = operator.itemgetter(4)
HASH_FILE_LOCKER = operator.itemgetter(5)


class OtherThreadFailed(Exception):
    pass


class ClusterDiffImage(threading.Thread):
    def __init__(self, setting, read_blocks, error):
        super(ClusterDiffImage, self).__init__()
        self.name = r'ClusterDiffImage_{}'.format(setting['diff_image_path'])
        self._setting = setting
        self._read_blocks = read_blocks
        self._error = error
        self._blocks = 0

    def run(self):
        try:
            time0_hash_files = self.get_time0_hash_files()
            combination = self.generate_combination(time0_hash_files)
            if len(combination):
                self.search_diff_blocks(combination)
        except OtherThreadFailed:
            _logger.error(r'ClusterDiffImage {} OtherThreadFailed {}'.format(self.name, self._error.error))
        except Exception as e:
            _logger.error(r'ClusterDiffImage {} failed {}'.format(self.name, e), exc_info=True)
            self._error.set_error(e)
        finally:
            _logger.info(r'{} blocks : {}'.format(self.name, self._blocks))
            self._setting = None
            self._read_blocks = None
            self._error = None

    def get_time0_hash_files(self):
        time0_hash_files = list()
        for map_disk in self._setting['map_disks']:
            if not os.path.exists(map_disk['time0_hash_path']):
                _logger.warning(r'not exist {}'.format(map_disk['time0_hash_path']))
                continue
            time0_hash_files.append(map_disk['time0_hash_path'])
        return time0_hash_files

    @staticmethod
    def generate_combination(sorted_hash_files):
        sorted_hash_files_count = len(sorted_hash_files)
        if sorted_hash_files_count == 0:
            return list()
        elif sorted_hash_files_count == 1:
            return [(sorted_hash_files[0], None), ]
        else:
            return list(itertools.combinations(sorted_hash_files, 2))

    def search_diff_blocks(self, combination):
        for pair in combination:
            self.search_diff_blocks_in_pair(pair[0], pair[1])

    def search_diff_blocks_in_pair(self, left_path, right_path):
        if right_path is None:
            self.push_all_hash_file(left_path)
        else:
            compare_aio_hash.fetch_changes(left_path, right_path, None, self.search_diff_blocks_in_pair_callback, r',',
                                           cmp_type=r'cmp_hex_str')

    def push_all_hash_file(self, file_path):
        with open(file_path) as f:
            for line in f:
                self.push_one_line(line.strip())

    def push_one_line(self, line):
        if self._error.has_error:
            raise OtherThreadFailed()
        if ',' not in line:
            return
        self._blocks += 1
        self._read_blocks.put(
            (self._setting['diff_host'], self._setting['disk_index'], int(line.split(',')[0], 16),
             self._setting['diff_image_handle'],
             self._setting['diff_hash_file'], self._setting['diff_hash_file_locker'])
        )

    def search_diff_blocks_in_pair_callback(self, context, key, change_type, oldline, newline):
        if self._error.has_error:
            raise OtherThreadFailed()
        self._blocks += 1
        self._read_blocks.put(
            (self._setting['diff_host'], self._setting['disk_index'], int(key, 16), self._setting['diff_image_handle'],
             self._setting['diff_hash_file'], self._setting['diff_hash_file_locker'])
        )


class DiffError(object):
    def __init__(self):
        self.error = None

    @property
    def has_error(self):
        return self.error is not None

    def set_error(self, e):
        self.error = e


class ClusterDiffImages(object):
    def __init__(self, config):
        self._config = config
        self._error = DiffError()
        self._read_blocks = queue.Queue(len(config) * 256)
        self._read_block_worker_threads = list()
        self._read_block_worker_quit = False
        self._read_semaphore = dict()
        for _ in range(len(config) * 2):
            t = threading.Thread(target=self.read_block_worker)
            t.daemon = True
            self._read_block_worker_threads.append(t)
        self._cluster_diff_image_worker_threads = list()
        for setting in config:
            t = ClusterDiffImage(setting, self._read_blocks, self._error)
            t.daemon = True
            self._cluster_diff_image_worker_threads.append(t)
            self._read_semaphore[setting['disk_index']] = threading.Semaphore(4)

    def generate(self):
        self.clean()

        try:
            self.create_images()

            for t in self._cluster_diff_image_worker_threads:
                t.start()
            for t in self._read_block_worker_threads:
                t.start()
            for t in self._cluster_diff_image_worker_threads:
                t.join()
            self._read_blocks.join()
            self._read_block_worker_quit = True
            for t in self._read_block_worker_threads:
                t.join()
            error = self._error.error
        except Exception as e:
            _logger.error(r'ClusterDiffImages failed {}'.format(e), exc_info=True)
            error = e
        finally:
            self.close_images()

        self._error = None
        self._read_blocks = None
        self._read_block_worker_threads = None
        self._cluster_diff_image_worker_threads = None

        if error is not None:
            self.clean()
            raise error

    def clean(self):
        for setting in self._config:
            os.system(r'rm -f {}'.format(setting['diff_image_path']))

    def create_images(self):
        for setting in self._config:
            new_ident = IMG.ImageSnapshotIdent(setting['diff_image_path'], 'diff')
            setting['diff_image_handle'] = logicService.createNormalDiskSnapshot(
                new_ident, [], setting['diff_image_bytes'],
                r'PiD{:x} LogicService|ClusterDiffImages {}'.format(os.getpid(), setting['diff_image_path']))

            hash_file_path = setting['diff_image_path'] + '_diff.hash'
            setting['diff_hash_file'] = open(hash_file_path, 'w')
            setting['diff_hash_file_locker'] = threading.Lock()

    def close_images(self):
        for setting in self._config:
            handle = setting.get('diff_image_handle', None)
            if handle:
                logicService.closeNormalDiskSnapshot(handle, True)
            hash_file = setting.get('diff_hash_file', None)
            if hash_file:
                hash_file.close()

    def read_block_worker(self):
        _blocks = 0
        try:
            while True:
                block = None
                try:
                    block = self._read_blocks.get(timeout=1)
                    self._read_blocks.task_done()
                except queue.Empty:
                    if self._read_block_worker_quit:
                        break

                if self._error.has_error or block is None:
                    continue

                try:
                    with self._read_semaphore[DISK_INDEX(block)]:
                        bs = logicService.readDisk(DIFF_HOST_IDENT(block), DISK_INDEX(block), SECTOR_OFFSET(block), 128)
                    logicService.write2NormalDiskSnapshot(IMAGE_HANDLE(block), 512 * SECTOR_OFFSET(block), bs)
                    self.calc_hash_value(block, bs)

                    _blocks += 1
                except Exception as e:
                    _logger.error(r'read_block_worker failed {} {}'.format(block, e))
                    self._error.set_error(e)
        finally:
            _logger.info(r'read_block_worker read blocks : {}'.format(_blocks))

    @staticmethod
    def calc_hash_value(block, bs):
        sector_offset = [SECTOR_OFFSET(block)]
        blk_lens = [len(bs)]
        length = 1
        sector_offset_c = (ctypes.c_ulonglong * length)(*sector_offset)
        blk_lens_c = (ctypes.c_int * length)(*blk_lens)

        hash_bytes = 64
        hash_buffer = ctypes.create_string_buffer(hash_bytes * length)
        returned = hash_helper.hash_blk_multi(
            bytes(bs),
            sector_offset_c,
            blk_lens_c,
            ctypes.c_int32(length),
            hash_buffer,
            ctypes.c_int32(hash_bytes))
        if returned != 0:
            raise Exception('_generate_and_add_new_hash return != 0')
        else:
            with HASH_FILE_LOCKER(block):
                HASH_FILE(block).write(hash_buffer.raw.decode("utf-8").rstrip('\x00'))


class ClusterDiffImagesTest(ClusterDiffImages):
    def __init__(self, config):
        super(ClusterDiffImagesTest, self).__init__(config)
        if not os.path.exists('/dev/shm/test_cluster_diff'):
            self._read_block_worker_threads = list()
            t = threading.Thread(target=self.read_block_worker)
            t.daemon = True
            self._read_block_worker_threads.append(t)

    def clean(self):
        pass  # do nothing

    def create_images(self):
        for setting in self._config:
            if os.path.exists(setting['diff_image_path']):
                setting['diff_image_handle'] = os.open(setting['diff_image_path'], os.O_RDWR)
            else:
                setting['diff_image_handle'] = os.open(setting['diff_image_path'], os.O_RDWR | os.O_CREAT)
            hash_file_path = setting['diff_image_path'] + '_diff.hash'
            setting['diff_hash_file'] = open(hash_file_path, 'w')
            setting['diff_hash_file_locker'] = threading.Lock()

    def close_images(self):
        for setting in self._config:
            handle = setting.get('diff_image_handle', None)
            if handle:
                os.close(handle)
            hash_file = setting.get('diff_hash_file', None)
            if hash_file:
                hash_file.close()

    def read_block_worker(self):
        _blocks = 0
        try:
            while True:
                block = None
                try:
                    block = self._read_blocks.get(timeout=1)
                    self._read_blocks.task_done()
                except queue.Empty:
                    if self._read_block_worker_quit:
                        break

                if self._error.has_error or block is None:
                    continue

                try:
                    bs = logicService.readDisk(DIFF_HOST_IDENT(block), DISK_INDEX(block), SECTOR_OFFSET(block), 128)

                    if DISK_INDEX(block) == 30 and os.path.exists('/dev/shm/test_cluster_diff'):
                        r_bin = os.pread(IMAGE_HANDLE(block), len(bs), 512 * SECTOR_OFFSET(block))
                        if r_bin != bs:
                            with open('/dev/shm/error_bin', 'wb') as www:
                                www.write(bs)
                            raise Exception(
                                '发现数据不同？！ disk_idx : {}  sector_offset : {}'.format(
                                    DISK_INDEX(block), SECTOR_OFFSET(block)))
                    else:
                        os.pwrite(IMAGE_HANDLE(block), bs, 512 * SECTOR_OFFSET(block))
                    self.calc_hash_value(block, bs)

                    _blocks += 1
                except Exception as e:
                    _logger.error(r'read_block_worker failed {} {}'.format(block, e))
                    self._error.set_error(e)
        finally:
            _logger.info(r'read_block_worker read blocks : {}'.format(_blocks))


class CalcClusterTime0Hash(object):
    BITMASK = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
    BLOCK_BYTE_SIZE = 64 * 1024
    BLOCK_SECTOR_SIZE = 128

    def __init__(self, config):
        self._config = config
        self._nbd_object = nbd.nbd_wrapper(
            nbd.nbd_wrapper_disable_lvm_allocator(nbd.nbd_wrapper_local_device_allocator()))
        self._nbd_thread = None

    def calc(self):
        required_bitmap = self._get_required_bitmap()
        try:
            self._start_nbd()
            disk_block_offset = 0
            with open(self._nbd_object.device_path, 'rb') as r:
                with open(self._config['time0_hash_path'], 'w') as w:
                    for b in required_bitmap:
                        if b == 0:
                            disk_block_offset += 8
                            continue
                        self._calc_bit_entry(disk_block_offset, b, r, w)
                        disk_block_offset += 8
        finally:
            self._stop_nbd()

    def _calc_bit_entry(self, disk_block_offset, bit_entry, r, w):
        for i in range(0, 8):
            if bit_entry & self.BITMASK[i] == 0:
                continue
            sector_offset = self.BLOCK_SECTOR_SIZE * (disk_block_offset + i)
            byte_offset = self.BLOCK_BYTE_SIZE * (disk_block_offset + i)
            byte_end = min((byte_offset + self.BLOCK_BYTE_SIZE), self._config['disk_bytes'])
            assert byte_offset < byte_end
            block_content = os.pread(r.fileno(), byte_end - byte_offset, byte_offset)
            w.write('{:x},{}\n'.format(sector_offset, self._calc_hash(block_content)))

    @staticmethod
    def _calc_hash(content):
        return hashlib.md5(content).hexdigest() + '{:08x}'.format(zlib.adler32(content))

    def _stop_nbd(self):
        self._nbd_object.unmount()
        self._nbd_object.wait_no_mounting()
        self._nbd_object.set_no_longer_used()
        self._nbd_object = None

    def _start_nbd(self):
        name = r'CalcClusterTime0Hash ({})'.format(self._nbd_object.device_path)
        self._nbd_thread = nbd.nbd_direct_images(name, self._nbd_object, self._config['snapshots'])
        self._nbd_thread.start()
        nbd.nbd_wrapper.wait_nbd_read_ok(self._nbd_object)

    def _get_required_bitmap(self):
        cdp_idents = [IMG.ImageSnapshotIdent(x['path'], x['snapshot']) for x in self._config['cdps']]
        flag = r'PiD{:x} LogicService|CalcClusterTime0Hash {}'.format(
            os.getpid(), os.path.split(self._config['time0_hash_path'])[1])
        with logicService.SnapshotsUsedBitMap(cdp_idents, flag) as fd:
            return fd.read()
