import json
import queue
import logging
import uuid
import threading
import os
import argparse
import sys
import time
import traceback
import merge_hash_core

import Ice

import xlogging
import IMG
import Box
import Utils

_logger = xlogging.getLogger(__name__)


def _to_ice(path, ident):
    return IMG.ImageSnapshotIdent(path, ident)


def createNormalDiskSnapshot(ident, last_snapshot, disk_bytes, flag):
    handle = client.getImgPrx().create(ident, last_snapshot, disk_bytes, flag)
    if handle == 0 or handle == -1:
        xlogging.raise_system_error(
            r'创建快照磁盘镜像失败',
            r'create snapshot {} - {} failed, {} {} {}'.format(ident, last_snapshot, disk_bytes, handle, flag),
            handle,
        )
    else:
        _logger.info(r'createNormalDiskSnapshot ok {} {} {} {} {}'.format(
            handle, ident, last_snapshot, disk_bytes, flag))
        return handle


def deleteNormalDiskSnapshot(path, ident):
    _logger.info(r'deleteNormalDiskSnapshot : {} {}'.format(path, ident))
    client.getImgPrx().DelSnaport(IMG.ImageSnapshotIdent(path, ident))


def closeNormalDiskSnapshot(handle, successful):
    _logger.info(r'closeNormalDiskSnapshot : {} {}'.format(handle, successful))
    client.getImgPrx().close(handle, successful)


def write2NormalDiskSnapshot(handle, byteOffset, data):
    try:
        client.getImgPrx().write(handle, byteOffset, data)
    except Utils.SystemError as e:
        if e.rawCode == -28:
            xlogging.raise_system_error(r'快照文件写入失败，存储空间不足',
                                        '{} {} {} {}'.format(e.description, e.debug, handle, byteOffset),
                                        e.rawCode)
        elif e.rawCode == -12:
            xlogging.raise_system_error(r'快照文件写入失败，写入偏移大于磁盘大小',
                                        '{} {} {} {}'.format(e.description, e.debug, handle, byteOffset),
                                        e.rawCode)
        else:
            xlogging.raise_system_error(r'快照文件写入失败', '{} {} {} {}'.format(e.description, e.dubug, handle, byteOffset),
                                        e.rawCode)
    except Exception as e:
        xlogging.raise_system_error(r'快照文件写入失败',
                                    'write2NormalDiskSnapshot failed {} {} {}'.format(handle, byteOffset, e), 1)


def readNormalDiskSnapshot(handle, byteOffset, size):
    try:
        _size, data = client.getImgPrx().read(handle, byteOffset, size)
        if _size != size:
            raise Exception('readNormalDiskSnapshot fail, _size != size _size:{} size:{}'.format(_size, size))
        return data
    except Exception as e:
        xlogging.raise_system_error(r'快照文件读失败',
                                    'readNormalDiskSnapshot failed {} {} {} {}'.format(handle, byteOffset, size, e), 2)


def readNormalDiskSnapshotEx(handle, byteOffset, size):
    try:
        _size, data = client.getImgPrx().readEx(handle, byteOffset, size)
        if _size != size:
            raise Exception('readNormalDiskSnapshotEx fail, _size != size _size:{} size:{}'.format(_size, size))
        return data
    except Exception as e:
        xlogging.raise_system_error(r'快照文件读失败1',
                                    'readNormalDiskSnapshotEx failed {} {} {} {}'.format(handle, byteOffset, size,
                                                                                         e), 3)


def openDiskSnapshot(snapshots, flag):
    handle = client.getImgPrx().open(snapshots, flag)
    if handle == 0 or handle == -1:
        xlogging.raise_system_error(
            r'打开快照磁盘镜像失败',
            r'open snapshot {} failed, {} {}'.format(snapshots, handle, flag),
            handle,
        )
    else:
        _logger.info(r'openDiskSnapshot ok {} {} {}'.format(handle, snapshots, flag))
        return handle


class LoggerAdapter(logging.LoggerAdapter):

    def process(self, msg, kwargs):
        return '{} [{}] {}'.format(threading.current_thread().name, self.extra['prefix'], msg), kwargs


@xlogging.convert_exception_to_value(None)
def _remove_no_exception(path):
    if os.path.exists(path):
        os.remove(path)


class WriteQcow(object):
    def __init__(self, write_handle):
        self._write_handle = write_handle

    def write(self, offset, content):
        write2NormalDiskSnapshot(self._write_handle, offset, content)

    def close(self, successful):
        closeNormalDiskSnapshot(self._write_handle, successful)
        self._write_handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close(exc_type is None)
        return False


class ClusterReadDisk(object):
    def __init__(self, params):
        self._params = params
        self._handle = None
        self._flag = r'PiD{:x} cluster read disk|read disk {}'.format(os.getpid(), self._params['disk_id'])

    def _open(self, snapshots, flag):
        return openDiskSnapshot(snapshots, flag)

    def read(self, offset, size, hash_value, hash_type):
        if offset + size > self._params['new_qcow']['disk_bytes']:
            size = self._params['new_qcow']['disk_bytes'] - offset
        args = {
            'type': 'read_disk',
            'disk_index': str(self._params['disk_id']),
            'sectorOffset': str(offset // 512),
            'numberOfSectors': str(size // 512),
            'hash': hash_value,
            'hash_ver': '1',
        }
        new_hash, res_raw = client.getBoxPrx().JsonFuncV2(self._params['host_ident'], json.dumps(args), b'')
        if res_raw:  # 客户端处hash与传入的hash值不一致
            return new_hash, res_raw
        else:
            return hash_value, readNormalDiskSnapshotEx(self._handle, offset, size)

    def close(self):
        closeNormalDiskSnapshot(self._handle, True)
        self._handle = None

    def __enter__(self):
        _snapshots = [_to_ice(sn['path'], sn['ident']) for sn in self._params['source_snapshots']]
        self._handle = self._open(_snapshots, self._flag)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class TaskMainLogic(object):

    def __init__(self, params):
        self._params = params
        self._logger = LoggerAdapter(_logger,
                                     {'prefix': 'TaskMainLogic_{}'.format(uuid.uuid4().hex[-6:])})

        self._works = list()
        self._error = None
        self._end_flag = object()
        self._in_debug = True

        self._blocks_queue = queue.Queue(32)
        self._content_queue = queue.Queue(32)
        self._hash_queue = queue.Queue(32)
        self._flag = r'PiD{:x} cluster gen qcow|write qcow {}'.format(os.getpid(), self._params['new_qcow']['ident'])

        self._blk_counts = merge_hash_core.Counter()  # 总共块个数
        self._read_blk_counts = merge_hash_core.Counter()  # 读取块个数
        self._write_blk_counts = merge_hash_core.Counter()  # 写hash块个数

    def _create_qcow(self):
        _new_snapshot = _to_ice(self._params['new_qcow']['path'], self._params['new_qcow']['ident'])
        return createNormalDiskSnapshot(_new_snapshot, list(), self._params['new_qcow']['disk_bytes'],
                                        self._flag)

    def _delete_snapshot(self):
        deleteNormalDiskSnapshot(self._params['new_qcow']['path'], self._params['new_qcow']['ident'])

    def work(self):
        """
        读取hash文件，根据得到offset, hash
        调用客户端接口 testHash(host_ident, disk_id, bytes_offset, bytes_size, hash_version, hash_value)
        如果hash-value 一致，agent报告读取成功，且hash一致。 这个时候就将该block从source_snapshots磁盘快照链读取并写入new_qcow
        如果hash_value不一样，agent报告读取成功并传送回数据，这个时候就将该数据写入new_qcow中
        """
        # 产生线段线程
        try:
            self._logger.info('main logic begin, {}'.format(self._params))
            st = time.time()
            read_works = 5
            write_works = 5
            self._logger.info(
                '{} read workers {} write workers'.format(read_works, write_works))
            self._delete_snapshot()
            with ClusterReadDisk(self._params) as read_handle:
                with WriteQcow(self._create_qcow()) as write_handle:
                    # 读hash文件线程
                    generate_blocks_ins = threading.Thread(target=self._work_read_hash_file,
                                                           args=(self._params['hash_path'], self._blocks_queue))
                    generate_blocks_ins.setDaemon(True)
                    generate_blocks_ins.start()

                    # 读线程
                    read_work_ins = list()
                    for _ in range(read_works):
                        wk = threading.Thread(target=self._read_worker,
                                              args=(self._blocks_queue, self._content_queue,
                                                    self._hash_queue, read_handle))
                        wk.setDaemon(True)
                        wk.start()
                        read_work_ins.append(wk)

                    # 写数据线程
                    write_work_ins = list()
                    for _ in range(write_works):
                        wk = threading.Thread(target=self._write_worker,
                                              args=(self._content_queue, write_handle))
                        wk.setDaemon(True)
                        wk.start()
                        write_work_ins.append(wk)

                    # 写hash线程
                    write_hash_ins = threading.Thread(target=self._write_hash_worker,
                                                      args=(self._hash_queue,))
                    write_hash_ins.setDaemon(True)
                    write_hash_ins.start()

                    debug_ins = threading.Thread(target=self._work_debug,
                                                 args=(self._blocks_queue, self._hash_queue, self._content_queue))
                    debug_ins.setDaemon(True)
                    debug_ins.start()

                    generate_blocks_ins.join()
                    self._blocks_queue.join()
                    for _ in read_work_ins:
                        self._blocks_queue.put(self._end_flag)
                    for th in read_work_ins:
                        th.join()

                    # 写hash退出
                    self._hash_queue.join()
                    self._hash_queue.put(self._end_flag)
                    write_hash_ins.join()

                    self._content_queue.join()
                    for _ in write_work_ins:
                        self._content_queue.put(self._end_flag)
                    for th in write_work_ins:
                        th.join()

                    self._in_debug = False
                    debug_ins.join()
                    if self._error:
                        raise self._error
                    assert self._blk_counts.count == self._read_blk_counts.count == self._write_blk_counts.count, '生成qcow数据不准确'

                    blks = self._blk_counts.count
                    cost_time = time.time() - st
                    spend = (blks * 64 * 1024) / (cost_time * 1024 ** 2)
                    self._logger.info('generate {} blocks'.format(blks))
                    self._logger.info('use {:.2f}s'.format(cost_time))
                    self._logger.info('spend {:.2f}MB/s'.format(spend))
                    self._logger.info('end generate')
        except Exception as e:
            self._logger.error('error:{}'.format(e), exc_info=True)
            raise e
        finally:
            self._logger.info('main logic end, {}'.format(self._params))

    def _work_read_hash_file(self, file_path, blocks_queue):
        try:
            with open(file_path) as rf:
                while not self._error:
                    line = rf.readline()
                    if not line:
                        break
                    offset_org, type_org, hash_str = line.strip('\n').split(',')
                    blocks_queue.put((int(offset_org, 16) * 512, type_org, hash_str))
                    self._blk_counts.inc()
        except Exception as e:
            self._logger.error('_work_read_hash_file error:{}'.format(e), exc_info=True)
            self._error = e

    def _work_debug(self, _blocks_queue, _hash_queue, _content_queue):
        try:
            last_time = time.time()
            while self._in_debug:
                if time.time() - last_time > 10:
                    last_time = time.time()
                    self._logger.debug(
                        '_blocks_queue {} _hash_queue {} _content_queue {} already write {} blks'.format(
                            _blocks_queue.qsize(),
                            _hash_queue.qsize(),
                            _content_queue.qsize(),
                            self._write_blk_counts.count
                        ))
                time.sleep(1)
        except Exception as e:
            self._logger.error('_work_debug error:{}'.format(e))

    def _read_worker(self, blocks_queue, content_queue, hash_queue, read_handle):
        while True:
            item = blocks_queue.get()
            try:
                if item is self._end_flag:
                    break
                if self._error:
                    continue
                bytes_offset, type_org, hash_str = item
                new_hash, data = read_handle.read(bytes_offset, 64 * 1024, hash_str, type_org)
                content_queue.put((bytes_offset, data))
                self._read_blk_counts.inc()
                hash_queue.put((bytes_offset, type_org, new_hash))
            except Exception as e:
                self._logger.error('_read_worker error:{}'.format(e), exc_info=True)
                self._error = e
            finally:
                blocks_queue.task_done()

    def _write_worker(self, content_queue, write_handle):
        while True:
            item = content_queue.get()
            try:
                if item is self._end_flag:
                    break
                if self._error:
                    continue
                bytes_offset, data = item
                write_handle.write(bytes_offset, data)
                self._write_blk_counts.inc()
            except Exception as e:
                self._logger.error('_write_worker error:{}'.format(e), exc_info=True)
                self._error = e
            finally:
                content_queue.task_done()

    def _write_hash_worker(self, hash_queue):
        with open(self._params['new_qcow_hash'], 'w') as wf:
            while True:
                item = hash_queue.get()
                try:
                    if item is self._end_flag:
                        break
                    if self._error:
                        continue
                    bytes_offset, hash_type, hash_value = item
                    wf.write('0x{:x},{},{}\n'.format(bytes_offset // 512, hash_type, hash_value))
                except Exception as e:
                    self._logger.error('_write_hash_worker error:{}'.format(e), exc_info=True)
                    self._error = e
                finally:
                    hash_queue.task_done()


def get_init_data():
    initData = Ice.InitializationData()
    initData.properties = Ice.createProperties()
    initData.properties.setProperty(r'Ice.LogFile', r'/var/log/aio/logic_service_cluster_ice.log')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.Size', r'8')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.SizeMax', r'64')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.StackSize', r'8388608')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.Size', r'8')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.SizeMax', r'64')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.StackSize', r'8388608')
    initData.properties.setProperty(r'Ice.Default.Host', r'localhost')
    initData.properties.setProperty(r'Ice.Warn.Connections', r'1')
    initData.properties.setProperty(r'Ice.ACM.Heartbeat', r'3')
    initData.properties.setProperty(r'Ice.ThreadPool.Client.ThreadIdleTime', r'0')
    initData.properties.setProperty(r'Ice.ThreadPool.Server.ThreadIdleTime', r'0')
    initData.properties.setProperty(r'BoxSerivce.Proxy', r'apis : tcp -h 127.0.0.1 -p 21105')
    initData.properties.setProperty(r'ImageSerivce.Proxy', r'img : tcp -h 127.0.0.1 -p 21101')
    initData.properties.setProperty(r'Ice.MessageSizeMax', r'131072')  # 单位KB, 128MB

    config_path = r'/etc/aio/logic_service.cfg'
    if os.path.exists(config_path):
        initData.properties.load(config_path)

    return initData


def get_args():
    args = argparse.ArgumentParser('generate qcow')
    args.add_argument('file_path', help='file path')
    return args.parse_args()


class Client(Ice.Application):
    def __init__(self, *args, **kwargs):
        super(Client, self).__init__(*args, **kwargs)
        xlogging.TraceDecorator(ignore=['run', 'main', 'doMain', 'getBoxPrx', 'getImgPrx', 'communicator']).decorate()
        xlogging.ExceptionHandlerDecorator().decorate()

        self.__boxPrx = None
        self.__imgPrx = None

    def run(self, args):
        _args = get_args()
        with open(_args.file_path) as f:
            content = json.load(f)
        TaskMainLogic(content).work()
        return 0

    def getBoxPrx(self):
        if self.__boxPrx is None:
            self.__boxPrx = Box.ApisPrx.checkedCast(self.communicator().propertyToProxy(r'BoxSerivce.Proxy'))
        return self.__boxPrx

    def getImgPrx(self):
        if self.__imgPrx is None:
            self.__imgPrx = IMG.ImgServicePrx.checkedCast(self.communicator().propertyToProxy(r'ImageSerivce.Proxy'))
        return self.__imgPrx


if __name__ == '__main__':
    client = Client()
    sys.exit(client.main(sys.argv, initData=get_init_data()))
