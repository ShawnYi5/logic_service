import threading
import xlogging
import os
import datetime
import json
import copy
import uuid
import shutil
import sys
import collections
import time
import errno

try:
    from . import tape_librarian
    from .models import MediaTaskRecord
except Exception:
    import tape_librarian
    from models import MediaTaskRecord

status = [
    (0, 'successful'),
    (-1, 'error'),  # 表示出错，见错误信息。
    (-2, 'need waite'),  # 表示media_rw_obj对象不足，需要释放之前的所有media_rw_obj才能用。
    (-3, 'busy'),  # 表示设备繁忙。
]


class MBaseException(Exception):
    def __init__(self, msg, debug, code):
        self.msg = msg
        self.debug = debug
        self.code = code

    def __str__(self):
        return '{}:{} {} {}'.format(self.__class__.__name__, self.msg, self.debug, self.code)


_logger = xlogging.getLogger('tape_r')


class MediaTarget(object):
    def __init__(self, media_uuid, media_data):
        self.media_uuid = copy.copy(media_uuid)  # 要跟子类共用。
        self.media_data = copy.copy(media_data)  # 要跟子类共用。
        self.align_size = 64 * 1024
        self.__lock = threading.RLock()  # 不能重写。

        self.writetask = False
        self.__task_info = None  # 不能重写。
        self.__taskext = dict()  #
        self.__handles = list()  # 不能重写。
        self.__file_uuids_list = list()  # 不能重写。
        self.__uuid_used_check = dict()
        self.__task_size = 0  # 不能重写。
        self.__filecount = 0
        self.__successful = False
        self.__task_recordInfo = None
        self.__readcache = None
        self.__readcache_len = 0
        self.__write_error = 0

    def clean_task(self):
        self.writetask = False
        self.__task_info = None  # 不能重写。
        self.__taskext = dict()  #
        self.__handles = list()  # 不能重写。
        self.__file_uuids_list = list()  # 不能重写。
        self.__uuid_used_check = dict()
        self.__task_size = 0  # 不能重写。
        self.__filecount = 0
        self.__successful = False
        self.__task_recordInfo = None
        self.__readcache = None
        self.__readcache_len = 0
        self.__write_error = 0

    def media_start_task(self, task_info):
        pass

    def media_finish_task(self, is_successful):
        pass

    def media_get_write_handle(self, file_uuid):
        pass

    def media_get_read_handle(self, file_name_uuid):
        pass

    def media_write(self, fd, data):
        pass

    def media_read(self, fd, size):
        pass

    def media_close(self, fd):
        pass

    def start_task(self, task_info):
        """
        :param task_info: 包含此次任务需要写入的大小 {'size':1111, 'task_uuid':'', 'task_date':''}
        :return:
        """
        with self.__lock:
            if self.__task_info is None:
                _logger.info('LocalMediaTarget start task, task info:{}'.format(task_info))
                self.clean_task()
                if True:
                    # try:
                    self.media_start_task(task_info)
                    self.__task_info = task_info
                    self.writetask = True
                    self.new_task_record()
                    # except Exception as e:
                    #    raise MBaseException('任务开始失败', 'start task fail, {}'.format(e), 301)
                    # else:
                    return 0, ''
            else:
                return -1, task_info  # 正在任务

    def get_write_handle(self, file_uuid):
        with self.__lock:
            if self.__uuid_used_check.get(file_uuid, None) is not None:
                raise MBaseException('文件重复添加', 'file has in handles', 300)
            if True:
                # try:
                fd, size = self.media_get_write_handle(file_uuid)
                if -1 == fd:
                    return fd, size
                self.__write_error = 0
                self.__uuid_used_check[file_uuid] = fd
                fdIndex = self.__filecount
                self.__filecount = self.__filecount + 1
                self.__handles.append(fd)
                self.__file_uuids_list.append(file_uuid)
                if self.__handles[fdIndex] != fd:
                    raise MBaseException('internal error 1', 'internal error 1', 302)
                if self.__file_uuids_list[fdIndex] != file_uuid:
                    raise MBaseException('internal error 2', 'internal error 2', 303)
            # except Exception as e:
            #   raise MBaseException('获取写句柄失败', 'get write fail, {}'.format(e), 304)
        return fdIndex, size

    def get_read_handle(self, file_info):
        with self.__lock:
            if self.__task_info is None:
                _logger.info('LocalMediaTarget get_read_handle:{}'.format(file_info))
                self.__task_info = file_info
                self.writetask = False
                return self.media_get_read_handle(file_info), ''
            else:
                return -1, self.__task_info

    def write(self, fdIndex, data):
        if fdIndex < 0 or fdIndex >= len(self.__handles):
            _logger.info('media_write error fdIndex:{},size:{}'.format(fdIndex, len(data)))
            self.__write_error = -1
            return -1, 'error fd'
        self.__task_size = self.__task_size + len(data)
        _write_err, info = self.media_write(self.__handles[fdIndex], data)
        if _write_err != 0:
            self.__write_error = -1

        return _write_err, info

    def read(self, fd, size):
        # _logger.info('MediaTarget read(fd:{},size:{})'.format(fd, size))

        if size <= self.__readcache_len:
            # in cache
            retbs = self.__readcache[0:size]
            self.__readcache = self.__readcache[size:self.__readcache_len]
            self.__readcache_len -= size
            _logger.info('MediaTarget read(fd:{},size:{}) return {}'.format(fd, size, len(retbs)))
            return 0, retbs
        need_size = size - self.__readcache_len
        readsize = (need_size + self.align_size - 1) // self.align_size * self.align_size

        ret, newbs = self.media_read(fd, readsize)
        if 0 != ret:
            return ret, newbs

        if self.__readcache_len != 0:
            # 之前有数据。合并使用。
            retbs = self.__readcache + newbs[:need_size]
            self.__readcache_len = readsize - need_size
        else:
            # 全新的数据。
            retbs = newbs[:size]
            self.__readcache_len = readsize - size

        if self.__readcache_len != 0:
            # 还有数据
            self.__readcache = newbs[readsize - self.__readcache_len:]

        # 因为磁带库只能块对其读。
        # _logger.info('MediaTarget read(fd:{},size:{}) return {}'.format(fd, size, len(retbs)))

        return 0, retbs

    def close(self, fdIndex):
        _logger.info('start close fdIndex:{}'.format(fdIndex))
        if self.writetask:
            if fdIndex < 0:
                return
            file_uuid = self.__file_uuids_list[fdIndex]
            close_info = self.media_close(self.__handles[fdIndex])
            if self.__write_error == 0:
                # 只有成功，才会记录。
                _logger.info('new fdIndex:{}'.format(fdIndex))
                close_info['fdIndex'] = fdIndex
                self.__taskext[file_uuid] = close_info
                # self.update_current_task_ext()
                #  多增加一个文件，是没有必要写数据库记录的。只有在最后写了成功标记后，才有必要update
            else:
                _logger.info('skip fdIndex:{}'.format(fdIndex))
        else:
            try:
                self.media_close(fdIndex)
            finally:
                self.__task_info = None
                self.clean_task()
        _logger.info('end close fdIndex:{}'.format(fdIndex))

    def finish_task(self, is_successful):
        if not self.writetask:
            return
        with self.__lock:
            self.__successful = is_successful
            try:
                self.update_current_task_ext()
            except Exception as e:
                _logger.error("update_current_task_ext error:{}".format(e))
            self.__task_recordInfo = None
            try:
                self.media_finish_task(is_successful)
            except Exception as e:
                _logger.error("media_finish_task error:{}".format(e))
            _task_ext = self.__taskext
            self.clean_task()
            return _task_ext

    def new_task_record(self):
        self.__task_recordInfo = MediaTaskRecord.objects.create(
            production_date=self.__task_info['task_date'],  # 产生日期，统一由上层传入。
            media_uuid=self.media_uuid,  # 媒体库的uuid
            task_ext_inf=json.dumps(self.__taskext),  # task扩展信息
            occupy_size=0,
            task_uuid=self.__task_info['task_uuid'])
        return

    def update_current_task_ext(self):
        if not self.writetask or self.__task_recordInfo == None:
            return
        self.__task_recordInfo.task_ext_inf = json.dumps(self.__taskext)
        self.__task_recordInfo.file_count = self.__filecount
        self.__task_recordInfo.occupy_size = self.__task_size
        self.__task_recordInfo.successful = self.__successful
        self.__task_recordInfo.save()
        return

    def get_last_success_task(self):
        try:
            return MediaTaskRecord.objects.filter(
                MediaTaskRecord.media_uuid == self.media_uuid,
                MediaTaskRecord.successful == True
            ).order_by(MediaTaskRecord.id)[-1]
        except IndexError as e:
            return None

    def get_first_valid_task(self):
        try:
            return MediaTaskRecord.objects.filter(
                MediaTaskRecord.media_uuid == self.media_uuid,
                MediaTaskRecord.successful == True,
                MediaTaskRecord.overwritedata == False
            ).order_by(MediaTaskRecord.id)[0]
        except IndexError as e:
            return None

    def update_all_task_life_cycle(self, crt_date):
        # 跟新所有任务，该打删除标记的打删除标记。crt_date是当前的时间。
        return


class Tape_Group_Class(object):
    def __init__(self, tapes_list):
        self.__tapesOrdered = collections.OrderedDict()
        _tapes = tapes_list
        _tapedict = dict()
        for _k, _v in _tapes.items():
            _crt_id = int(_k)
            _tapedict[_crt_id] = _v

        _list_key = sorted(_tapedict)
        for _key in _list_key:
            self.__tapesOrdered[_key] = _tapedict[_key]

    def get_tape_count(self):
        return len(self.__tapesOrdered)

    def get_next_volume(self, current_volumeID):
        if 0 == len(self.__tapesOrdered):
            return -1, None
        _bFoundOut = False
        for k, v in self.__tapesOrdered.items():
            if _bFoundOut:
                return copy.copy(k), copy.copy(v)
            if current_volumeID == k:
                _bFoundOut = True
                continue
        for k, v in self.__tapesOrdered.items():
            return copy.copy(k), copy.copy(v)


class TapeMediaHardwareAPI(object):
    def __init__(self, media_data):
        self.media_data = media_data
        # 下面是设备相关的。
        self.__tape_devname = None
        self.__tape_devobj = None
        self.__mc_devname = None
        self.__mc_devobj = None
        self.__mc_drvID = -1
        self.__hardware_status = False

    def init_hardware_device(self):

        if self.__hardware_status:
            return
        self.__hardware_status = True

        mc_tape = tape_librarian.mc_and_tape_mgr()

        _tape_drv_sn = self.media_data['driver']
        self.__tape_devname = mc_tape.get_tape_devicename(_tape_drv_sn)
        if self.__tape_devname == None:
            raise MBaseException("不能找到带库驱动器{}".format(_tape_drv_sn), "can not found tape drive {}".format(_tape_drv_sn),
                                 sys._getframe().f_lineno)

        _mc_link = self.media_data['link']
        self.__mc_devname, self.__mc_drvID = mc_tape.get_mc_devicename(_tape_drv_sn, _mc_link)
        if self.__mc_devname == None:
            raise MBaseException("不能找到机械臂对应的驱动器{}".format(_tape_drv_sn),
                                 "can not found Medium Changer device{}".format(_tape_drv_sn),
                                 sys._getframe().f_lineno)

        self.__tape_devobj = tape_librarian.tape_dev_mgr(self.__tape_devname)
        self.__tape_devobj.update_tape_status()

        self.__mc_devobj = tape_librarian.Medium_Changer_devmgr(self.__mc_devname)
        self.__mc_devobj.update_Medium_Changer()

    def get_tapename(self):
        return self.__tape_devname[0]

    def get_mcname(self):
        return self.__mc_devname

    def try_check_drive_status(self):
        for _ in range(30):
            try:
                self.__tape_devobj.update_tape_status()
                if self.__tape_devobj.Ready == tape_librarian.const_yes and self.__tape_devobj.online:
                    return
                else:
                    _str = "tapeDev{} ready:{} online:{}".format(
                        self.__tape_devname, self.__tape_devobj.Ready, self.__tape_devobj.online)
                    _logger.info(_str)
            except:
                pass
            time.sleep(1)

    def try_rewind_and_set_block_size(self, _align_size):
        for _ in range(2):
            try:
                self.__tape_devobj.update_tape_status()
                if self.__tape_devobj.Ready == tape_librarian.const_yes and self.__tape_devobj.online:
                    self.__tape_devobj.set_blksize(_align_size)
                    return
                else:
                    _str = "tapeDev{} ready:{} online:{}".format(
                        self.__tape_devname, self.__tape_devobj.Ready, self.__tape_devobj.online)
                    _logger.info(_str)
                    self.__tape_devobj.set_blksize(_align_size)
            except Exception as e:
                str = "try_rewind_and_set_block_size error:{}".format(e)
                _logger.error(str)
                try:
                    self.__tape_devobj.tape_rewind()
                except Exception as e:
                    str = "tape_rewind error:{}".format(e)
                    _logger.error(str)
            time.sleep(1)

    def load_Volume(self, _crt_VolumeTag, _align_size):
        _logger.info("load_Volume({})".format(_crt_VolumeTag))
        _load_status, _load_new_volume = self.__mc_devobj.load_Volume(_crt_VolumeTag, self.__mc_drvID)
        _logger.info("load_Volume return {}".format(_load_new_volume))

        # 这里可能有的坑：
        # 1、磁带可能不能兼容这个驱动器，任何操作都可能被卡住。
        # 2、磁带没有倒带前，不能用，直接报错。
        # 3、磁带可能busy，需要等待一会。

        # 所以，处理流程如下：
        # 1、如果 noready, ，等待30秒，
        # 2、segblksize，如果失败，直接倒带。重试3次。
        self.try_check_drive_status()
        self.try_rewind_and_set_block_size(_align_size)
        if _load_new_volume:
            _logger.info("new Volume rewind")
            try:
                self.__tape_devobj.tape_rewind()
                self.try_rewind_and_set_block_size(_align_size)
            except Exception as e:
                _logger.error("tape({}) rewind error:{}".format(self.__tape_devname, e))

        return

    def seek(self, _crt_FileNO):
        return self.__tape_devobj.seek(_crt_FileNO)


class TapeSpaceMgr(object):

    def __init__(self):
        self.__all = list()
        pass

    def append_free_space(self, _vol_ID, _vol_Tag, _file_ID):
        _one = dict()
        _one[r'volumeid'] = copy.copy(_vol_ID)
        _one[r'volumetag'] = copy.copy(_vol_Tag)
        _one[r'volfileid'] = copy.copy(_file_ID)
        self.__all.append(_one)

    def use_new_volume(self):
        _logger.info("use_new_volume({})")
        self.__all.pop(0)

    def malloc_free_space(self):
        if 0 == len(self.__all):
            return None
        _first_space = copy.copy(self.__all[0])
        self.__all[0]['volfileid'] = self.__all[0]['volfileid'] + 1
        return _first_space

    def get_free_bytes(self):
        if 0 == len(self.__all):
            return 0
        # 计算空间：
        return 1024 * 1024 * 1024 * 1024 * 1024


# http://172.16.1.11/AIO/project_main/issues/4087

class TapeMediaTarget(MediaTarget):

    def __init__(self, media_uuid, media_data):
        super(TapeMediaTarget, self).__init__(media_uuid, media_data)
        self.const_max_id = 999999999  # 1G一个文件，最大就是999p。
        self.const_first_fileNO_per_vol = 0

        self.__crt_VolumeID = -1
        self.__crt_VolumeTag = None
        self.__crt_FileNO = -1
        self.__task_info = None
        self.__fd = 0
        self.__tape_space_mgr = TapeSpaceMgr()
        self.__tape_drive_locker = None
        self.__max_size_per_write = 2 * 1024 * 1024

        self.__tapeGroupMgrObj = Tape_Group_Class(self.media_data['tapas'])
        self.__hwDev = TapeMediaHardwareAPI(self.media_data)

    def __clear_tape_task(self):
        # 跟任务相关，要重置的。
        self.__crt_VolumeID = -1
        self.__crt_VolumeTag = None
        self.__crt_FileNO = -1
        self.__task_info = None
        self.__fd = 0
        self.__tape_space_mgr = TapeSpaceMgr()

        if self.__tape_drive_locker != None:
            _temp_locker = self.__tape_drive_locker
            self.__tape_drive_locker = None
            _temp_locker = None  # 最后一个这样来释放？应该没问题吧。

    def get_last_success_valid_file(self):
        _lastTask = self.get_last_success_task()
        if None == _lastTask:
            return -1, None, -1

        _logger.info("get_last_success_task _task_ext_inf({})".format(_lastTask.task_ext_inf))
        _task_ext_inf = json.loads(_lastTask.task_ext_inf)
        _maxFileID = -1
        _lastFileExt = None
        for _k, _v in _task_ext_inf.items():
            if _v['fdIndex'] > _maxFileID:
                _maxFileID = _v['fdIndex']
                _lastFileExt = _v

        return _lastFileExt['volumeid'], _lastFileExt['volumetag'], _lastFileExt['volfileid']

    def get_fist_valid_file(self):
        _firstTask = self.get_first_valid_task()
        if None == _firstTask:
            return -1, None, -1

        _logger.info("get_fist_valid_file _task_ext_inf({})".format(_firstTask.task_ext_inf))
        _task_ext_inf = json.loads(_firstTask.task_ext_inf)
        _minFileID = self.const_max_id
        _firstFileExt = None
        for _k, _v in _task_ext_inf.items():
            if _v['fdIndex'] < _minFileID:
                _minFileID = _v['fdIndex']
                _firstFileExt = _v

        return _firstFileExt['volumeid'], _firstFileExt['volumetag'], _firstFileExt['volfileid']

    # 初始化空间。
    def init_task_space(self):

        # 查第一块可用的空间。从上一个成功的文件 + 1
        _last_VolumeID, _last_VolumeTag, _last_FileNO = self.get_last_success_valid_file()
        # 从last + 1 到， first的 Volume.
        if None == _last_VolumeTag:
            # 从第一块开始用。
            _start_free_VolumeID, _start_free_VolumeTag = self.__tapeGroupMgrObj.get_next_volume(self.const_max_id)
            if _start_free_VolumeTag is None:
                # 没有磁带？
                raise MBaseException("无磁带可用!", "no tape", sys._getframe().f_lineno)
            _start_free_fileNO = self.const_first_fileNO_per_vol
        else:
            _start_free_VolumeID = _last_VolumeID
            _start_free_VolumeTag = _last_VolumeTag
            _start_free_fileNO = _last_FileNO + 1

        # 查最后一个用的磁带。
        _end_VolumeID, _end_VolumeTag, _end_FileNO = self.get_fist_valid_file()
        if _end_VolumeID == -1 or _end_VolumeTag == None:
            # 如果还没有任务，就把开始当成结束。
            _end_VolumeID = _start_free_VolumeID

        # 加入磁带:
        self.__tape_space_mgr.append_free_space(_start_free_VolumeID, _start_free_VolumeTag, _start_free_fileNO)
        _current__VolumeID = _start_free_VolumeID
        while True:
            _nextVolID, _next_VolTag = self.__tapeGroupMgrObj.get_next_volume(_current__VolumeID)
            if _nextVolID == _end_VolumeID:
                # 不能用有任务的volume..
                break
            self.__tape_space_mgr.append_free_space(_nextVolID, _next_VolTag, self.const_first_fileNO_per_vol)
            _current__VolumeID = _nextVolID

        return

    def media_start_task(self, task_info):

        _logger.info("media_start_task({})".format(task_info))

        self.__clear_tape_task()

        self.__tape_drive_locker = tape_librarian.get_tape_drive_lock()

        self.__hwDev.init_hardware_device()

        if self.__tapeGroupMgrObj.get_tape_count() <= 1:
            # 只有一盘磁带时：
            raise MBaseException("必须有2盘磁带及以上", "tape count{}".format(self.__tapeGroupMgrObj.get_tape_count()),
                                 sys._getframe().f_lineno)

        self.init_task_space()

        self.__task_info = copy.copy(task_info)

        __free = self.__tape_space_mgr.get_free_bytes()
        __need_size = task_info['size']

        if __free < __need_size:
            raise MBaseException("磁带无可用空间!", "no free spaces!{} < {} ".format(__free, __need_size),
                                 sys._getframe().f_lineno)

        return

    def __open_tape(self):

        try:
            self.__hwDev.load_Volume(self.__crt_VolumeTag, self.align_size)
        except:
            # 磁带不能用了，
            str = "设备{}加载磁带失败({})".format(self.__hwDev.get_mcname(), self.__crt_VolumeTag)
            MBaseException(str, "load volume failed", sys._getframe().f_lineno)
            _logger.error(str)
            raise Exception(str)

        crt_fileNO = self.__hwDev.seek(self.__crt_FileNO)
        if self.__crt_FileNO != crt_fileNO:
            str = "{}移动磁带失败(old: {} != current:{})".format(self.__hwDev.get_mcname(), self.__crt_FileNO, crt_fileNO)
            MBaseException(str, 'seek tape failed', sys._getframe().f_lineno)
            log.error(str)
            # raise Exception(str) 以下面打开文件为判断标准

        try:
            if self.writetask:
                mode = os.O_WRONLY | os.O_APPEND | os.O_SYNC
            else:
                mode = os.O_RDONLY
            self.__fd = os.open(self.__hwDev.get_tapename(), mode, 0o666)
        except Exception as e:
            str = "os.open{} error:{}".format(self.__hwDev.get_tapename(), e)
            MBaseException("打开磁带机驱动器({})设备失败".format(self.__hwDev.get_tapename()), str, sys._getframe().f_lineno)
            _logger.error(str)
            raise Exception(str)
        _logger.info("os.open{} success fd:{}".format(self.__hwDev.get_tapename(), self.__fd))

    def media_get_write_handle(self, file_uuid):

        _logger.info("media_get_write_handle({})".format(file_uuid))

        while True:
            free_space = self.__tape_space_mgr.malloc_free_space()
            if None == free_space:
                # 无空间可用了。
                return -1, 0

            self.__crt_VolumeID = free_space['volumeid']
            self.__crt_VolumeTag = free_space['volumetag']
            self.__crt_FileNO = free_space['volfileid']

            try:
                self.__open_tape()
            except Exception as e:
                # 继续用下一盘磁带。
                str = "__open_tape:{} error:{}".format(self.__hwDev.get_tapename(), e)
                _logger.error(str)
                self.__tape_space_mgr.use_new_volume()
                continue

            return self.__fd, 4 * 1024 * 1024 * 1024

    def media_get_read_handle(self, file_info):

        _logger.info("media_get_read_handle({})".format(file_info))

        self.__tape_drive_locker = tape_librarian.get_tape_drive_lock()

        self.__hwDev.init_hardware_device()

        self.__crt_VolumeID = file_info['volumeid']
        self.__crt_VolumeTag = file_info['volumetag']
        self.__crt_FileNO = file_info['volfileid']

        self.__open_tape()

        return self.__fd

    def media_write(self, fd, data):
        if fd != self.__fd:
            str = "error fd: {} != self:{}".format(fd, self.__fd)
            _logger.error(str)
            return -1, str

        _blk_start = 0
        _blk_end = 0
        _len = len(data)
        while _len != 0:
            _io_size = min(self.__max_size_per_write, _len)
            _blk_end = _blk_start + _io_size
            try:
                _wrdsize = os.write(self.__fd, data[_blk_start:_blk_end])
                if _wrdsize > 0:
                    # 写成功。
                    _len -= _wrdsize
                    _blk_start = _blk_start + _wrdsize
                    continue
                else:
                    _logger.error('os.write(fd:{}) error size: _wrdsize:{} != _io_size:{}'.format(
                        self.__fd, _wrdsize, _io_size))
                    self.__tape_space_mgr.use_new_volume()
                    return errno.ENOSPC, r'ENOSPC'
            except IOError as e:
                str = 'os.write(fd:{}) error({}) size: _io_size:{}'.format(self.__fd, e.errno, _io_size)
                _logger.error(str)
                if e.errno == errno.ENOSPC:
                    self.__tape_space_mgr.use_new_volume()
                    return errno.ENOSPC, r'ENOSPC'

                if e.errno == errno.EINVAL:
                    # 有的磁带机一次只能写2M，没去查究竟能写多少，就弄一个递减重试。
                    if self.__max_size_per_write <= 65536:
                        # 不能比 64k 小了。
                        return e.errno, str
                    self.__max_size_per_write /= 2
                    continue
                if e.errno == errno.EINTR or e.errno == errno.EAGAIN:
                    continue

                return -e.errno, str
        return 0, 'OK'

    def media_read(self, fd, size):
        while True:
            try:
                one_buf = os.read(self.__fd, size)
                if size != len(one_buf):
                    return -1, 'no more'
            except IOError as e:
                str = 'os.read(fd:{}) error({}) size:{}'.format(fd, e, size)
                _logger.error(str)
                if e.errno == errno.EINTR or e.errno == errno.EAGAIN:
                    continue
                return -e.errno, str
            return 0, one_buf

    def media_close(self, fd):

        _logger.info("os.close({})".format(self.__fd))
        os.close(self.__fd)
        vid = self.__crt_VolumeID
        vtag = self.__crt_VolumeTag
        vfileid = self.__crt_FileNO
        self.__fd = 0

        if not self.writetask:
            # 读取任务的时候，一个读取完成，就释放锁。
            _temp_locker = self.__tape_drive_locker
            self.__tape_drive_locker = None
            _temp_locker = None  # 最后一个这样来释放？应该没问题吧。
        # 写入任务时，必须等待任务结束后，才能释放锁。

        return {'volumeid': vid, 'volumetag': vtag, 'volfileid': vfileid}

    def media_finish_task(self, is_successful):
        self.__clear_tape_task()

        return


class LocalMediaTarget(MediaTarget):

    def __init__(self, media_uuid, data):
        super(LocalMediaTarget, self).__init__(media_uuid, data)
        self._out_path = self.media_data['path']
        self._out_dir = None
        self.path = None

    def media_start_task(self, task_info):
        self._out_dir = os.path.join(self._out_path, uuid.uuid4().hex)
        os.makedirs(self._out_dir)

    def media_finish_task(self, is_successful):
        if not is_successful:
            shutil.rmtree(self._out_dir, ignore_errors=True)

    def media_get_write_handle(self, file_uuid):
        self.path = os.path.join(self._out_dir, file_uuid)
        fd = open(self.path, 'wb')
        return fd, 1 * 1024 * 1024 * 1024

    def media_get_read_handle(self, file_info):
        return open(file_info['path'], 'rb')

    def media_write(self, fd, data):
        fd.write(data)
        return 0, ''

    def media_read(self, fd, size):
        return 0, fd.read(size)

    def media_close(self, fd):
        fd.close()
        return {'path': self.path}


class MediaTargetManager(object):
    """
    管理所有MediaTarget， 提供增删改查
    """

    def __init__(self):
        self._medias = dict()
        self._medias_lock = threading.RLock()

        t = threading.Thread(target=self.check_expired, args=(), name='MediaTargetManagerThread')
        t.setDaemon(True)
        t.start()

    def check_expired(self):
        while True:
            today = datetime.datetime.now().date()
            try:
                for media_uuid, media_target in self._medias.items():
                    dead_line = today - datetime.timedelta(days=media_target.media_data['max_days'])
                    MediaTaskRecord.objects.filter(
                        MediaTaskRecord.media_uuid == media_uuid,
                        MediaTaskRecord.successful == True,
                        MediaTaskRecord.overwritedata == False,
                        MediaTaskRecord.production_date < dead_line
                    ).update({'overwritedata': True})
            except Exception as e:
                _logger.error('MediaTargetManager check_expired error:{}'.format(e), exc_info=True)
            time.sleep(60)

    def add(self, info):
        media_uuid = info['media_uuid']
        media_type = info['media_type']
        with self._medias_lock:
            if media_uuid in self._medias:
                _logger.error('MediaTargetManager media:{} is already in'.format(media_uuid))
                return 0
            else:
                if media_type == 'tape':
                    self._medias[media_uuid] = TapeMediaTarget(media_uuid, info['info'])
                    return 0
                elif media_type == 'local':
                    self._medias[media_uuid] = LocalMediaTarget(media_uuid, info['info'])
                    return 0
                else:
                    return -1

    def delete(self):
        pass

    def get(self, media_uuid):
        with self._medias_lock:
            return self._medias.get(media_uuid)

    def put(self):
        pass

    def enum_mc_hw_info(self, info):
        return tape_librarian.enum_mc_hw_info(info)

    def operations(self, json_params):
        params = json.loads(json_params)
        rev = getattr(self, params['action'])(params['info'])
        return json.dumps({'rev': rev})


if __name__ == "__main__":
    mtmgr = MediaTargetManager()

    __media_data = dict()

    __media_data['name'] = 'tape_media_name'
    __media_data['link'] = {
        "DriveList": [{"DriveSN": "31333130323534303531", "MCSN": "30304c3255373856393532385f4c4c30", "MCBoxID": 0}]}
    __media_data['driver'] = '31333130323534303531'
    __media_data['cycle'] = 'cycle'
    __media_data['max_days'] = 33
    __media_data['cycle_type'] = 'cycle_type'
    __media_data['tapas'] = {'1': 'DH1397L4', '2': "DH1398L4", '11': "DH1399L4"}

    __inf = dict()
    __inf['media_uuid'] = 'test_media_uuid'
    __inf['media_type'] = 'tape'
    __inf['info'] = __media_data
    mtmgr.add(__inf)

    tapeDev = mtmgr.get('test_media_uuid')

    taskinfo = dict()
    taskinfo['size'] = 123456789
    taskinfo['task_uuid'] = uuid.uuid4().hex
    taskinfo['task_date'] = datetime.datetime.now()  # ('%Y_%m_%dT%H_%M_%S')
    tapeDev.start_task(taskinfo)
    for i in range(3):
        __mfd, wrsize = tapeDev.get_write_handle(uuid.uuid4().hex)
        bs = bytearray(65536)
        ret, err = tapeDev.write(__mfd, bs)
        tapeDev.close(__mfd)
        __mfd, wrsize = tapeDev.get_write_handle(uuid.uuid4().hex)
        s = 0
        wrsize = 1000000
        while s < wrsize:
            bs = bytearray(65536)
            ret, err = tapeDev.write(__mfd, bs)
            if ret != 0:
                break
            s = s + 65536
        tapeDev.close(__mfd)

    success_task_extinfo = tapeDev.finish_task(True)

    _fdIndex = 0
    _maxfdIndex = -1
    for _k, _v in success_task_extinfo.items():
        _fdIndex = _v['fdIndex']
        if _fdIndex > _maxfdIndex:
            _maxfdIndex = _fdIndex

    _maxfdIndex = _maxfdIndex + 1
    for _i in range(_maxfdIndex):
        for _k, _v in success_task_extinfo.items():
            _fdIndex = _v['fdIndex']
            if _fdIndex == _i:
                _fileext = _v
                fd = tapeDev.get_read_handle(_fileext)
                ret, bs = tapeDev.read(fd, 9)
                if ret != 0:
                    print("read error")
                else:
                    print("read size:{}", len(bs))

                ret, bs = tapeDev.read(fd, 1111)
                if ret != 0:
                    print("read error")
                else:
                    print("read size:{}", len(bs))

                ret, bs = tapeDev.read(fd, 2222)
                if ret != 0:
                    print("read error")
                else:
                    print("read size:{}", len(bs))

                tapeDev.close(fd)
